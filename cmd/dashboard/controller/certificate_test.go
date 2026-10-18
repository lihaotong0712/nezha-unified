package controller

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/nezhahq/nezha/internal/audit"
	"github.com/nezhahq/nezha/internal/authz"
	"github.com/nezhahq/nezha/internal/certificate"
	"github.com/nezhahq/nezha/model"
)

type certificateHTTPAllowAuthorizer struct {
	entries    []authz.Execution
	denyAction authz.Action
}

func (a *certificateHTTPAllowAuthorizer) Authorize(_ context.Context, request authz.Request) (authz.Decision, error) {
	a.entries = append(a.entries, request.Execution)
	return authz.Decision{Allowed: request.Action != a.denyAction, PolicyVersion: "test"}, nil
}

type certificateHTTPAudit struct{}

func (certificateHTTPAudit) Record(context.Context, audit.Event) error { return nil }

func certificateHTTPFixture(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	now := time.Now().Add(-time.Minute).Truncate(time.Second)
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(11),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    now,
		NotAfter:     now.Add(time.Hour),
	}, &x509.Certificate{SerialNumber: big.NewInt(11)}, &key.PublicKey, key)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func TestCertificateHTTPHandlersUseTrustedExecutionAndHidePrivateKey(t *testing.T) {
	gin.SetMode(gin.TestMode)
	authorizer := new(certificateHTTPAllowAuthorizer)
	SetCertificateService(certificate.NewService(certificate.NewMemoryStore(), authorizer, certificateHTTPAudit{}))
	t.Cleanup(func() { SetCertificateService(nil) })
	certPEM, keyPEM := certificateHTTPFixture(t)

	r := gin.New()
	r.Use(func(c *gin.Context) {
		// This is the same server-populated identity used by JWT/PAT middleware.
		// The request never supplies a role or owner field.
		c.Set(model.CtxKeyAuthorizedUser, &model.User{Common: model.Common{ID: 7}, Role: model.RoleMember})
		c.Next()
	})
	r.POST("/certificates", commonHandler(createCertificate))
	r.GET("/certificates", commonHandler(listCertificates))
	r.GET("/certificates/:id", commonHandler(getCertificate))
	r.GET("/certificates/:id/download", downloadCertificate)
	r.DELETE("/certificates/:id", commonHandler(deleteCertificate))

	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	require.NoError(t, form.WriteField("name", "production"))
	require.NoError(t, form.WriteField("owner_id", "999"))
	require.NoError(t, form.WriteField("role", "admin"))
	certificatePart, err := form.CreateFormFile("certificate", "certificate.pem")
	require.NoError(t, err)
	_, err = certificatePart.Write(certPEM)
	require.NoError(t, err)
	keyPart, err := form.CreateFormFile("private_key", "key.pem")
	require.NoError(t, err)
	_, err = keyPart.Write(keyPEM)
	require.NoError(t, err)
	require.NoError(t, form.Close())
	createResponse := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/certificates", &body)
	req.Header.Set("Content-Type", form.FormDataContentType())
	r.ServeHTTP(createResponse, req)
	require.Equal(t, http.StatusOK, createResponse.Code)
	var created model.CommonResponse[certificate.Record]
	require.NoError(t, json.Unmarshal(createResponse.Body.Bytes(), &created))
	require.True(t, created.Success)
	require.NotEmpty(t, created.Data.Ref.ID)
	require.Equal(t, uint64(7), created.Data.OwnerID)
	require.NotContains(t, createResponse.Body.String(), "PRIVATE KEY")

	listResponse := httptest.NewRecorder()
	r.ServeHTTP(listResponse, httptest.NewRequest(http.MethodGet, "/certificates", nil))
	var listed model.CommonResponse[[]certificate.Record]
	require.NoError(t, json.Unmarshal(listResponse.Body.Bytes(), &listed))
	require.True(t, listed.Success)
	require.Len(t, listed.Data, 1)
	require.NotContains(t, string(listResponse.Body.Bytes()), string(keyPEM))

	detailResponse := httptest.NewRecorder()
	r.ServeHTTP(detailResponse, httptest.NewRequest(http.MethodGet, "/certificates/"+created.Data.Ref.ID, nil))
	var detail model.CommonResponse[certificate.Record]
	require.NoError(t, json.Unmarshal(detailResponse.Body.Bytes(), &detail))
	require.True(t, detail.Success)
	require.Equal(t, created.Data.Ref, detail.Data.Ref)
	require.NotContains(t, detailResponse.Body.String(), "PRIVATE KEY")

	publicResponse := httptest.NewRecorder()
	r.ServeHTTP(publicResponse, httptest.NewRequest(http.MethodGet, "/certificates/"+created.Data.Ref.ID+"/download", nil))
	require.Equal(t, http.StatusOK, publicResponse.Code)
	require.Equal(t, certPEM, publicResponse.Body.Bytes())
	require.NotContains(t, publicResponse.Body.String(), "PRIVATE KEY")

	authorizer.denyAction = authz.Reveal
	deniedResponse := httptest.NewRecorder()
	r.ServeHTTP(deniedResponse, httptest.NewRequest(http.MethodGet, "/certificates/"+created.Data.Ref.ID+"/download?include_private=true", nil))
	var denied model.CommonResponse[any]
	require.NoError(t, json.Unmarshal(deniedResponse.Body.Bytes(), &denied))
	require.False(t, denied.Success)
	require.Contains(t, denied.Error, "forbidden")
	require.NotContains(t, deniedResponse.Body.String(), "PRIVATE KEY")
	authorizer.denyAction = ""

	privateResponse := httptest.NewRecorder()
	r.ServeHTTP(privateResponse, httptest.NewRequest(http.MethodGet, "/certificates/"+created.Data.Ref.ID+"/download?include_private=true", nil))
	require.Equal(t, http.StatusOK, privateResponse.Code)
	require.Contains(t, privateResponse.Body.String(), "PRIVATE KEY")
	require.Contains(t, privateResponse.Body.String(), "CERTIFICATE")
	require.Equal(t, "no-store", privateResponse.Header().Get("Cache-Control"))

	deleteResponse := httptest.NewRecorder()
	r.ServeHTTP(deleteResponse, httptest.NewRequest(http.MethodDelete, "/certificates/"+created.Data.Ref.ID, nil))
	var deleted model.CommonResponse[any]
	require.NoError(t, json.Unmarshal(deleteResponse.Body.Bytes(), &deleted))
	require.True(t, deleted.Success)

	require.NotEmpty(t, authorizer.entries)
	for _, execution := range authorizer.entries {
		require.Equal(t, authz.User(7), execution.Subject)
		require.Equal(t, authz.Session, execution.Entry)
		require.Equal(t, "7", execution.Subject.ID)
	}
}

func TestCertificateHTTPUnavailableAndUnauthenticated(t *testing.T) {
	SetCertificateService(nil)
	r := gin.New()
	r.GET("/unauthenticated", commonHandler(listCertificates))
	r.GET("/unavailable", func(c *gin.Context) {
		c.Set(model.CtxKeyAuthorizedUser, &model.User{Common: model.Common{ID: 7}})
	}, commonHandler(listCertificates))
	for _, test := range []struct{ path, code string }{
		{"/unauthenticated", "unauthenticated"},
		{"/unavailable", "unavailable"},
	} {
		response := httptest.NewRecorder()
		r.ServeHTTP(response, httptest.NewRequest(http.MethodGet, test.path, nil))
		var result model.CommonResponse[any]
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &result))
		require.False(t, result.Success)
		require.Contains(t, result.Error, test.code)
	}
}

func TestCertificateHTTPHandlersPreservePATExecution(t *testing.T) {
	gin.SetMode(gin.TestMode)
	authorizer := new(certificateHTTPAllowAuthorizer)
	SetCertificateService(certificate.NewService(certificate.NewMemoryStore(), authorizer, nil))
	t.Cleanup(func() { SetCertificateService(nil) })

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(model.CtxKeyAuthorizedUser, &model.User{Common: model.Common{ID: 9}, Role: model.RoleMember})
		c.Set(apiTokenCtxKey, &model.APIToken{ID: 42})
		c.Next()
	})
	r.GET("/certificates", commonHandler(listCertificates))
	response := httptest.NewRecorder()
	r.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/certificates", nil))
	require.Equal(t, http.StatusOK, response.Code)
	require.Len(t, authorizer.entries, 0, "empty list does not invoke resource authorization")

	// A create request exercises the service authorization path and proves the
	// execution carries the trusted PAT ID rather than a browser-supplied role.
	certPEM, keyPEM := certificateHTTPFixture(t)
	r.POST("/certificates", commonHandler(createCertificate))
	body, err := json.Marshal(certificateCreatePayload{Name: "pat", CertificatePEM: string(certPEM), PrivateKeyPEM: string(keyPEM)})
	require.NoError(t, err)
	createResponse := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/certificates", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(createResponse, req)
	require.Equal(t, http.StatusOK, createResponse.Code)
	require.NotEmpty(t, authorizer.entries)
	require.Equal(t, authz.PAT, authorizer.entries[0].Entry)
	require.Equal(t, uint64(42), authorizer.entries[0].TokenID)
}
