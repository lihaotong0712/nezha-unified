package controller

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"github.com/gin-gonic/gin"
	"github.com/hashicorp/go-uuid"

	"github.com/nezhahq/nezha/internal/authz"
	"github.com/nezhahq/nezha/internal/certificate"
	"github.com/nezhahq/nezha/internal/platformerr"
	"github.com/nezhahq/nezha/internal/resource"
	"github.com/nezhahq/nezha/model"
)

const certificateUploadLimit = 16 << 20

var certificateServiceState struct {
	sync.RWMutex
	service *certificate.Service
}

// SetCertificateService injects the certificate application service used by
// Dashboard handlers. Runtime wiring owns construction and lifecycle; tests
// can install a memory-backed service without starting the Dashboard process.
func SetCertificateService(service *certificate.Service) {
	certificateServiceState.Lock()
	certificateServiceState.service = service
	certificateServiceState.Unlock()
}

func currentCertificateService() *certificate.Service {
	certificateServiceState.RLock()
	defer certificateServiceState.RUnlock()
	return certificateServiceState.service
}

func certificateExecution(c *gin.Context) (authz.Execution, error) {
	value, ok := c.Get(model.CtxKeyAuthorizedUser)
	user, userOK := value.(*model.User)
	if !ok || !userOK || user == nil || user.ID == 0 {
		return authz.Execution{}, platformerr.New(platformerr.Unauthenticated, "", nil)
	}

	principal := authz.User(user.ID)
	execution := authz.Execution{
		Subject:     principal,
		TriggeredBy: principal,
		Entry:       authz.Session,
		OperationID: certificateOperationID(),
	}
	if token := APITokenFromContext(c); token != nil {
		execution.Entry = authz.PAT
		execution.TokenID = token.ID
	}
	if err := execution.Validate(); err != nil {
		return authz.Execution{}, platformerr.New(platformerr.Unauthenticated, execution.OperationID, err)
	}
	return execution, nil
}

func certificateOperationID() string {
	id, err := uuid.GenerateUUID()
	if err == nil && id != "" {
		return "dashboard-" + id
	}
	// UUID generation failure is extraordinarily unlikely. Keep the operation
	// valid and unique enough for audit correlation without exposing internals.
	return "dashboard-" + strconv.FormatInt(int64(nextCertificateOperation()), 10)
}

var certificateOperationCounter uint64

func nextCertificateOperation() uint64 {
	certificateServiceState.Lock()
	certificateOperationCounter++
	value := certificateOperationCounter
	certificateServiceState.Unlock()
	return value
}

func certificateRef(id string) (resource.Ref, error) {
	ref := resource.Ref{Kind: resource.Certificate, ID: strings.TrimSpace(id)}
	if err := ref.Validate(); err != nil {
		return resource.Ref{}, platformerr.New(platformerr.InvalidArgument, "", err)
	}
	return ref, nil
}

func requireCertificateService(execution authz.Execution) (*certificate.Service, error) {
	service := currentCertificateService()
	if service == nil {
		return nil, platformerr.New(platformerr.Unavailable, execution.OperationID, nil)
	}
	return service, nil
}

func listCertificates(c *gin.Context) ([]certificate.Record, error) {
	execution, err := certificateExecution(c)
	if err != nil {
		return nil, err
	}
	service, err := requireCertificateService(execution)
	if err != nil {
		return nil, err
	}
	return service.List(c.Request.Context(), execution, getUid(c))
}

func getCertificate(c *gin.Context) (certificate.Record, error) {
	execution, err := certificateExecution(c)
	if err != nil {
		return certificate.Record{}, err
	}
	service, err := requireCertificateService(execution)
	if err != nil {
		return certificate.Record{}, err
	}
	ref, err := certificateRef(c.Param("id"))
	if err != nil {
		return certificate.Record{}, withOperation(err, execution.OperationID)
	}
	return service.Get(c.Request.Context(), execution, ref)
}

type certificateCreatePayload struct {
	Name           string `json:"name"`
	Source         string `json:"source"`
	CertificatePEM string `json:"certificate_pem"`
	PrivateKeyPEM  string `json:"private_key_pem"`
}

func createCertificate(c *gin.Context) (certificate.Record, error) {
	execution, err := certificateExecution(c)
	if err != nil {
		return certificate.Record{}, err
	}
	service, err := requireCertificateService(execution)
	if err != nil {
		return certificate.Record{}, err
	}
	payload, err := decodeCertificateCreatePayload(c)
	if err != nil {
		return certificate.Record{}, platformerr.New(platformerr.InvalidArgument, execution.OperationID, err)
	}
	source := certificate.Source(payload.Source)
	if source == "" {
		source = certificate.SourceUpload
	}
	return service.Create(c.Request.Context(), certificate.CreateRequest{
		Execution:      execution,
		OwnerID:        getUid(c),
		Name:           payload.Name,
		Source:         source,
		CertificatePEM: []byte(payload.CertificatePEM),
		PrivateKeyPEM:  []byte(payload.PrivateKeyPEM),
	})
}

func decodeCertificateCreatePayload(c *gin.Context) (certificateCreatePayload, error) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, certificateUploadLimit)
	contentType, _, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
	if err != nil {
		return certificateCreatePayload{}, err
	}
	if strings.EqualFold(contentType, "application/json") {
		var payload certificateCreatePayload
		decoder := json.NewDecoder(c.Request.Body)
		if err := decoder.Decode(&payload); err != nil {
			return certificateCreatePayload{}, err
		}
		if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
			return certificateCreatePayload{}, errors.New("expected one certificate object")
		}
		return payload, nil
	}

	if !strings.EqualFold(contentType, "multipart/form-data") {
		return certificateCreatePayload{}, errors.New("expected JSON or multipart form")
	}
	if err := c.Request.ParseMultipartForm(certificateUploadLimit); err != nil {
		return certificateCreatePayload{}, err
	}
	defer c.Request.MultipartForm.RemoveAll()
	payload := certificateCreatePayload{
		Name:   c.PostForm("name"),
		Source: c.PostForm("source"),
	}
	if payload.Source == "" {
		payload.Source = string(certificate.SourceUpload)
	}
	certificatePEM, err := readCertificateUpload(c, "certificate", "certificate_pem")
	if err != nil {
		return certificateCreatePayload{}, err
	}
	privateKeyPEM, err := readCertificateUpload(c, "private_key", "private_key_pem")
	if err != nil {
		return certificateCreatePayload{}, err
	}
	payload.CertificatePEM = string(certificatePEM)
	payload.PrivateKeyPEM = string(privateKeyPEM)
	return payload, nil
}

func readCertificateUpload(c *gin.Context, fileField, valueField string) ([]byte, error) {
	if file, err := c.FormFile(fileField); err == nil {
		if file.Size > certificateUploadLimit {
			return nil, fmt.Errorf("%s exceeds upload limit", fileField)
		}
		opened, err := file.Open()
		if err != nil {
			return nil, err
		}
		defer opened.Close()
		value, err := io.ReadAll(io.LimitReader(opened, certificateUploadLimit+1))
		if err != nil {
			return nil, err
		}
		if len(value) > certificateUploadLimit {
			return nil, fmt.Errorf("%s exceeds upload limit", fileField)
		}
		return value, nil
	}
	value := c.PostForm(valueField)
	if value == "" {
		// Also accept the short field name as a text part for clients that use
		// multipart fields instead of file parts.
		value = c.PostForm(fileField)
	}
	if len(value) > certificateUploadLimit {
		return nil, fmt.Errorf("%s exceeds upload limit", valueField)
	}
	return []byte(value), nil
}

func downloadCertificate(c *gin.Context) {
	execution, err := certificateExecution(c)
	if err != nil {
		writeCertificateError(c, err)
		return
	}
	service, err := requireCertificateService(execution)
	if err != nil {
		writeCertificateError(c, err)
		return
	}
	ref, err := certificateRef(c.Param("id"))
	if err != nil {
		writeCertificateError(c, withOperation(err, execution.OperationID))
		return
	}
	includePrivate := parseBoolQuery(c, "include_private") || parseBoolQuery(c, "private_key")
	bundle, err := service.Download(c.Request.Context(), execution, ref, includePrivate)
	if err != nil {
		writeCertificateError(c, err)
		return
	}
	payload := append([]byte(nil), bundle.Certificate...)
	if includePrivate && len(bundle.PrivateKey) > 0 {
		if len(payload) > 0 && !bytes.HasSuffix(payload, []byte("\n")) {
			payload = append(payload, '\n')
		}
		payload = append(payload, bundle.PrivateKey...)
	}
	filename := safeCertificateFilename(bundle.Record.Name)
	c.Header("Content-Type", "application/x-pem-file")
	c.Header("Content-Disposition", `attachment; filename="`+filename+`"`)
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Cache-Control", "no-store")
	c.Data(http.StatusOK, "application/x-pem-file", payload)
}

func deleteCertificate(c *gin.Context) (any, error) {
	execution, err := certificateExecution(c)
	if err != nil {
		return nil, err
	}
	service, err := requireCertificateService(execution)
	if err != nil {
		return nil, err
	}
	ref, err := certificateRef(c.Param("id"))
	if err != nil {
		return nil, withOperation(err, execution.OperationID)
	}
	if err := service.Delete(c.Request.Context(), execution, ref); err != nil {
		return nil, err
	}
	return nil, nil
}

func parseBoolQuery(c *gin.Context, key string) bool {
	value := strings.ToLower(strings.TrimSpace(c.Query(key)))
	return value == "1" || value == "true" || value == "yes"
}

func safeCertificateFilename(name string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(name) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("._-", r) {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "certificate.pem"
	}
	return b.String() + ".pem"
}

func writeCertificateError(c *gin.Context, err error) {
	// Dashboard REST endpoints historically return HTTP 200 with a
	// CommonResponse error envelope. Preserve that contract for browser and PAT
	// clients while keeping platform errors' safe messages.
	c.JSON(http.StatusOK, newErrorResponse(err))
}

func withOperation(err error, operationID string) error {
	if platformErr, ok := err.(*platformerr.Error); ok && platformErr.OperationID == operationID {
		return err
	}
	return platformerr.From(err, operationID)
}
