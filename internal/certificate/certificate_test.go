package certificate

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/nezhahq/nezha/internal/audit"
	"github.com/nezhahq/nezha/internal/authz"
	"github.com/nezhahq/nezha/internal/platformerr"
	"github.com/nezhahq/nezha/internal/resource"
)

type allowAuthorizer struct {
	denyAction authz.Action
}

func (a allowAuthorizer) Authorize(_ context.Context, req authz.Request) (authz.Decision, error) {
	if req.Action == a.denyAction {
		return authz.Decision{Allowed: false, PolicyVersion: "v1"}, nil
	}
	return authz.Decision{Allowed: true, PolicyVersion: "v1", GrantIDs: []string{"grant-1"}}, nil
}

type recordingAudit struct{ events []audit.Event }

func (r *recordingAudit) Record(_ context.Context, event audit.Event) error {
	r.events = append(r.events, event)
	return nil
}

func makeCertificate(t *testing.T, dnsNames []string) ([]byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	require.NoError(t, err)
	now := time.Now().Add(-time.Minute).Truncate(time.Second)
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		DNSNames:     dnsNames,
		NotBefore:    now,
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, &x509.Certificate{SerialNumber: serial}, &key.PublicKey, key)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func execution() authz.Execution {
	return authz.Execution{Subject: authz.User(7), TriggeredBy: authz.User(7), Entry: authz.Session, OperationID: "op-1"}
}

func TestNormalizeNameAndParsePEM(t *testing.T) {
	got, err := NormalizeName("*.Example.COM")
	require.NoError(t, err)
	require.Equal(t, "*.example.com.", got)
	got, err = NormalizeName("例子.测试")
	require.NoError(t, err)
	require.Equal(t, "xn--fsqu00a.xn--0zwm56d.", got)
	_, err = NormalizeName("foo.*.example.com")
	require.ErrorIs(t, err, ErrInvalidDomain)

	certPEM, keyPEM := makeCertificate(t, []string{"example.com", "www.example.com"})
	parsed, err := ParsePEM(certPEM, keyPEM)
	require.NoError(t, err)
	require.Equal(t, []string{"example.com.", "www.example.com."}, parsed.DNSNames)
	require.NotEmpty(t, parsed.SerialNumber)

	otherCert, _ := makeCertificate(t, []string{"other.example.com"})
	_, err = ParsePEM(certPEM, otherCert)
	require.ErrorIs(t, err, ErrInvalidCertificate)
	_, err = ParsePEM(append(certPEM, certPEM...), keyPEM)
	require.ErrorIs(t, err, ErrInvalidCertificate)
}

func TestServiceHidesPrivateKeyUntilReveal(t *testing.T) {
	certPEM, keyPEM := makeCertificate(t, []string{"example.com"})
	recorder := new(recordingAudit)
	service := NewService(NewMemoryStore(), allowAuthorizer{}, recorder)
	record, err := service.Create(context.Background(), CreateRequest{Execution: execution(), OwnerID: 7, Name: "production", Source: SourceUpload, CertificatePEM: certPEM, PrivateKeyPEM: keyPEM})
	require.NoError(t, err)
	require.Equal(t, resource.Certificate, record.Ref.Kind)

	metadata, err := service.Get(context.Background(), execution(), record.Ref)
	require.NoError(t, err)
	require.NotEmpty(t, metadata.Ref.ID)

	public, err := service.Download(context.Background(), execution(), record.Ref, false)
	require.NoError(t, err)
	require.Equal(t, certPEM, public.Certificate)
	require.Empty(t, public.PrivateKey)

	private, err := service.Download(context.Background(), execution(), record.Ref, true)
	require.NoError(t, err)
	require.Equal(t, keyPEM, private.PrivateKey)
	require.GreaterOrEqual(t, len(recorder.events), 4)
}

func TestServiceRechecksDownloadAuthorization(t *testing.T) {
	certPEM, keyPEM := makeCertificate(t, []string{"example.com"})
	service := NewService(NewMemoryStore(), allowAuthorizer{denyAction: authz.Reveal}, nil)
	record, err := service.Create(context.Background(), CreateRequest{Execution: execution(), OwnerID: 7, Name: "production", Source: SourceUpload, CertificatePEM: certPEM, PrivateKeyPEM: keyPEM})
	require.NoError(t, err)
	_, err = service.Download(context.Background(), execution(), record.Ref, true)
	var publicErr *platformerr.Error
	require.ErrorAs(t, err, &publicErr)
	require.Equal(t, platformerr.Forbidden, publicErr.Code)
}

func TestMemoryStoreRejectsInvalidMetadata(t *testing.T) {
	store := NewMemoryStore()
	err := store.Create(context.Background(), Record{Ref: resource.Ref{Kind: resource.Certificate, ID: "x"}}, []byte("cert"), []byte("key"))
	require.ErrorIs(t, err, ErrInvalidCertificate)
	_, err = store.Get(context.Background(), resource.Ref{Kind: resource.Certificate, ID: "missing"})
	require.ErrorIs(t, err, ErrNotFound)
	require.True(t, errors.Is(err, ErrNotFound))
}
