package certificate

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

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

func TestServiceListAllowsDelegatedOwnerThroughAuthorizer(t *testing.T) {
	certPEM, keyPEM := makeCertificate(t, []string{"example.com"})
	service := NewService(NewMemoryStore(), allowAuthorizer{}, nil)
	if _, err := service.Create(context.Background(), CreateRequest{Execution: execution(), OwnerID: 8, Name: "delegated", Source: SourceUpload, CertificatePEM: certPEM, PrivateKeyPEM: keyPEM}); err != nil {
		t.Fatal(err)
	}
	got, err := service.List(context.Background(), execution(), 8)
	if err != nil || len(got) != 1 {
		t.Fatalf("delegated list = %+v, %v", got, err)
	}
}

func TestServiceAuditsRevealAndDeleteOutcomes(t *testing.T) {
	certPEM, keyPEM := makeCertificate(t, []string{"example.com"})
	recorder := new(recordingAudit)
	service := NewService(NewMemoryStore(), allowAuthorizer{}, recorder)
	record, err := service.Create(context.Background(), CreateRequest{Execution: execution(), OwnerID: 7, Name: "audit", Source: SourceUpload, CertificatePEM: certPEM, PrivateKeyPEM: keyPEM})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Download(context.Background(), execution(), record.Ref, true); err != nil {
		t.Fatal(err)
	}
	if err := service.Delete(context.Background(), execution(), record.Ref); err != nil {
		t.Fatal(err)
	}
	var revealSucceeded, deleteSucceeded bool
	for _, event := range recorder.events {
		if event.Action == authz.Reveal && event.Outcome == audit.Succeeded {
			revealSucceeded = true
		}
		if event.Action == authz.Delete && event.Outcome == audit.Succeeded {
			deleteSucceeded = true
		}
	}
	if !revealSucceeded || !deleteSucceeded {
		t.Fatalf("missing success audit events: %+v", recorder.events)
	}
}

func TestMemoryStoreRejectsInvalidMetadata(t *testing.T) {
	store := NewMemoryStore()
	err := store.Create(context.Background(), Record{Ref: resource.Ref{Kind: resource.Certificate, ID: "x"}}, []byte("cert"), []byte("key"))
	require.ErrorIs(t, err, ErrInvalidCertificate)
	_, err = store.Get(context.Background(), resource.Ref{Kind: resource.Certificate, ID: "missing"})
	require.ErrorIs(t, err, ErrNotFound)
	require.True(t, errors.Is(err, ErrNotFound))
}

func TestAESGCMMaterialStoreSplitEnvelopeAndNarrowRead(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name())), &gorm.Config{})
	require.NoError(t, err)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	materials, err := NewAESGCMMaterialStore(db, "key-1", key)
	require.NoError(t, err)
	store, err := NewGORMStore(db, materials)
	require.NoError(t, err)

	certificatePEM, privateKeyPEM := makeCertificate(t, []string{"example.com"})
	parsed, err := ParsePEM(certificatePEM, privateKeyPEM)
	require.NoError(t, err)
	now := time.Now().UTC()
	ref := resource.Ref{Kind: resource.Certificate, ID: "cert-gorm"}
	record := Record{
		Ref: ref, OwnerID: 7, Name: "gorm", Source: SourceUpload, Status: StatusActive,
		SerialNumber: parsed.SerialNumber, Subject: parsed.Subject, Issuer: parsed.Issuer,
		DNSNames: parsed.DNSNames, IPAddresses: parsed.IPAddresses, NotBefore: parsed.NotBefore,
		NotAfter: parsed.NotAfter, Revision: 1, CreatedAt: now, UpdatedAt: now,
	}
	require.NoError(t, store.Create(context.Background(), record, certificatePEM, privateKeyPEM))

	gotCertificate, gotPrivateKey, err := materials.Get(context.Background(), ref)
	require.NoError(t, err)
	require.Equal(t, certificatePEM, gotCertificate)
	require.Equal(t, privateKeyPEM, gotPrivateKey)

	public, err := store.Bundle(context.Background(), ref, false)
	require.NoError(t, err)
	require.Equal(t, certificatePEM, public.Certificate)
	require.Empty(t, public.PrivateKey)

	var row materialRow
	require.NoError(t, db.First(&row, "ref_id = ?", ref.ID).Error)
	require.NotEmpty(t, row.PrivateKeyCiphertext)
	corruptPrivate := append([]byte(nil), row.PrivateKeyCiphertext...)
	corruptPrivate[0] ^= 0xff
	require.NoError(t, db.Model(&materialRow{}).Where("ref_id = ?", ref.ID).Update("private_key_ciphertext", corruptPrivate).Error)

	// The narrow read path still succeeds because it does not select or decrypt
	// the private-key envelope. A reveal download must fail closed instead.
	public, err = store.Bundle(context.Background(), ref, false)
	require.NoError(t, err)
	require.Equal(t, certificatePEM, public.Certificate)
	_, err = store.Bundle(context.Background(), ref, true)
	require.Error(t, err)

	corruptCertificate := append([]byte(nil), row.CertificateCiphertext...)
	corruptCertificate[0] ^= 0xff
	require.NoError(t, db.Model(&materialRow{}).Where("ref_id = ?", ref.ID).Update("certificate_ciphertext", corruptCertificate).Error)
	_, err = materials.GetCertificate(context.Background(), ref)
	require.Error(t, err)
}

func TestAESGCMMaterialStoreReadsLegacyCombinedEnvelope(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name())), &gorm.Config{})
	require.NoError(t, err)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(0xa0 + i)
	}
	materials, err := NewAESGCMMaterialStore(db, "legacy-key", key)
	require.NoError(t, err)
	ref := resource.Ref{Kind: resource.Certificate, ID: "cert-legacy"}
	certificatePEM := []byte("legacy certificate")
	privateKeyPEM := []byte("legacy private key")
	nonce := make([]byte, materials.aead.NonceSize())
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	ciphertext := materials.aead.Seal(nil, nonce, encodeMaterial(certificatePEM, privateKeyPEM), materialAAD(ref, materials.keyID))
	now := time.Now().UTC()
	require.NoError(t, db.Create(&materialRow{RefID: ref.ID, KeyID: materials.keyID, Nonce: nonce, Ciphertext: ciphertext, CreatedAt: now, UpdatedAt: now}).Error)

	gotCertificate, gotPrivateKey, err := materials.Get(context.Background(), ref)
	require.NoError(t, err)
	require.Equal(t, certificatePEM, gotCertificate)
	require.Equal(t, privateKeyPEM, gotPrivateKey)
	gotCertificate, err = materials.GetCertificate(context.Background(), ref)
	require.NoError(t, err)
	require.Equal(t, certificatePEM, gotCertificate)
}
