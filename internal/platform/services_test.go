package platform

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
	"os"
	"testing"
	"time"

	"github.com/nezhahq/nezha/internal/authz"
	"github.com/nezhahq/nezha/internal/certificate"
	"github.com/nezhahq/nezha/internal/platformerr"
	"github.com/nezhahq/nezha/internal/resource"
	"github.com/nezhahq/nezha/model"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newPlatformTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name())), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.APIToken{}); err != nil {
		t.Fatal(err)
	}
	return db
}

func platformTestCertificate(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com", "www.example.com"},
		NotBefore:    now,
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, &x509.Certificate{SerialNumber: serial}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return certificatePEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func platformSession(id uint64, operation string) authz.Execution {
	return authz.Execution{Subject: authz.User(id), TriggeredBy: authz.User(id), Entry: authz.Session, OperationID: operation}
}

func platformPAT(id, tokenID uint64, operation string) authz.Execution {
	return authz.Execution{Subject: authz.User(id), TriggeredBy: authz.User(id), Entry: authz.PAT, TokenID: tokenID, OperationID: operation}
}

func putCertificateGrant(t *testing.T, services *Services, userID uint64, grantID string, actions ...authz.Action) {
	t.Helper()
	if err := services.Authorizer.GORMAuthorizer.PutGrant(context.Background(), authz.PolicyGrant{
		ID:            grantID,
		Principal:     authz.User(userID),
		Resource:      resource.Ref{Kind: resource.Certificate, ID: "*"},
		Actions:       actions,
		PolicyVersion: "platform-test-v1",
		Enabled:       true,
	}); err != nil {
		t.Fatal(err)
	}
}

func putCertificatePAT(t *testing.T, db *gorm.DB, id, userID uint64, scopes string) {
	t.Helper()
	if err := db.Create(&model.APIToken{ID: id, UserID: userID, Name: "platform-test", TokenHash: fmt.Sprintf("platform-test-%d", id), ScopesCSV: scopes}).Error; err != nil {
		t.Fatal(err)
	}
}

func TestNewServicesRequiresDatabaseAndStableSecret(t *testing.T) {
	if _, err := NewServices(nil, "key"); err == nil {
		t.Fatal("nil database should fail")
	}
	db := newPlatformTestDB(t)
	if _, err := NewServices(db, ""); err == nil {
		t.Fatal("empty secret should fail")
	}
}

func TestNewServicesMigrationsAreRepeatableAndAdminSessionIsTrusted(t *testing.T) {
	db := newPlatformTestDB(t)
	keyPath := t.TempDir() + "/platform.key"
	if err := db.Create(&model.User{Common: model.Common{ID: 7}, Username: "admin", Role: model.RoleAdmin}).Error; err != nil {
		t.Fatal(err)
	}
	first, err := NewServices(db, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewServices(db, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if first.Authorizer == nil || second.Certificates == nil || second.Credentials == nil {
		t.Fatal("expected all platform services")
	}
	execution := authz.Execution{Subject: authz.User(7), TriggeredBy: authz.User(7), Entry: authz.Session, OperationID: "platform-admin"}
	decision, err := first.Authorizer.Authorize(context.Background(), authz.Request{
		Execution: execution,
		Action:    authz.Delete,
		Resource:  resource.Ref{Kind: resource.Certificate, ID: "cert-test"},
	})
	if err != nil || !decision.Allowed || decision.PolicyVersion == "" {
		t.Fatalf("admin decision = %+v, %v", decision, err)
	}
}

func TestCertificateSQLiteLifecyclePersistsEncryptedMaterialAcrossRestart(t *testing.T) {
	db := newPlatformTestDB(t)
	keyPath := t.TempDir() + "/platform.key"
	if err := db.Create(&model.User{Common: model.Common{ID: 7}, Username: "admin", Role: model.RoleAdmin}).Error; err != nil {
		t.Fatal(err)
	}
	services, err := NewServices(db, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM, privateKeyPEM := platformTestCertificate(t)
	execution := platformSession(7, "certificate-lifecycle-create")
	record, err := services.Certificates.Create(context.Background(), certificate.CreateRequest{
		Execution: execution, OwnerID: 7, Name: "production", Source: certificate.SourceUpload,
		CertificatePEM: certificatePEM, PrivateKeyPEM: privateKeyPEM,
	})
	if err != nil {
		t.Fatal(err)
	}

	listed, err := services.Certificates.List(context.Background(), execution, 7)
	if err != nil || len(listed) != 1 || listed[0].Ref != record.Ref {
		t.Fatalf("certificate list = %+v, %v", listed, err)
	}
	metadata, err := services.Certificates.Get(context.Background(), execution, record.Ref)
	if err != nil || metadata.Ref != record.Ref || metadata.Name != "production" {
		t.Fatalf("certificate detail = %+v, %v", metadata, err)
	}
	public, err := services.Certificates.Download(context.Background(), platformSession(7, "certificate-lifecycle-public"), record.Ref, false)
	if err != nil {
		t.Fatal(err)
	}
	if string(public.Certificate) != string(certificatePEM) || len(public.PrivateKey) != 0 {
		t.Fatalf("public download exposed unexpected material: certificate=%d private=%d", len(public.Certificate), len(public.PrivateKey))
	}
	private, err := services.Certificates.Download(context.Background(), platformSession(7, "certificate-lifecycle-private"), record.Ref, true)
	if err != nil {
		t.Fatal(err)
	}
	if string(private.Certificate) != string(certificatePEM) || string(private.PrivateKey) != string(privateKeyPEM) {
		t.Fatal("private download did not recover the original encrypted material")
	}

	restarted, err := NewServices(db, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := restarted.Certificates.Download(context.Background(), platformSession(7, "certificate-lifecycle-restart"), record.Ref, true)
	if err != nil {
		t.Fatal(err)
	}
	if string(recovered.Certificate) != string(certificatePEM) || string(recovered.PrivateKey) != string(privateKeyPEM) {
		t.Fatal("restart did not recover encrypted certificate material")
	}
	if err := restarted.Certificates.Delete(context.Background(), platformSession(7, "certificate-lifecycle-delete"), record.Ref); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Certificates.Get(context.Background(), execution, record.Ref); err == nil {
		t.Fatal("deleted certificate should not be readable")
	}
}

func TestCertificateOwnerSessionRejectsOtherMember(t *testing.T) {
	db := newPlatformTestDB(t)
	keyPath := t.TempDir() + "/platform.key"
	for _, user := range []*model.User{
		{Common: model.Common{ID: 8}, Username: "owner", Role: model.RoleMember},
		{Common: model.Common{ID: 9}, Username: "other", Role: model.RoleMember},
	} {
		if err := db.Create(user).Error; err != nil {
			t.Fatal(err)
		}
	}
	services, err := NewServices(db, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM, privateKeyPEM := platformTestCertificate(t)
	ownerExecution := platformSession(8, "member-owner")
	record, err := services.Certificates.Create(context.Background(), certificate.CreateRequest{
		Execution: ownerExecution, OwnerID: 8, Name: "member-cert", Source: certificate.SourceUpload,
		CertificatePEM: certificatePEM, PrivateKeyPEM: privateKeyPEM,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := services.Certificates.Get(context.Background(), ownerExecution, record.Ref); err != nil {
		t.Fatalf("owner session should read its own certificate: %v", err)
	}
	_, err = services.Certificates.Get(context.Background(), platformSession(9, "member-other"), record.Ref)
	var forbidden *platformerr.Error
	if !errorAs(err, &forbidden) || forbidden.Code != platformerr.Forbidden {
		t.Fatalf("other member access = %v, want forbidden", err)
	}
}

func TestCertificatePATDoesNotInheritAdminRole(t *testing.T) {
	db := newPlatformTestDB(t)
	keyPath := t.TempDir() + "/platform.key"
	if err := db.Create(&model.User{Common: model.Common{ID: 7}, Username: "admin", Role: model.RoleAdmin}).Error; err != nil {
		t.Fatal(err)
	}
	services, err := NewServices(db, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	putCertificateGrant(t, services, 7, "admin-pat-read", authz.Edit)
	putCertificatePAT(t, db, 101, 7, model.ScopeCertificateRead)
	certificatePEM, privateKeyPEM := platformTestCertificate(t)
	_, err = services.Certificates.Create(context.Background(), certificate.CreateRequest{
		Execution: platformPAT(7, 101, "admin-pat-create"), OwnerID: 7, Name: "pat-cert", Source: certificate.SourceUpload,
		CertificatePEM: certificatePEM, PrivateKeyPEM: privateKeyPEM,
	})
	var forbidden *platformerr.Error
	if !errorAs(err, &forbidden) || forbidden.Code != platformerr.Forbidden {
		t.Fatalf("admin PAT with read-only scope create = %v, want forbidden", err)
	}
}

func TestCertificatePATDownloadAndRevealScopes(t *testing.T) {
	db := newPlatformTestDB(t)
	keyPath := t.TempDir() + "/platform.key"
	if err := db.Create(&model.User{Common: model.Common{ID: 7}, Username: "certificate-pat", Role: model.RoleMember}).Error; err != nil {
		t.Fatal(err)
	}
	services, err := NewServices(db, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	putCertificateGrant(t, services, 7, "certificate-pat-download-reveal", authz.Download, authz.Reveal)
	certificatePEM, privateKeyPEM := platformTestCertificate(t)
	record, err := services.Certificates.Create(context.Background(), certificate.CreateRequest{
		Execution: platformSession(7, "certificate-pat-scopes-create"), OwnerID: 7, Name: "pat-scopes", Source: certificate.SourceUpload,
		CertificatePEM: certificatePEM, PrivateKeyPEM: privateKeyPEM,
	})
	if err != nil {
		t.Fatal(err)
	}

	putCertificatePAT(t, db, 103, 7, model.ScopeCertificateRead)
	if _, err := services.Certificates.Download(context.Background(), platformPAT(7, 103, "certificate-pat-read-only"), record.Ref, false); !certificateErrorIsForbidden(err) {
		t.Fatalf("read-only PAT download = %v, want forbidden", err)
	}

	putCertificatePAT(t, db, 104, 7, model.ScopeCertificateDownload)
	public, err := services.Certificates.Download(context.Background(), platformPAT(7, 104, "certificate-pat-download"), record.Ref, false)
	if err != nil {
		t.Fatalf("download PAT public material = %v", err)
	}
	if string(public.Certificate) != string(certificatePEM) || len(public.PrivateKey) != 0 {
		t.Fatalf("download PAT public bundle = certificate %d bytes, private %d bytes", len(public.Certificate), len(public.PrivateKey))
	}
	if _, err := services.Certificates.Download(context.Background(), platformPAT(7, 104, "certificate-pat-download-without-reveal"), record.Ref, true); !certificateErrorIsForbidden(err) {
		t.Fatalf("download-only PAT private material = %v, want forbidden", err)
	}

	putCertificatePAT(t, db, 105, 7, model.ScopeCertificateDownload+","+model.ScopeCertificateReveal)
	private, err := services.Certificates.Download(context.Background(), platformPAT(7, 105, "certificate-pat-download-reveal"), record.Ref, true)
	if err != nil {
		t.Fatalf("download+reveal PAT private material = %v", err)
	}
	if string(private.Certificate) != string(certificatePEM) || string(private.PrivateKey) != string(privateKeyPEM) {
		t.Fatal("download+reveal PAT did not recover the complete certificate bundle")
	}

	putCertificatePAT(t, db, 106, 7, model.ScopeCertificateReveal)
	if _, err := services.Certificates.Download(context.Background(), platformPAT(7, 106, "certificate-pat-reveal-only"), record.Ref, false); !certificateErrorIsForbidden(err) {
		t.Fatalf("reveal-only PAT public material = %v, want forbidden", err)
	}
}

func certificateErrorIsForbidden(err error) bool {
	var forbidden *platformerr.Error
	return errorAs(err, &forbidden) && forbidden.Code == platformerr.Forbidden
}

func TestDeletedUserSessionAndPATAreRejected(t *testing.T) {
	db := newPlatformTestDB(t)
	keyPath := t.TempDir() + "/platform.key"
	if err := db.Create(&model.User{Common: model.Common{ID: 8}, Username: "deleted-member", Role: model.RoleMember}).Error; err != nil {
		t.Fatal(err)
	}
	services, err := NewServices(db, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	putCertificateGrant(t, services, 8, "deleted-user-pat", authz.View)
	putCertificatePAT(t, db, 102, 8, model.ScopeCertificateRead)
	certificatePEM, privateKeyPEM := platformTestCertificate(t)
	record, err := services.Certificates.Create(context.Background(), certificate.CreateRequest{
		Execution: platformSession(8, "deleted-create"), OwnerID: 8, Name: "deleted-cert", Source: certificate.SourceUpload,
		CertificatePEM: certificatePEM, PrivateKeyPEM: privateKeyPEM,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Delete(&model.User{}, 8).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := services.Certificates.Get(context.Background(), platformSession(8, "deleted-session"), record.Ref); err == nil {
		t.Fatal("deleted user's session should be rejected")
	}
	if _, err := services.Certificates.Get(context.Background(), platformPAT(8, 102, "deleted-pat"), record.Ref); err == nil {
		t.Fatal("deleted user's PAT should be rejected")
	}
}

func TestNewServicesFailsWhenStableKeyMissingAfterEncryptedDataExists(t *testing.T) {
	db := newPlatformTestDB(t)
	keyPath := t.TempDir() + "/platform.key"
	if err := db.Create(&model.User{Common: model.Common{ID: 7}, Username: "admin", Role: model.RoleAdmin}).Error; err != nil {
		t.Fatal(err)
	}
	services, err := NewServices(db, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM, privateKeyPEM := platformTestCertificate(t)
	if _, err := services.Certificates.Create(context.Background(), certificate.CreateRequest{
		Execution: platformSession(7, "stable-key-material"), OwnerID: 7, Name: "encrypted", Source: certificate.SourceUpload,
		CertificatePEM: certificatePEM, PrivateKeyPEM: privateKeyPEM,
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := NewServices(db, keyPath); err == nil {
		t.Fatal("missing stable key must fail when encrypted platform data exists")
	}
}

func TestNewServicesRejectsBroadStableKeyPermissions(t *testing.T) {
	db := newPlatformTestDB(t)
	keyPath := t.TempDir() + "/platform.key"
	if err := db.Create(&model.User{Common: model.Common{ID: 7}, Username: "key-permission", Role: model.RoleAdmin}).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := NewServices(db, keyPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewServices(db, keyPath); err == nil {
		t.Fatal("stable key with broad permissions must fail closed")
	}
}

func errorAs(err error, target any) bool {
	if err == nil {
		return false
	}
	return errors.As(err, target)
}
