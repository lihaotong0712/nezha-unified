// Package platform wires the persistent unified-module services together.
//
// The package owns construction and additive migrations only. HTTP handlers
// receive the resulting narrow services through explicit injection, so a
// handler cannot silently create a second database, key, or policy boundary.
package platform

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/nezhahq/nezha/internal/audit"
	"github.com/nezhahq/nezha/internal/authz"
	"github.com/nezhahq/nezha/internal/certificate"
	"github.com/nezhahq/nezha/internal/credential"
	"github.com/nezhahq/nezha/internal/resource"
	"github.com/nezhahq/nezha/model"
	"gorm.io/gorm"
)

// Services is the application-owned set of persistent unified-module
// services. The key material is kept in a dedicated file and is never written
// to SQLite. It is independent from the dashboard JWT secret, which may be
// rotated without making existing materials unreadable.
type Services struct {
	Resources       *resource.GORMStore
	Authorizer      *DashboardAuthorizer
	Audit           *audit.GORMRecorder
	Credentials     *credential.Store
	Certificates    *certificate.Service
	CertificateData *certificate.GORMStore
}

// DashboardAuthorizer adds the trusted browser-session policy that the
// dashboard needs to operate its own resources. PAT and background executions
// always go through the persistent grant authorizer, so a user role can never
// widen a token's scopes or a delegated job's permissions.
//
// The embedded policy store is intentional: callers that manage grants can use
// the same Services.Authorizer while application services only depend on the
// authz.Authorizer interface.
type DashboardAuthorizer struct {
	*authz.GORMAuthorizer
	db *gorm.DB
}

func newDashboardAuthorizer(db *gorm.DB, policies *authz.GORMAuthorizer) *DashboardAuthorizer {
	return &DashboardAuthorizer{GORMAuthorizer: policies, db: db}
}

func (a *DashboardAuthorizer) Authorize(ctx context.Context, req authz.Request) (authz.Decision, error) {
	if a == nil || a.GORMAuthorizer == nil || a.db == nil {
		return authz.Decision{}, errors.New("platform: authorization service is unavailable")
	}
	if err := req.Validate(); err != nil {
		return authz.Decision{}, err
	}
	// PAT and non-interactive executions must retain the grant/PAT intersection.
	if req.Execution.Entry != authz.Session || req.Execution.TokenID != 0 {
		return a.GORMAuthorizer.Authorize(ctx, req)
	}
	uid, err := strconv.ParseUint(req.Execution.Subject.ID, 10, 64)
	if err != nil || uid == 0 || req.Execution.Subject != authz.User(uid) {
		return authz.Decision{Allowed: false}, nil
	}
	var user struct {
		ID   uint64
		Role model.Role
	}
	if err := a.db.WithContext(ctx).Table("users").Select("id", "role").Where("id = ?", uid).First(&user).Error; err != nil {
		return authz.Decision{}, err
	}
	if user.Role.IsAdmin() {
		return authz.Decision{Allowed: true, PolicyVersion: "dashboard-admin-v1", GrantIDs: []string{"dashboard-admin"}}, nil
	}

	// A member may use a persisted grant for delegated access. If no grant
	// matches, the owner fallback below keeps the first-party certificate page
	// usable without requiring administrators to seed a grant for every upload.
	decision, err := a.GORMAuthorizer.Authorize(ctx, req)
	if err != nil {
		return authz.Decision{}, err
	}
	if decision.Allowed {
		return decision, nil
	}
	if req.Resource.Kind != resource.Certificate || !certificateOwnerAction(req.Action) {
		return decision, nil
	}
	var row struct{ OwnerID uint64 }
	query := a.db.WithContext(ctx).Table("platform_certificates").Select("owner_id").Where("ref_id = ?", req.Resource.ID).Limit(1)
	if err := query.Scan(&row).Error; err != nil {
		return authz.Decision{}, err
	}
	if row.OwnerID == 0 {
		// Create generates the resource ID before authorization and the service
		// binds interactive callers to OwnerID, so an absent row is a safe
		// owner-scoped creation boundary.
		if req.Action == authz.Edit {
			return authz.Decision{Allowed: true, PolicyVersion: "dashboard-owner-v1", GrantIDs: []string{"dashboard-owner-create"}}, nil
		}
		return decision, nil
	}
	if row.OwnerID != uid {
		return decision, nil
	}
	return authz.Decision{Allowed: true, PolicyVersion: "dashboard-owner-v1", GrantIDs: []string{"dashboard-owner"}}, nil
}

func certificateOwnerAction(action authz.Action) bool {
	switch action {
	case authz.View, authz.Edit, authz.Download, authz.Reveal, authz.Delete:
		return true
	default:
		return false
	}
}

// NewServices performs all additive migrations and returns services that
// share one database, authorizer, recorder, and application encryption key.
// keyPath must point to a file outside SQLite.
func NewServices(db *gorm.DB, keyPath string) (*Services, error) {
	if db == nil {
		return nil, errors.New("platform: database is required")
	}
	if keyPath == "" {
		return nil, errors.New("platform: stable key file path is required")
	}
	key, err := loadOrCreateKey(db, keyPath)
	if err != nil {
		return nil, err
	}
	defer clearBytes(key)
	resources, err := resource.NewGORMStore(db)
	if err != nil {
		return nil, err
	}
	policyAuthorizer, err := authz.NewGORMAuthorizer(db)
	if err != nil {
		return nil, err
	}
	authorizer := newDashboardAuthorizer(db, policyAuthorizer)
	recorder, err := audit.NewGORMRecorder(db)
	if err != nil {
		return nil, err
	}
	protector, err := credential.NewAESGCMProtector("dashboard-v1", key)
	if err != nil {
		return nil, fmt.Errorf("platform credential protector: %w", err)
	}
	credentials := credential.NewStore(db, protector, authorizer)
	if err := credentials.Migrate(context.Background()); err != nil {
		return nil, err
	}
	credentials.SetRecorder(recorder)

	materials, err := certificate.NewAESGCMMaterialStore(db, "dashboard-v1", key)
	if err != nil {
		return nil, err
	}
	certificateData, err := certificate.NewGORMStore(db, materials)
	if err != nil {
		return nil, err
	}
	certificates := certificate.NewService(certificateData, authorizer, recorder)

	return &Services{
		Resources: resources, Authorizer: authorizer, Audit: recorder,
		Credentials: credentials, Certificates: certificates,
		CertificateData: certificateData,
	}, nil
}

func loadOrCreateKey(db *gorm.DB, path string) ([]byte, error) {
	path = filepath.Clean(path)
	if path == "." || path == string(filepath.Separator) {
		return nil, errors.New("platform: invalid stable key file path")
	}
	if data, err := os.ReadFile(path); err == nil {
		if len(data) != 32 {
			return nil, errors.New("platform: stable key file has invalid length")
		}
		if info, statErr := os.Stat(path); statErr == nil && info.Mode().Perm()&0077 != 0 {
			return nil, errors.New("platform: stable key file permissions are too broad")
		}
		return data, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("platform: read stable key file: %w", err)
	} else {
		encrypted, probeErr := hasEncryptedPlatformData(db)
		if probeErr != nil {
			// A failed probe is an unavailable identity/key state. Creating a
			// replacement key in that situation could strand existing ciphertext
			// while making startup appear successful.
			return nil, fmt.Errorf("platform: inspect encrypted data: %w", probeErr)
		}
		if encrypted {
			return nil, errors.New("platform: encrypted data exists but stable key file is missing")
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("platform: create stable key directory: %w", err)
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("platform: generate stable key: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return loadOrCreateKey(db, path)
		}
		return nil, fmt.Errorf("platform: create stable key file: %w", err)
	}
	_, writeErr := file.Write(key)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(path)
		return nil, fmt.Errorf("platform: write stable key file: %w", errors.Join(writeErr, closeErr))
	}
	return key, nil
}

func hasEncryptedPlatformData(db *gorm.DB) (bool, error) {
	if db == nil {
		return false, errors.New("platform: database is required")
	}
	tables, err := db.Migrator().GetTables()
	if err != nil {
		return false, err
	}
	existing := make(map[string]bool, len(tables))
	for _, table := range tables {
		existing[table] = true
	}
	for _, table := range []string{"platform_credential_versions", "platform_certificate_materials"} {
		if !existing[table] {
			continue
		}
		var count int64
		if err := db.Table(table).Count(&count).Error; err != nil {
			return false, err
		}
		if count > 0 {
			return true, nil
		}
	}
	return false, nil
}

func clearBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
