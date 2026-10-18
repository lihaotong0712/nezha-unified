package certificate

import (
	"context"
	"errors"
	"sort"
	"sync"

	"github.com/nezhahq/nezha/internal/resource"
)

var (
	ErrNotFound = errors.New("certificate not found")
	ErrConflict = errors.New("certificate conflict")
)

// Bundle is returned only by an explicitly authorized download. The private
// key is omitted unless the caller also has the reveal permission.
type Bundle struct {
	Record      Record `json:"record"`
	Certificate []byte `json:"certificate_pem"`
	PrivateKey  []byte `json:"private_key_pem,omitempty"`
}

type Store interface {
	Create(context.Context, Record, []byte, []byte) error
	Get(context.Context, resource.Ref) (Record, error)
	List(context.Context, uint64) ([]Record, error)
	Delete(context.Context, resource.Ref) error
	Bundle(context.Context, resource.Ref, bool) (Bundle, error)
}

// CertificateMaterialReader is an optional narrow read path for public-only
// downloads. Implementations should avoid loading the private key at all when
// the caller has not been granted reveal permission.
type CertificateMaterialReader interface {
	GetCertificate(context.Context, resource.Ref) ([]byte, error)
}

type storedCertificate struct {
	record      Record
	certificate []byte
	privateKey  []byte
}

// MemoryStore is a deterministic store for tests and small installations. A
// production adapter can implement Store with GORM and an injected protected
// secret service without changing certificate validation or authorization.
type MemoryStore struct {
	mu      sync.RWMutex
	records map[string]storedCertificate
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{records: make(map[string]storedCertificate)} }

func (s *MemoryStore) Create(_ context.Context, record Record, certificate, privateKey []byte) error {
	if err := record.Validate(); err != nil || len(certificate) == 0 || len(privateKey) == 0 {
		return ErrInvalidCertificate
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := string(record.Ref.Kind) + ":" + record.Ref.ID
	if _, ok := s.records[key]; ok {
		return ErrConflict
	}
	s.records[key] = storedCertificate{record: cloneRecord(record), certificate: append([]byte(nil), certificate...), privateKey: append([]byte(nil), privateKey...)}
	return nil
}

func (s *MemoryStore) Get(_ context.Context, ref resource.Ref) (Record, error) {
	if ref.Validate() != nil || ref.Kind != resource.Certificate {
		return Record{}, ErrNotFound
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, ok := s.records[string(ref.Kind)+":"+ref.ID]
	if !ok {
		return Record{}, ErrNotFound
	}
	return cloneRecord(item.record), nil
}

func (s *MemoryStore) List(_ context.Context, ownerID uint64) ([]Record, error) {
	if ownerID == 0 {
		return nil, ErrInvalidCertificate
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Record, 0)
	for _, item := range s.records {
		if item.record.OwnerID == ownerID {
			out = append(out, cloneRecord(item.record))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.Before(out[j].UpdatedAt) })
	return out, nil
}

func (s *MemoryStore) Delete(_ context.Context, ref resource.Ref) error {
	if ref.Validate() != nil || ref.Kind != resource.Certificate {
		return ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := string(ref.Kind) + ":" + ref.ID
	if _, ok := s.records[key]; !ok {
		return ErrNotFound
	}
	delete(s.records, key)
	return nil
}

func (s *MemoryStore) Bundle(_ context.Context, ref resource.Ref, includePrivate bool) (Bundle, error) {
	if ref.Validate() != nil || ref.Kind != resource.Certificate {
		return Bundle{}, ErrNotFound
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, ok := s.records[string(ref.Kind)+":"+ref.ID]
	if !ok {
		return Bundle{}, ErrNotFound
	}
	out := Bundle{Record: cloneRecord(item.record), Certificate: append([]byte(nil), item.certificate...)}
	if includePrivate {
		out.PrivateKey = append([]byte(nil), item.privateKey...)
	}
	return out, nil
}

func cloneRecord(in Record) Record {
	in.DNSNames = append([]string(nil), in.DNSNames...)
	in.IPAddresses = append([]string(nil), in.IPAddresses...)
	return in
}
