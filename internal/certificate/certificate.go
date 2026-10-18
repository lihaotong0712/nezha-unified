// Package certificate contains the certificate asset boundary used by the
// unified platform. It owns validation and safe metadata, while authorization
// and secret storage remain injected dependencies.
package certificate

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/net/idna"

	"github.com/nezhahq/nezha/internal/resource"
)

type Source string

const (
	SourceRequest Source = "request"
	SourceUpload  Source = "upload"
)

type Status string

const (
	StatusActive  Status = "active"
	StatusExpired Status = "expired"
	StatusRevoked Status = "revoked"
)

var (
	ErrInvalidCertificate = errors.New("invalid certificate")
	ErrPrivateKeyMismatch = errors.New("certificate and private key do not match")
	ErrPrivateKeyRequired = errors.New("private key is required")
	ErrInvalidDomain      = errors.New("invalid certificate name")
)

// Parsed is the validated, safe projection of a PEM certificate. PrivateKey
// contains a copy only for the caller that is importing the asset; it is never
// included in Record or JSON metadata.
type Parsed struct {
	CertificatePEM []byte
	PrivateKeyPEM  []byte
	SerialNumber   string
	Subject        string
	Issuer         string
	DNSNames       []string
	IPAddresses    []string
	NotBefore      time.Time
	NotAfter       time.Time
	PublicKeyAlgo  x509.PublicKeyAlgorithm
}

// Record is the non-secret certificate metadata kept by the certificate store.
// PEM material is intentionally absent. Private keys must be stored through a
// protected secret service and are only available during an explicit import or
// download operation.
type Record struct {
	Ref          resource.Ref `json:"ref"`
	OwnerID      uint64       `json:"owner_id,string"`
	Name         string       `json:"name"`
	Source       Source       `json:"source"`
	Status       Status       `json:"status"`
	SerialNumber string       `json:"serial_number"`
	Subject      string       `json:"subject"`
	Issuer       string       `json:"issuer"`
	DNSNames     []string     `json:"dns_names"`
	IPAddresses  []string     `json:"ip_addresses,omitempty"`
	NotBefore    time.Time    `json:"not_before"`
	NotAfter     time.Time    `json:"not_after"`
	Revision     uint64       `json:"revision"`
	CreatedAt    time.Time    `json:"created_at"`
	UpdatedAt    time.Time    `json:"updated_at"`
}

func (r Record) Validate() error {
	if r.Ref.Kind != resource.Certificate || r.Ref.Validate() != nil || r.OwnerID == 0 || strings.TrimSpace(r.Name) == "" || r.Revision == 0 {
		return ErrInvalidCertificate
	}
	if r.Source != SourceRequest && r.Source != SourceUpload {
		return ErrInvalidCertificate
	}
	if r.Status != StatusActive && r.Status != StatusExpired && r.Status != StatusRevoked {
		return ErrInvalidCertificate
	}
	if len(r.DNSNames) == 0 && len(r.IPAddresses) == 0 || r.NotAfter.Before(r.NotBefore) {
		return ErrInvalidCertificate
	}
	return nil
}

// NormalizeName converts a user or certificate name to the stable ASCII form
// used for scope checks. A trailing dot is preserved; wildcard is allowed only
// as the complete left-most label.
func NormalizeName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || strings.ContainsAny(name, "\r\n\t ") {
		return "", ErrInvalidDomain
	}
	wildcard := strings.HasPrefix(name, "*.")
	if strings.Contains(name, "*") && !wildcard {
		return "", ErrInvalidDomain
	}
	bare := strings.TrimSuffix(name, ".")
	if bare == "" {
		return "", ErrInvalidDomain
	}
	labels := strings.Split(bare, ".")
	if wildcard {
		if len(labels) < 2 || labels[0] != "*" {
			return "", ErrInvalidDomain
		}
		labels = labels[1:]
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return "", ErrInvalidDomain
		}
	}
	ascii, err := idna.Lookup.ToASCII(strings.Join(labels, "."))
	if err != nil || ascii == "" || len(ascii) > 253 {
		return "", ErrInvalidDomain
	}
	ascii = strings.ToLower(ascii)
	if wildcard {
		ascii = "*." + ascii
	}
	return ascii + ".", nil
}

func normalizeNames(names []string) ([]string, error) {
	if len(names) == 0 {
		return nil, ErrInvalidDomain
	}
	out := make([]string, 0, len(names))
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		normalized, err := NormalizeName(name)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	if len(out) == 0 {
		return nil, ErrInvalidDomain
	}
	return out, nil
}

func parsePrivateKey(block *pem.Block) (crypto.PrivateKey, error) {
	if block == nil {
		return nil, ErrPrivateKeyRequired
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, ErrInvalidCertificate
}

func publicKeyEqual(cert *x509.Certificate, key crypto.PrivateKey) bool {
	var public crypto.PublicKey
	switch k := key.(type) {
	case *rsa.PrivateKey:
		public = &k.PublicKey
	case *ecdsa.PrivateKey:
		public = &k.PublicKey
	case ed25519.PrivateKey:
		public = k.Public()
	default:
		return false
	}
	left, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return false
	}
	right, err := x509.MarshalPKIXPublicKey(public)
	return err == nil && string(left) == string(right)
}

// ParsePEM validates one leaf certificate and its matching private key. It
// rejects extra certificate blocks and malformed name entries so imported data
// cannot later bypass certificate and resource authorization.
func ParsePEM(certificatePEM, privateKeyPEM []byte) (Parsed, error) {
	certBlock, rest := pem.Decode(certificatePEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return Parsed{}, ErrInvalidCertificate
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return Parsed{}, fmt.Errorf("%w: parse certificate", ErrInvalidCertificate)
	}
	keyBlock, keyRest := pem.Decode(privateKeyPEM)
	if keyBlock == nil || len(strings.TrimSpace(string(keyRest))) != 0 {
		return Parsed{}, ErrPrivateKeyRequired
	}
	key, err := parsePrivateKey(keyBlock)
	if err != nil {
		return Parsed{}, err
	}
	if !publicKeyEqual(cert, key) {
		return Parsed{}, ErrPrivateKeyMismatch
	}
	var names []string
	if len(cert.DNSNames) > 0 {
		names, err = normalizeNames(cert.DNSNames)
		if err != nil {
			return Parsed{}, err
		}
	}
	if len(names) == 0 && len(cert.IPAddresses) == 0 {
		return Parsed{}, ErrInvalidDomain
	}
	ips := make([]string, 0, len(cert.IPAddresses))
	for _, ip := range cert.IPAddresses {
		ips = append(ips, ip.String())
	}
	return Parsed{
		CertificatePEM: append([]byte(nil), certificatePEM...),
		PrivateKeyPEM:  append([]byte(nil), privateKeyPEM...),
		SerialNumber:   cert.SerialNumber.String(),
		Subject:        cert.Subject.String(),
		Issuer:         cert.Issuer.String(),
		DNSNames:       names,
		IPAddresses:    ips,
		NotBefore:      cert.NotBefore,
		NotAfter:       cert.NotAfter,
		PublicKeyAlgo:  cert.PublicKeyAlgorithm,
	}, nil
}

func statusAt(now, notAfter time.Time) Status {
	if !now.Before(notAfter) {
		return StatusExpired
	}
	return StatusActive
}
