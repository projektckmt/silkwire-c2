package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// CAManager handles certificate authority operations similar to Sliver
type CAManager struct {
	caPath     string
	caCert     *x509.Certificate
	caKey      *ecdsa.PrivateKey
	certPool   *x509.CertPool
	serverAddr string
}

// NewCAManager creates a new CA manager instance
func NewCAManager(caPath, serverAddr string) (*CAManager, error) {
	cm := &CAManager{
		caPath:     caPath,
		serverAddr: serverAddr,
		certPool:   x509.NewCertPool(),
	}

	// Ensure CA directory exists
	if err := os.MkdirAll(caPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create CA directory: %v", err)
	}

	// Load or generate CA
	if err := cm.loadOrGenerateCA(); err != nil {
		return nil, fmt.Errorf("failed to initialize CA: %v", err)
	}

	return cm, nil
}

// loadOrGenerateCA loads existing CA or generates a new one (Sliver-style)
func (cm *CAManager) loadOrGenerateCA() error {
	caCertPath := filepath.Join(cm.caPath, "ca.crt")
	caKeyPath := filepath.Join(cm.caPath, "ca.key")

	// Check if CA files exist
	if _, err := os.Stat(caCertPath); os.IsNotExist(err) {
		return cm.generateCA()
	}

	// Load existing CA certificate
	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %v", err)
	}

	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil {
		return fmt.Errorf("failed to decode CA certificate PEM")
	}

	cm.caCert, err = x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %v", err)
	}

	// Load existing CA private key
	caKeyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read CA private key: %v", err)
	}

	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		return fmt.Errorf("failed to decode CA private key PEM")
	}

	cm.caKey, err = x509.ParseECPrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA private key: %v", err)
	}

	// Add CA cert to cert pool
	cm.certPool.AddCert(cm.caCert)

	return nil
}

// generateCA creates a new ECDSA certificate authority (Sliver-style)
func (cm *CAManager) generateCA() error {
	// Generate ECDSA private key for CA (like Sliver)
	caKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate CA private key: %v", err)
	}

	// Create CA certificate template
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("Silkwire CA %s", cm.serverAddr),
			Organization: []string{"Silkwire C2"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour * 10), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	// Create CA certificate
	caCertDER, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %v", err)
	}

	// Parse the certificate
	cm.caCert, err = x509.ParseCertificate(caCertDER)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %v", err)
	}

	cm.caKey = caKey

	// Save CA certificate
	caCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertDER,
	})
	caCertPath := filepath.Join(cm.caPath, "ca.crt")
	if err := os.WriteFile(caCertPath, caCertPEM, 0644); err != nil {
		return fmt.Errorf("failed to save CA certificate: %v", err)
	}

	// Save CA private key
	caKeyBytes, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		return fmt.Errorf("failed to marshal CA private key: %v", err)
	}

	caKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: caKeyBytes,
	})
	caKeyPath := filepath.Join(cm.caPath, "ca.key")
	if err := os.WriteFile(caKeyPath, caKeyPEM, 0600); err != nil {
		return fmt.Errorf("failed to save CA private key: %v", err)
	}

	// Add CA cert to cert pool
	cm.certPool.AddCert(cm.caCert)

	return nil
}

// GenerateClientCertificate creates a CA-signed client certificate for an implant
func (cm *CAManager) GenerateClientCertificate(implantID string) ([]byte, []byte, error) {
	// Generate ECDSA private key for client (like Sliver)
	clientKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate client private key: %v", err)
	}

	// Create client certificate template
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   implantID,
			Organization: []string{"Silkwire Implant"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Create client certificate signed by CA
	clientCertDER, err := x509.CreateCertificate(rand.Reader, template, cm.caCert, &clientKey.PublicKey, cm.caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create client certificate: %v", err)
	}

	// Encode certificate to PEM
	clientCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: clientCertDER,
	})

	// Encode private key to PEM
	clientKeyBytes, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal client private key: %v", err)
	}

	clientKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: clientKeyBytes,
	})

	return clientCertPEM, clientKeyPEM, nil
}

// GenerateClientTLSCertificate creates a tls.Certificate for an implant
func (cm *CAManager) GenerateClientTLSCertificate(implantID string) (tls.Certificate, error) {
	certPEM, keyPEM, err := cm.GenerateClientCertificate(implantID)
	if err != nil {
		return tls.Certificate{}, err
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load client certificate: %v", err)
	}

	// Parse certificate for metadata
	cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])

	return cert, nil
}

// GetCACertificate returns the CA certificate in PEM format
func (cm *CAManager) GetCACertificate() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cm.caCert.Raw,
	})
}

// GetClientCAs returns the cert pool for validating client certificates
func (cm *CAManager) GetClientCAs() *x509.CertPool {
	return cm.certPool
}

// GetTLSConfig returns a TLS config for mTLS with Sliver-like settings
func (cm *CAManager) GetTLSConfig(serverCert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    cm.certPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		// Use Sliver-like TLS settings
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.CurveP384,
		},
	}
}

// GenerateServerCertificate creates a CA-signed server certificate for a listener
func (cm *CAManager) GenerateServerCertificate(address string) (tls.Certificate, error) {
	// Generate ECDSA private key for server
	serverKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate server private key: %v", err)
	}

	// Parse address to get host
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		// If address doesn't have port, use it as host
		host = address
	}
	if host == "" {
		host = "localhost"
	}

	// Create server certificate template
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate serial number: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   host,
			Organization: []string{"Silkwire C2 Server"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Add IP and DNS SANs
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	// Always add localhost variants
	template.DNSNames = append(template.DNSNames, "localhost")
	template.IPAddresses = append(template.IPAddresses, net.IPv4(127, 0, 0, 1), net.IPv6loopback)

	// Create server certificate signed by CA
	serverCertDER, err := x509.CreateCertificate(rand.Reader, template, cm.caCert, &serverKey.PublicKey, cm.caKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create server certificate: %v", err)
	}

	// Encode certificate to PEM
	serverCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: serverCertDER,
	})

	// Encode private key to PEM
	serverKeyBytes, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to marshal server private key: %v", err)
	}

	serverKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: serverKeyBytes,
	})

	// Create TLS certificate
	cert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load server certificate: %v", err)
	}

	// Parse certificate for metadata
	cert.Leaf, _ = x509.ParseCertificate(serverCertDER)

	return cert, nil
}

// VerifyClientCertificate verifies a client certificate against the CA
func (cm *CAManager) VerifyClientCertificate(certDER []byte) error {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %v", err)
	}

	opts := x509.VerifyOptions{
		Roots: cm.certPool,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
	}

	_, err = cert.Verify(opts)
	return err
}
