package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/open-quantum-safe/liboqs-go/oqs"
	"github.com/gorilla/mux"
)

// Role types
const (
	RoleUser       = "user"
	RoleAdmin      = "admin"
	RoleSuperAdmin = "super_admin"
)

// Certificate params
type CertParams struct {
	CommonName         string
	Organization       string
	OrganizationalUnit string
	Country            string
	ValidFor           time.Duration
	IsCA               bool
	KeyUsage           x509.KeyUsage
	ExtKeyUsage        []x509.ExtKeyUsage
}

// PQCKeyPair holds both classical and PQC keys
type PQCKeyPair struct {
	ClassicalPrivateKey *ecdsa.PrivateKey
	PQPublicKey         []byte
	PQPrivateKey        []byte
	PQPrivateKeyPEM     []byte
	PQAlgorithm         string
}

// Certificate generation request
type CertRequest struct {
	Username     string `json:"username"`
	Organization string `json:"organization"`
	Role         string `json:"role"`
}

// Certificate response
type CertResponse struct {
	ValidFrom  string `json:"validFrom"`
	ValidUntil string `json:"validUntil"`
	Algorithm  string `json:"algorithm"`
}

// File paths
const (
	CertDir = "./certs"
)

func main() {
	// Create certs directory if it doesn't exist
	if err := os.MkdirAll(CertDir, 0755); err != nil {
		log.Fatalf("Failed to create certs directory: %v", err)
	}

	// Create router
	r := mux.NewRouter()
	
	// API routes
	r.HandleFunc("/api/generate-certificate", handleGenerateCertificate).Methods("POST")
	r.HandleFunc("/api/download-certificate/{username}/{role}", handleDownloadCertificate).Methods("GET")
	r.HandleFunc("/api/download-classical-key/{username}/{role}", handleDownloadClassicalKey).Methods("GET")
	r.HandleFunc("/api/download-pq-key/{username}/{role}", handleDownloadPQKey).Methods("GET")
	
	// Serve the frontend
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./static")))
	
	// Start server
	port := "8080"
	fmt.Printf("Server started on http://localhost:%s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}

// Handle certificate generation
// Handle certificate generation
func handleGenerateCertificate(w http.ResponseWriter, r *http.Request) {
	// Parse request
	var req CertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	
	// Validate
	if req.Username == "" || req.Organization == "" {
		http.Error(w, "Username and organization are required", http.StatusBadRequest)
		return
	}
	
	// Check role
	if req.Role != RoleUser && req.Role != RoleAdmin && req.Role != RoleSuperAdmin {
		http.Error(w, "Invalid role", http.StatusBadRequest)
		return
	}
	
	// Generate certificate
	iam := &IAMService{}
	classicalKey, pqKey, certificate, err := iam.CreateUserCertificate(
		req.Username,
		req.Role,
		req.Organization,
	)
	
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to generate certificate: %v", err), http.StatusInternalServerError)
		return
	}
	
	// Save files
	err = SaveCertificateToFiles(req.Username, req.Role, classicalKey, pqKey, certificate)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to save certificate: %v", err), http.StatusInternalServerError)
		return
	}
	
	// Notify the Fabric client that a new certificate is available
	err = NotifyFabricClient(req.Username, req.Role)
	if err != nil {
		log.Printf("Warning: Failed to notify Fabric client: %v", err)
		// Continue processing as this is not critical
	}
	
	// Parse certificate to get dates
	block, _ := pem.Decode(certificate)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse certificate: %v", err), http.StatusInternalServerError)
		return
	}
	
	// Create response
	resp := CertResponse{
		ValidFrom:  cert.NotBefore.Format("2006-01-02"),
		ValidUntil: cert.NotAfter.Format("2006-01-02"),
		Algorithm:  getPQAlgorithmForRole(req.Role),
	}
	
	// Send response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// Handle certificate download
func handleDownloadCertificate(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]
	role := vars["role"]
	
	filepath := filepath.Join(CertDir, fmt.Sprintf("%s_%s_cert.pem", username, role))
	serveFile(w, r, filepath, "application/x-pem-file")
}

// Handle classical key download
func handleDownloadClassicalKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]
	role := vars["role"]
	
	filepath := filepath.Join(CertDir, fmt.Sprintf("%s_%s_classical_private.pem", username, role))
	serveFile(w, r, filepath, "application/x-pem-file")
}

// Handle PQ key download
func handleDownloadPQKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]
	role := vars["role"]
	
	filepath := filepath.Join(CertDir, fmt.Sprintf("%s_%s_pq_private.pem", username, role))
	serveFile(w, r, filepath, "application/x-pem-file")
}

// Helper to serve a file
func serveFile(w http.ResponseWriter, r *http.Request, filepath, contentType string) {
	// Check if file exists
	if _, err := os.Stat(filepath); os.IsNotExist(err) {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	
	// Serve the file
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filepath))
	http.ServeFile(w, r, filepath)
}

// IAM service that uses the certificate generator
type IAMService struct {
	// Add fields as needed for your service
}

// CreateUserCertificate generates a certificate for a user based on their role
func (s *IAMService) CreateUserCertificate(username, role, organization string) ([]byte, []byte, []byte, error) {
	params := CertParams{
		CommonName:         username,
		Organization:       organization,
		OrganizationalUnit: role,
		Country:            "US",
		ValidFor:           365 * 24 * time.Hour, // 1 year
		IsCA:               false,
		KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	return GenerateCertificate(role, params)
}

// Generate a new hybrid certificate based on role
func GenerateCertificate(role string, params CertParams) ([]byte, []byte, []byte, error) {
	var (
		err            error
		certificatePEM []byte
		pqcKeyPair     *PQCKeyPair
	)

	// Generate a hybrid keypair (classical + PQC)
	pqcKeyPair, err = generateHybridKeypair(role)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate keypair: %v", err)
	}

	// Create certificate template
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	notBefore := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         params.CommonName,
			Organization:       []string{params.Organization},
			OrganizationalUnit: []string{params.OrganizationalUnit},
			Country:            []string{params.Country},
		},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(params.ValidFor),
		KeyUsage:              params.KeyUsage,
		ExtKeyUsage:           params.ExtKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  params.IsCA,
		DNSNames:              []string{params.CommonName},
	}

	// Add role and PQC algorithm extensions
	template.ExtraExtensions = []pkix.Extension{
		{
			Id:       []int{1, 3, 6, 1, 4, 1, 44947, 1, 1}, // Custom OID for role
			Critical: false,
			Value:    []byte(role),
		},
		{
			Id:       []int{1, 3, 6, 1, 4, 1, 44947, 1, 2}, // Custom OID for algorithm
			Critical: false,
			Value:    []byte(pqcKeyPair.PQAlgorithm),
		},
		{
			Id:       []int{1, 3, 6, 1, 4, 1, 44947, 1, 3}, // Custom OID for PQC public key
			Critical: false,
			Value:    pqcKeyPair.PQPublicKey,
		},
	}

	// Create a certificate using the classical key for signing
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &pqcKeyPair.ClassicalPrivateKey.PublicKey, pqcKeyPair.ClassicalPrivateKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	// Encode the certificate
	certificatePEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode the classical private key
	keyBytes, err := x509.MarshalECPrivateKey(pqcKeyPair.ClassicalPrivateKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to marshal ECDSA private key: %v", err)
	}
	
	classicalPrivKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})

	return classicalPrivKeyPEM, pqcKeyPair.PQPrivateKeyPEM, certificatePEM, nil
}

// Generate hybrid keypair (classical + PQC)
func generateHybridKeypair(role string) (*PQCKeyPair, error) {
	// Generate classical key (ECDSA)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key: %v", err)
	}

	// Generate PQC key based on role
	var pqPublicKey []byte
	var pqPrivateKey []byte
	var pqPrivateKeyPEM []byte
	var algorithm string

	switch role {
	case RoleUser:
		algorithm = "Kyber512"
		pqPublicKey, pqPrivateKey, err = generateKEMKeypair(algorithm)
	case RoleAdmin:
		algorithm = "Falcon-512"
		pqPublicKey, pqPrivateKey, err = generateSigKeypair(algorithm)
	case RoleSuperAdmin:
		algorithm = "Dilithium2"
		pqPublicKey, pqPrivateKey, err = generateSigKeypair(algorithm)
	default:
		return nil, fmt.Errorf("unsupported role: %s", role)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to generate PQC keypair: %v", err)
	}

	// Create PEM-encoded private key
	pqPrivateKeyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  algorithm + " PRIVATE KEY",
		Bytes: pqPrivateKey,
	})

	return &PQCKeyPair{
		ClassicalPrivateKey: privateKey,
		PQPublicKey:         pqPublicKey,
		PQPrivateKey:        pqPrivateKey,
		PQPrivateKeyPEM:     pqPrivateKeyPEM,
		PQAlgorithm:         algorithm,
	}, nil
}

// Generate KEM keypair (for Kyber)
func generateKEMKeypair(algorithm string) ([]byte, []byte, error) {
	var kem oqs.KeyEncapsulation
	err := kem.Init(algorithm, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("error initializing %s: %v", algorithm, err)
	}
	defer kem.Clean()

	// Generate the keypair - this returns the public key
	publicKey, err := kem.GenerateKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("error generating %s keypair: %v", algorithm, err)
	}

	// Export the secret key
	secretKey := kem.ExportSecretKey()
	if secretKey == nil {
		return nil, nil, fmt.Errorf("error exporting %s secret key", algorithm)
	}

	// Create a structured key format that includes algorithm info
	keyData := struct {
		Algorithm string `json:"algorithm"`
		SecretKey []byte `json:"secretKey"`
	}{
		Algorithm: algorithm,
		SecretKey: secretKey,
	}

	// Serialize the key data
	privateKeyBytes, err := json.Marshal(keyData)
	if err != nil {
		return nil, nil, fmt.Errorf("error serializing %s private key: %v", algorithm, err)
	}

	return publicKey, privateKeyBytes, nil
}

// Generate signature keypair (for Falcon/Dilithium)
func generateSigKeypair(algorithm string) ([]byte, []byte, error) {
	var sig oqs.Signature
	err := sig.Init(algorithm, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("error initializing %s: %v", algorithm, err)
	}
	defer sig.Clean()

	// Generate the keypair - this returns the public key
	publicKey, err := sig.GenerateKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("error generating %s keypair: %v", algorithm, err)
	}

	// Export the secret key
	secretKey := sig.ExportSecretKey()
	if secretKey == nil {
		return nil, nil, fmt.Errorf("error exporting %s secret key", algorithm)
	}

	// Create a structured key format that includes algorithm info
	keyData := struct {
		Algorithm string `json:"algorithm"`
		SecretKey []byte `json:"secretKey"`
	}{
		Algorithm: algorithm,
		SecretKey: secretKey,
	}

	// Serialize the key data
	privateKeyBytes, err := json.Marshal(keyData)
	if err != nil {
		return nil, nil, fmt.Errorf("error serializing %s private key: %v", algorithm, err)
	}

	return publicKey, privateKeyBytes, nil
}

// Save certificate and private keys to files
func SaveCertificateToFiles(username, role string, classicalKeyPEM, pqKeyPEM, certificatePEM []byte) error {
	// Save classical private key
	classicalKeyFile := filepath.Join(CertDir, fmt.Sprintf("%s_%s_classical_private.pem", username, role))
	err := ioutil.WriteFile(classicalKeyFile, classicalKeyPEM, 0600)
	if err != nil {
		return fmt.Errorf("failed to save classical private key: %v", err)
	}

	// Save PQ private key
	pqKeyFile := filepath.Join(CertDir, fmt.Sprintf("%s_%s_pq_private.pem", username, role))
	err = ioutil.WriteFile(pqKeyFile, pqKeyPEM, 0600)
	if err != nil {
		return fmt.Errorf("failed to save PQ private key: %v", err)
	}

	// Save certificate
	certFile := filepath.Join(CertDir, fmt.Sprintf("%s_%s_cert.pem", username, role))
	err = ioutil.WriteFile(certFile, certificatePEM, 0644)
	if err != nil {
		return fmt.Errorf("failed to save certificate: %v", err)
	}

	return nil
}

// Helper function to get algorithm name for a role
func getPQAlgorithmForRole(role string) string {
	switch role {
	case RoleUser:
		return "Kyber512"
	case RoleAdmin:
		return "Falcon-512"
	case RoleSuperAdmin:
		return "Dilithium2"
	default:
		return "Unknown"
	}
}

// NotifyFabricClient sends a notification that a new certificate is available
func NotifyFabricClient(username, role string) error {
	// The Fabric client is monitoring the certs directory, so no direct notification is needed
	// This function could be extended to trigger immediate processing or handle failures
	log.Printf("Certificate for %s with role %s is ready for blockchain storage", username, role)
	return nil
}