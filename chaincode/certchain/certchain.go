package main

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// CertificateContract defines the smart contract for certificate management
type CertificateContract struct {
	contractapi.Contract
}

// Certificate structure stored on the blockchain
type Certificate struct {
	Username     string `json:"username"`
	Organization string `json:"organization"`
	Role         string `json:"role"`
	Algorithm    string `json:"algorithm"`
	ValidFrom    string `json:"validFrom"`
	ValidUntil   string `json:"validUntil"`
	CertHash     string `json:"certHash"`
}

// VerificationResult structure for certificate verification
type VerificationResult struct {
	Verified bool   `json:"verified"`
	Message  string `json:"message"`
}

// InitLedger initializes the ledger with sample data
func (cc *CertificateContract) InitLedger(ctx contractapi.TransactionContextInterface) error {
	// No initial data needed
	return nil
}

// StoreCertificate stores a certificate on the blockchain
func (cc *CertificateContract) StoreCertificate(ctx contractapi.TransactionContextInterface, certID string, certJSON string) error {
	// Check if certificate already exists
	exists, err := cc.CertificateExists(ctx, certID)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("certificate with ID %s already exists", certID)
	}

	// Store the certificate
	return ctx.GetStub().PutState(certID, []byte(certJSON))
}

// VerifyCertificate verifies a certificate against the blockchain
func (cc *CertificateContract) VerifyCertificate(ctx contractapi.TransactionContextInterface, certID string, certHash string) ([]byte, error) {
	// Get the certificate from the ledger
	certJSON, err := ctx.GetStub().GetState(certID)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate: %v", err)
	}
	if certJSON == nil {
		result := VerificationResult{
			Verified: false,
			Message:  fmt.Sprintf("Certificate with ID %s does not exist", certID),
		}
		return json.Marshal(result)
	}

	// Parse the certificate
	var cert Certificate
	err = json.Unmarshal(certJSON, &cert)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	// Verify the certificate hash
	if cert.CertHash == certHash {
		result := VerificationResult{
			Verified: true,
			Message:  "Certificate is valid",
		}
		return json.Marshal(result)
	}

	result := VerificationResult{
		Verified: false,
		Message:  "Certificate hash does not match",
	}
	return json.Marshal(result)
}

// CertificateExists checks if a certificate exists
func (cc *CertificateContract) CertificateExists(ctx contractapi.TransactionContextInterface, certID string) (bool, error) {
	certJSON, err := ctx.GetStub().GetState(certID)
	if err != nil {
		return false, fmt.Errorf("failed to read certificate: %v", err)
	}
	return certJSON != nil, nil
}

// GetCertificate retrieves a certificate by ID
func (cc *CertificateContract) GetCertificate(ctx contractapi.TransactionContextInterface, certID string) ([]byte, error) {
	certJSON, err := ctx.GetStub().GetState(certID)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate: %v", err)
	}
	if certJSON == nil {
		return nil, fmt.Errorf("certificate with ID %s does not exist", certID)
	}
	return certJSON, nil
}

func main() {
	chaincode, err := contractapi.NewChaincode(&CertificateContract{})
	if err != nil {
		fmt.Printf("Error creating certificate chaincode: %v", err)
		return
	}

	if err := chaincode.Start(); err != nil {
		fmt.Printf("Error starting certificate chaincode: %v", err)
	}
}
