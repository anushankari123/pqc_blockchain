#!/bin/bash

# Exit on first error
set -e

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "Error: Go is not installed"
    exit 1
fi

# Check if Fabric samples are installed
FABRIC_SAMPLES_DIR="$HOME/go/src/github.com/anushankari123/fabric-samples"
if [ ! -d "$FABRIC_SAMPLES_DIR" ]; then
    echo "Error: Fabric samples not found at $FABRIC_SAMPLES_DIR"
    exit 1
fi

# Create chaincode directory
CHAINCODE_DIR="$PWD/chaincode"
mkdir -p $CHAINCODE_DIR/certchain

# Copy chaincode to directory
echo "Creating chaincode..."
cat > $CHAINCODE_DIR/certchain/certchain.go << 'EOF'
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
EOF

# Create go.mod file for chaincode
cd $CHAINCODE_DIR/certchain
go mod init github.com/anushankari123/certchain
go get github.com/hyperledger/fabric-contract-api-go/contractapi
cd -

# Create connection profile
echo "Creating connection profile..."
cat > connection-profile.yaml << 'EOF'
---
name: test-network-org1
version: 1.0.0
client:
  organization: Org1
  connection:
    timeout:
      peer:
        endorser: '300'
organizations:
  Org1:
    mspid: Org1MSP
    peers:
    - peer0.org1.example.com
    certificateAuthorities:
    - ca.org1.example.com
peers:
  peer0.org1.example.com:
    url: grpcs://localhost:7051
    tlsCACerts:
      path: ${FABRIC_SAMPLES_DIR}/test-network/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
    grpcOptions:
      ssl-target-name-override: peer0.org1.example.com
      hostnameOverride: peer0.org1.example.com
certificateAuthorities:
  ca.org1.example.com:
    url: https://localhost:7054
    caName: ca-org1
    tlsCACerts:
      path: ${FABRIC_SAMPLES_DIR}/test-network/organizations/peerOrganizations/org1.example.com/ca/ca.org1.example.com-cert.pem
    httpOptions:
      verify: false
EOF

# Start the Fabric network
echo "Starting Fabric network..."
cd "$FABRIC_SAMPLES_DIR/test-network"
./network.sh down
./network.sh up createChannel -c mychannel
./network.sh deployCC -c mychannel -ccn certchain -ccp $CHAINCODE_DIR/certchain -ccl go
cd -

echo "Network started and chaincode deployed!"

# Install Go dependencies for the application
echo "Installing Go dependencies..."
go get github.com/hyperledger/fabric-sdk-go
go get github.com/gorilla/mux

echo "Integration complete! You can now run your application."