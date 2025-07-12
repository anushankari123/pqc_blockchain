package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"path/filepath"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	mspID        = "Org1MSP"
	cryptoPath   = "../../../fabric-samples/test-network/organizations/peerOrganizations/org1.example.com"
	certPath     = cryptoPath + "/users/User1@org1.example.com/msp/signcerts/cert.pem"
	keyPath      = cryptoPath + "/users/User1@org1.example.com/msp/keystore/"
	tlsCertPath  = cryptoPath + "/peers/peer0.org1.example.com/tls/ca.crt"
	peerEndpoint = "localhost:7051"
	gatewayPeer  = "peer0.org1.example.com"
)

// Store certificate in Hyperledger Fabric
func StoreCertificateInFabric(username, role, organization string, certPEM, classicalKeyPEM, pqKeyPEM []byte) error {
	// Create a gRPC connection to the gateway peer
	connection, err := createConnection()
	if err != nil {
		return fmt.Errorf("failed to create connection: %w", err)
	}
	defer connection.Close()

	// Create identity from the certificate and private key
	id, err := createIdentity()
	if err != nil {
		return fmt.Errorf("failed to create identity: %w", err)
	}

	// Create sign function using the private key
	sign, err := createSign()
	if err != nil {
		return fmt.Errorf("failed to create sign: %w", err)
	}

	// Create a gateway connection
	gateway, err := client.Connect(
		id,
		client.WithSign(sign),
		client.WithClientConnection(connection),
		client.WithEvaluateTimeout(5),
		client.WithEndorseTimeout(15),
		client.WithSubmitTimeout(5),
		client.WithCommitStatusTimeout(1),
	)
	if err != nil {
		return fmt.Errorf("failed to connect to gateway: %w", err)
	}
	defer gateway.Close()

	// Get the network and contract
	network := gateway.GetNetwork("mychannel")
	contract := network.GetContract("certificate-store")
	
	// Convert byte arrays to base64 strings for storage
	certB64 := base64.StdEncoding.EncodeToString(certPEM)
	classicalKeyB64 := base64.StdEncoding.EncodeToString(classicalKeyPEM)
	pqKeyB64 := base64.StdEncoding.EncodeToString(pqKeyPEM)
	algorithm := getPQAlgorithmForRole(role)
	
	// Submit the transaction
	_, err = contract.SubmitTransaction("CreateCertificate", username, role, organization, certB64, classicalKeyB64, pqKeyB64, algorithm)
	if err != nil {
		return fmt.Errorf("failed to submit transaction: %w", err)
	}
	
	fmt.Printf("Certificate for %s with role %s stored in blockchain\n", username, role)
	return nil
}

// Authenticate a user by checking if their certificate exists
func AuthenticateUserInFabric(username, role string) (bool, error) {
	// Create a gRPC connection to the gateway peer
	connection, err := createConnection()
	if err != nil {
		return false, fmt.Errorf("failed to create connection: %w", err)
	}
	defer connection.Close()

	// Create identity from the certificate and private key
	id, err := createIdentity()
	if err != nil {
		return false, fmt.Errorf("failed to create identity: %w", err)
	}

	// Create sign function using the private key
	sign, err := createSign()
	if err != nil {
		return false, fmt.Errorf("failed to create sign: %w", err)
	}

	// Create a gateway connection
	gateway, err := client.Connect(
		id,
		client.WithSign(sign),
		client.WithClientConnection(connection),
		client.WithEvaluateTimeout(5),
		client.WithEndorseTimeout(15),
		client.WithSubmitTimeout(5),
		client.WithCommitStatusTimeout(1),
	)
	if err != nil {
		return false, fmt.Errorf("failed to connect to gateway: %w", err)
	}
	defer gateway.Close()

	// Get the network and contract
	network := gateway.GetNetwork("mychannel")
	contract := network.GetContract("certificate-store")
	
	// Call the AuthenticateUser function
	result, err := contract.EvaluateTransaction("AuthenticateUser", username, role)
	if err != nil {
		return false, fmt.Errorf("failed to evaluate transaction: %w", err)
	}
	
	// Parse the result
	authenticated := string(result) == "true"
	return authenticated, nil
}

// Create client connection to Fabric network
func createConnection() (*grpc.ClientConn, error) {
	// Read TLS certificate
	certificate, err := loadCertificate(tlsCertPath)
	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(certificate) {
		return nil, fmt.Errorf("failed to add certificate to credentials")
	}

	// Create credentials for connection
	transportCredentials := credentials.NewClientTLSFromCert(certPool, gatewayPeer)

	// Create connection
	connection, err := grpc.Dial(peerEndpoint, grpc.WithTransportCredentials(transportCredentials))
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC connection: %w", err)
	}

	return connection, nil
}

// Get identity for signing transactions
func createIdentity() (*identity.X509Identity, error) {
	certificatePEM, err := loadCertificate(certPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(certificatePEM)
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}

	// Fix: Properly create X509Identity with string certificate
	id, err := identity.NewX509Identity(mspID, string(certificatePEM))
	if err != nil {
		return nil, err
	}

	return id, nil
}

// Create a signing function
func createSign() (identity.Sign, error) {
	privateKeyPEM, err := loadPrivateKey()
	if err != nil {
		return nil, err
	}

	sign, err := identity.NewPrivateKeySign(privateKeyPEM)
	if err != nil {
		return nil, err
	}

	return sign, nil
}

// Load certificate from file
func loadCertificate(filename string) ([]byte, error) {
	certificatePEM, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}
	return certificatePEM, nil
}

// Load private key from file
func loadPrivateKey() ([]byte, error) {
	// Find the private key file in the keystore directory
	files, err := ioutil.ReadDir(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key directory: %w", err)
	}
	
	// We need to find the first file in the directory
	if len(files) == 0 {
		return nil, fmt.Errorf("no private key found in directory")
	}
	
	// Read the private key file
	privateKeyPEM, err := ioutil.ReadFile(filepath.Join(keyPath, files[0].Name()))
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	return privateKeyPEM, nil
}

// Helper function to get PQ algorithm based on role
func getPQAlgorithmForRole(role string) string {
	// Implement your logic here to determine the algorithm based on role
	return "DILITHIUM3" // Default algorithm
}