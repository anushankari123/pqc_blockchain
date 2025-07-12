package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/gateway"
)

type CertificateData struct {
	CertificatePEM string `json:"certificatePEM"`
	Username       string `json:"username"`
	Role           string `json:"role"`
	Organization   string `json:"organization"`
	Algorithm      string `json:"algorithm"`
	ValidFrom      string `json:"validFrom"`
	ValidUntil     string `json:"validUntil"`
}

func main() {
	// Load the Fabric connection profile
	configPath := os.Getenv("FABRIC_CONFIG_PATH")
	if configPath == "" {
		configPath = "../test-network/organizations/peerOrganizations/org1.example.com/connection-org1.yaml"
	}

	// Create a new Gateway connection
	wallet, err := gateway.NewFileSystemWallet("wallet")
	if err != nil {
		log.Fatalf("Failed to create wallet: %v", err)
	}

	// Check if identity exists in wallet
	if !wallet.Exists("appUser") {
		err = populateWallet(wallet)
		if err != nil {
			log.Fatalf("Failed to populate wallet: %v", err)
		}
	}

	gw, err := gateway.Connect(
		gateway.WithConfig(config.FromFile(filepath.Clean(configPath))),
		gateway.WithIdentity(wallet, "appUser"),
	)
	if err != nil {
		log.Fatalf("Failed to connect to gateway: %v", err)
	}
	defer gw.Close()

	// Get the network and contract
	network, err := gw.GetNetwork("quantum-cert-channel")
	if err != nil {
		log.Fatalf("Failed to get network: %v", err)
	}

	contract := network.GetContract("cert-storage")

	// Listen for certificate files in the certs directory
	go monitorCertificates(contract)

	// Keep the application running
	fmt.Println("Fabric client is running. Press Ctrl+C to exit.")
	select {}
}

// Populate the wallet with identities needed
func populateWallet(wallet *gateway.Wallet) error {
    // Use absolute path to avoid path resolution issues
    credPath := filepath.Join(
        os.Getenv("HOME"),
        "go/src/github.com/anushankari123/fabric-samples/test-network",
        "organizations",
        "peerOrganizations",
        "org1.example.com",
        "users",
        "User1@org1.example.com",
        "msp",
    )

    // For signcerts, check the actual filename - it might not be cert.pem
    certDir := filepath.Join(credPath, "signcerts")
    files, err := ioutil.ReadDir(certDir)
    if err != nil {
        return fmt.Errorf("failed to read signcerts directory: %w", err)
    }
    if len(files) == 0 {
        return fmt.Errorf("no certificate found in signcerts directory")
    }
    certPath := filepath.Join(certDir, files[0].Name())
    cert, err := ioutil.ReadFile(filepath.Clean(certPath))
    if err != nil {
        return fmt.Errorf("failed to read certificate file: %w", err)
    }

    // Same for keystore
    keyDir := filepath.Join(credPath, "keystore")
    files, err = ioutil.ReadDir(keyDir)
    if err != nil {
        return fmt.Errorf("failed to read keystore directory: %w", err)
    }
    if len(files) == 0 {
        return fmt.Errorf("no private key found in keystore directory")
    }
    keyPath := filepath.Join(keyDir, files[0].Name())
    key, err := ioutil.ReadFile(filepath.Clean(keyPath))
    if err != nil {
        return fmt.Errorf("failed to read private key file: %w", err)
    }

    identity := gateway.NewX509Identity("Org1MSP", string(cert), string(key))
    return wallet.Put("appUser", identity)
}

// Monitor the certs directory for new certificates
func monitorCertificates(contract *gateway.Contract) {
	certDir := "../certs"
	processedCerts := make(map[string]bool)

	// Create directory if it doesn't exist
	if _, err := os.Stat(certDir); os.IsNotExist(err) {
		os.MkdirAll(certDir, 0755)
	}

	for {
		files, err := ioutil.ReadDir(certDir)
		if err != nil {
			log.Printf("Error reading cert directory: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		for _, file := range files {
			if !file.IsDir() && filepath.Ext(file.Name()) == ".pem" && !processedCerts[file.Name()] {
				if filepath.Base(file.Name())[len(filepath.Base(file.Name()))-9:] == "_cert.pem" {
					processedCerts[file.Name()] = true
					
					// Extract username and role from filename
					// Expected format: username_role_cert.pem
					filename := filepath.Base(file.Name())
					// Remove the _cert.pem suffix
					nameRole := filename[:len(filename)-9]
					
					// Find the position of the last underscore
					lastUnderscore := -1
					for i := len(nameRole) - 1; i >= 0; i-- {
						if nameRole[i] == '_' {
							lastUnderscore = i
							break
						}
					}
					
					if lastUnderscore == -1 {
						log.Printf("Invalid certificate filename format: %s", filename)
						continue
					}
					
					username := nameRole[:lastUnderscore]
					role := nameRole[lastUnderscore+1:]
					
					log.Printf("Processing certificate for: %s with role: %s", username, role)
					
					// Read and process the certificate
					certPath := filepath.Join(certDir, file.Name())
					storeCertificate(contract, certPath, username, role)
				}
			}
		}
		
		time.Sleep(5 * time.Second)
	}
}

// Read certificate and store it in the blockchain
func storeCertificate(contract *gateway.Contract, certPath, username, role string) {
	// Read the certificate file
	certPEM, err := ioutil.ReadFile(certPath)
	if err != nil {
		log.Printf("Error reading certificate file: %v", err)
		return
	}
	
	// Parse the certificate
	block, _ := pem.Decode(certPEM)
	if block == nil {
		log.Printf("Failed to parse certificate PEM for %s", certPath)
		return
	}
	
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Printf("Failed to parse certificate: %v", err)
		return
	}
	
	// Extract organization from the certificate
	var organization string
	if len(cert.Subject.Organization) > 0 {
		organization = cert.Subject.Organization[0]
	} else {
		organization = "Unknown"
	}
	
	// Extract algorithm from extensions (we added it as a custom extension)
	algorithm := "Unknown"
	for _, ext := range cert.Extensions {
		// Check if this is our algorithm OID (1.3.6.1.4.1.44947.1.2)
		if ext.Id.Equal([]int{1, 3, 6, 1, 4, 1, 44947, 1, 2}) {
			algorithm = string(ext.Value)
			break
		}
	}
	
	// Create certificate ID from username, role and timestamp
	certID := fmt.Sprintf("%s_%s_%d", username, role, time.Now().Unix())
	
	// Convert the PEM to base64 string
	certificatePEMBase64 := base64.StdEncoding.EncodeToString(certPEM)
	
	// Store the certificate in blockchain
	log.Printf("Storing certificate with ID: %s", certID)

// Submit the transaction
result, err := contract.SubmitTransaction(
    "StoreCertificate",
    certID,
    username,
    role,
    organization,
    algorithm,
    cert.NotBefore.Format("2006-01-02"),
    cert.NotAfter.Format("2006-01-02"),
    certificatePEMBase64,
    "none",  // classicalPrivateKey (default value instead of empty string)
    "none",  // pqPrivateKey (default value instead of empty string)
)

if err != nil {
    log.Printf("Failed to submit transaction: %v", err)
    return
}

log.Printf("Transaction submitted successfully: %s", string(result))
}