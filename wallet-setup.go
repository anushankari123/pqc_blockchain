package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"github.com/hyperledger/fabric-sdk-go/pkg/gateway"
)

// SetupWallet sets up the wallet with the necessary identities
func SetupWallet() error {
	// Define path to Fabric samples
	fabricSamplesDir := os.Getenv("FABRIC_SAMPLES_DIR")
	if fabricSamplesDir == "" {
		fabricSamplesDir = os.Getenv("HOME") + "/go/src/github.com/anushankari123/fabric-samples"
	}

	// Path to crypto materials
	cryptoPath := path.Join(fabricSamplesDir, "test-network", "organizations", "peerOrganizations", "org1.example.com")
	certPath := path.Join(cryptoPath, "users", "Admin@org1.example.com", "msp", "signcerts", "Admin@org1.example.com-cert.pem")
	keyPath := path.Join(cryptoPath, "users", "Admin@org1.example.com", "msp", "keystore")

	// Read the certificate file
	cert, err := ioutil.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to read cert file: %v", err)
	}

	// Read the key file - need to find the key file first
	files, err := ioutil.ReadDir(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read keystore directory: %v", err)
	}

	if len(files) == 0 {
		return fmt.Errorf("no key files found in %s", keyPath)
	}

	// Use the first file in the keystore directory
	keyFile := path.Join(keyPath, files[0].Name())
	key, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("failed to read key file: %v", err)
	}

	// Create wallet directory if it doesn't exist
	walletPath := "./wallet"
	if err := os.MkdirAll(walletPath, 0755); err != nil {
		return fmt.Errorf("failed to create wallet directory: %v", err)
	}

	// Create the wallet
	wallet, err := gateway.NewFileSystemWallet(walletPath)
	if err != nil {
		return fmt.Errorf("failed to create wallet: %v", err)
	}

	// Check if identity already exists
	if wallet.Exists("Admin") {
		fmt.Println("An identity for 'Admin' already exists in the wallet")
		return nil
	}

	// Create a new identity
	identity := gateway.NewX509Identity("Org1MSP", string(cert), string(key))

	// Put the identity in the wallet
	err = wallet.Put("Admin", identity)
	if err != nil {
		return fmt.Errorf("failed to put identity in wallet: %v", err)
	}

	fmt.Println("Successfully imported Admin identity into the wallet")
	return nil
}