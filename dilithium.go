package main

import (
	"fmt"
	"github.com/open-quantum-safe/liboqs-go/oqs"
)

type User struct {
	Username string
	Role     string
}

func main() {
	// Define users with different roles
	users := []User{
		{Username: "Alice", Role: "user"},
		{Username: "Bob", Role: "admin"},
		{Username: "Charlie", Role: "super-admin"},
	}

	fmt.Println("Available Signature Algorithms:")
	for _, algo := range oqs.EnabledSigs() {
		fmt.Printf("- %s\n", algo)
	}

	for _, user := range users {
		fmt.Printf("\nProcessing user: %s with role: %s\n", user.Username, user.Role)

		var sig oqs.Signature
		err := sig.Init("Falcon-512", nil)
		if err != nil {
			fmt.Printf("Error initializing Falcon: %v\n", err)
			continue
		}
		defer sig.Clean()

		publicKey, err := sig.GenerateKeyPair()
		if err != nil {
			fmt.Printf("Error generating keypair: %v\n", err)
			continue
		}

		fmt.Println("Successfully generated Falcon-512 keypair:")
		fmt.Printf("Public key length: %d bytes\n", len(publicKey))

		message := []byte("This is a test message for Falcon signature")

		if user.Role == "user" {
			fmt.Println("User role can only view public key.")
		} else if user.Role == "admin" {
			signature, err := sig.Sign(message)
			if err != nil {
				fmt.Printf("Error during signing: %v\n", err)
				continue
			}
			fmt.Printf("Successfully signed message for %s:\n", user.Username)
			fmt.Printf("Signature length: %d bytes\n", len(signature))
		} else if user.Role == "super-admin" {
			signature, err := sig.Sign(message)
			if err != nil {
				fmt.Printf("Error during signing: %v\n", err)
				continue
			}
			fmt.Printf("Successfully signed message for %s:\n", user.Username)
			fmt.Printf("Signature length: %d bytes\n", len(signature))

			// Super-admin can also verify the signature
			isValid, err := sig.Verify(message, signature, publicKey)
			if err != nil {
				fmt.Printf("Error during verification: %v\n", err)
				continue
			}

			if isValid {
				fmt.Println("Signature successfully verified!")
			} else {
				fmt.Println("Signature verification failed!")
			}
		}
	}
}