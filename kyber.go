package main

import (
	"bytes"
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

	fmt.Println("Available KEM Algorithms:")
	for _, algo := range oqs.EnabledKEMs() {
		fmt.Printf("-%s\n", algo)
	}

	for _, user := range users {
		fmt.Printf("\nProcessing user: %s with role: %s\n", user.Username, user.Role)

		// Create a KEM instance for this user
		var kem oqs.KeyEncapsulation
		err := kem.Init("Kyber512", nil)
		if err != nil {
			fmt.Printf("Error Initializing Kyber: %v\n", err)
			continue
		}
		defer kem.Clean()

		// Generate keypair
		publicKey, err := kem.GenerateKeyPair()
		if err != nil {
			fmt.Printf("Error generating keypair: %v\n", err)
			continue
		}

		fmt.Printf("Successfully generated %s keypair for %s:\n", "Kyber512", user.Username)
		fmt.Printf("Public Key length: %d bytes\n", len(publicKey))

		if user.Role == "user" {
			fmt.Println("User role can only view public key.")
		} else if user.Role == "admin" {
			// Perform encapsulation
			sharedSecret, ciphertext, err := kem.EncapSecret(publicKey)
			if err != nil {
				fmt.Printf("Error during encapsulation: %v\n", err)
				continue
			}
			fmt.Printf("Successfully performed Encapsulation for %s:\n", user.Username)
			fmt.Printf("Ciphertext Length: %d bytes\n", len(ciphertext))
			fmt.Printf("Shared secret length: %d bytes\n", len(sharedSecret))
		} else if user.Role == "super-admin" {
			// For super-admin, perform both encapsulation and decapsulation
			// using the same KEM instance (which contains the secret key)
			
			// Perform encapsulation
			sharedSecret, ciphertext, err := kem.EncapSecret(publicKey)
			if err != nil {
				fmt.Printf("Error during encapsulation: %v\n", err)
				continue
			}
			fmt.Printf("Successfully performed Encapsulation for %s:\n", user.Username)
			fmt.Printf("Ciphertext Length: %d bytes\n", len(ciphertext))
			fmt.Printf("Shared secret length: %d bytes\n", len(sharedSecret))

			// Check if the ciphertext length matches the expected length for Kyber512
			expectedLength := 768
			if len(ciphertext) != expectedLength {
				fmt.Printf("Warning: Ciphertext length is %d bytes, expected %d bytes for Kyber512\n", 
					len(ciphertext), expectedLength)
				
				// If the length doesn't match, create a new ciphertext of correct length
				correctedCiphertext := make([]byte, expectedLength)
				copy(correctedCiphertext, ciphertext)
				
				// Try decapsulation with the corrected ciphertext
				decryptedSecret, err := kem.DecapSecret(correctedCiphertext)
				if err != nil {
					fmt.Printf("Error during decapsulation with corrected ciphertext: %v\n", err)
					fmt.Printf("Attempting decapsulation with original ciphertext...\n")
					
					// Fall back to original ciphertext
					decryptedSecret, err = kem.DecapSecret(ciphertext)
					if err != nil {
						fmt.Printf("Error during decapsulation with original ciphertext: %v\n", err)
					} else {
						fmt.Printf("Successfully performed Decapsulation for %s:\n", user.Username)
						fmt.Printf("Decrypted secret length: %d bytes\n", len(decryptedSecret))
						
						// Verify the decrypted secret matches the original
						if bytes.Equal(sharedSecret, decryptedSecret) {
							fmt.Println("Shared secret matches decrypted secret!")
						} else {
							fmt.Println("WARNING: Shared secret does not match decrypted secret!")
						}
					}
				} else {
					fmt.Printf("Successfully performed Decapsulation with corrected ciphertext for %s:\n", user.Username)
					fmt.Printf("Decrypted secret length: %d bytes\n", len(decryptedSecret))
					
					// Verify the decrypted secret matches the original
					if bytes.Equal(sharedSecret, decryptedSecret) {
						fmt.Println("Shared secret matches decrypted secret!")
					} else {
						fmt.Println("WARNING: Shared secret does not match decrypted secret!")
					}
				}
			} else {
				// Normal decapsulation if ciphertext length is as expected
				decryptedSecret, err := kem.DecapSecret(ciphertext)
				if err != nil {
					fmt.Printf("Error during decapsulation: %v\n", err)
				} else {
					fmt.Printf("Successfully performed Decapsulation for %s:\n", user.Username)
					fmt.Printf("Decrypted secret length: %d bytes\n", len(decryptedSecret))
					
					// Verify the decrypted secret matches the original
					if bytes.Equal(sharedSecret, decryptedSecret) {
						fmt.Println("Shared secret matches decrypted secret!")
					} else {
						fmt.Println("WARNING: Shared secret does not match decrypted secret!")
					}
				}
			}
		}
	}
}