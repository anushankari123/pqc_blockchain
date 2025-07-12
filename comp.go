package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/sign/dilithium"
	"github.com/cloudflare/circl/sign/falcon"
)

const MESSAGE = "This is a test message for benchmarking post-quantum cryptographic algorithms"

// BenchmarkResults holds performance data for each algorithm
type BenchmarkResults struct {
	KeyGenTime       time.Duration
	SignEncryptTime  time.Duration
	VerifyDecryptTime time.Duration
	PublicKeySize    int
	PrivateKeySize   int
	SignatureSize    int
}

func main() {
	fmt.Println("Benchmarking Post-Quantum Cryptographic Algorithms")
	fmt.Println("==================================================")

	// Run benchmarks
	dilithiumResults := benchmarkDilithium()
	falconResults := benchmarkFalcon()
	kyberResults := benchmarkKyber()

	// Print results in table format
	fmt.Println("\nResults Summary:")
	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Printf("%-15s | %-15s | %-15s | %-15s | %-15s | %-15s\n", 
		"Algorithm", "Key Gen (ms)", "Sign/Enc (ms)", "Verify/Dec (ms)", "PubKey (bytes)", "Sig/CT (bytes)")
	fmt.Println("--------------------------------------------------------------------------------")
	
	printResult("Dilithium", dilithiumResults)
	printResult("Falcon", falconResults)
	printResult("Kyber-512", kyberResults)
	
	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Println("\nNote: All tests performed on a single core. Real-world performance may vary.")
}

func printResult(name string, res BenchmarkResults) {
	fmt.Printf("%-15s | %-15.2f | %-15.2f | %-15.2f | %-15d | %-15d\n",
		name,
		float64(res.KeyGenTime.Microseconds())/1000,
		float64(res.SignEncryptTime.Microseconds())/1000,
		float64(res.VerifyDecryptTime.Microseconds())/1000,
		res.PublicKeySize,
		res.SignatureSize)
}

func benchmarkDilithium() BenchmarkResults {
	fmt.Println("\nBenchmarking Dilithium...")
	results := BenchmarkResults{}
	
	// Key generation
	start := time.Now()
	publicKey, privateKey, err := dilithium.Mode2.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("Error generating dilithium keys: %v\n", err)
		os.Exit(1)
	}
	results.KeyGenTime = time.Since(start)
	
	// Get serialized keys
	pubKeyBytes, _ := publicKey.MarshalBinary()
	privKeyBytes, _ := privateKey.MarshalBinary()
	results.PublicKeySize = len(pubKeyBytes)
	results.PrivateKeySize = len(privKeyBytes)
	
	// Signing
	message := []byte(MESSAGE)
	start = time.Now()
	signature, err := privateKey.Sign(rand.Reader, message, nil)
	if err != nil {
		fmt.Printf("Error signing with dilithium: %v\n", err)
		os.Exit(1)
	}
	results.SignEncryptTime = time.Since(start)
	results.SignatureSize = len(signature)
	
	// Verification
	start = time.Now()
	ok := publicKey.Verify(message, signature)
	results.VerifyDecryptTime = time.Since(start)
	
	if !ok {
		fmt.Println("Dilithium verification failed!")
	} else {
		fmt.Println("Dilithium verification succeeded")
		fmt.Printf("  Public key size: %d bytes\n", results.PublicKeySize)
		fmt.Printf("  Private key size: %d bytes\n", results.PrivateKeySize)
		fmt.Printf("  Signature size: %d bytes\n", results.SignatureSize)
	}
	
	return results
}

func benchmarkFalcon() BenchmarkResults {
	fmt.Println("\nBenchmarking Falcon...")
	results := BenchmarkResults{}
	
	// Key generation
	start := time.Now()
	publicKey, privateKey, err := falcon.Mode512.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("Error generating falcon keys: %v\n", err)
		os.Exit(1)
	}
	results.KeyGenTime = time.Since(start)
	
	// Get serialized keys
	pubKeyBytes, _ := publicKey.MarshalBinary()
	privKeyBytes, _ := privateKey.MarshalBinary()
	results.PublicKeySize = len(pubKeyBytes)
	results.PrivateKeySize = len(privKeyBytes)
	
	// Signing
	message := []byte(MESSAGE)
	start = time.Now()
	signature, err := privateKey.Sign(rand.Reader, message, nil)
	if err != nil {
		fmt.Printf("Error signing with falcon: %v\n", err)
		os.Exit(1)
	}
	results.SignEncryptTime = time.Since(start)
	results.SignatureSize = len(signature)
	
	// Verification
	start = time.Now()
	ok := publicKey.Verify(message, signature)
	results.VerifyDecryptTime = time.Since(start)
	
	if !ok {
		fmt.Println("Falcon verification failed!")
	} else {
		fmt.Println("Falcon verification succeeded")
		fmt.Printf("  Public key size: %d bytes\n", results.PublicKeySize)
		fmt.Printf("  Private key size: %d bytes\n", results.PrivateKeySize)
		fmt.Printf("  Signature size: %d bytes\n", results.SignatureSize)
	}
	
	return results
}

func benchmarkKyber() BenchmarkResults {
	fmt.Println("\nBenchmarking Kyber-512...")
	results := BenchmarkResults{}
	
	// Key generation
	start := time.Now()
	publicKey, privateKey, err := kyber512.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("Error generating kyber keys: %v\n", err)
		os.Exit(1)
	}
	results.KeyGenTime = time.Since(start)
	
	// Get key sizes
	results.PublicKeySize = kyber512.PublicKeySize
	results.PrivateKeySize = kyber512.PrivateKeySize
	
	// Message to encrypt (we'll use a random message of the required size)
	message := make([]byte, kyber512.SharedKeySize)
	rand.Read(message)
	
	// Encryption
	start = time.Now()
	ciphertext, sharedSecret, err := kyber512.Encapsulate(publicKey)
	if err != nil {
		fmt.Printf("Error encapsulating with kyber: %v\n", err)
		os.Exit(1)
	}
	results.SignEncryptTime = time.Since(start)
	results.SignatureSize = len(ciphertext) // Using signature size for ciphertext size
	
	// Decryption
	start = time.Now()
	decapsulated, err := kyber512.Decapsulate(privateKey, ciphertext)
	results.VerifyDecryptTime = time.Since(start)
	
	if err != nil || hex.EncodeToString(sharedSecret) != hex.EncodeToString(decapsulated) {
		fmt.Println("Kyber decapsulation failed!")
	} else {
		fmt.Println("Kyber decapsulation succeeded")
		fmt.Printf("  Public key size: %d bytes\n", results.PublicKeySize)
		fmt.Printf("  Private key size: %d bytes\n", results.PrivateKeySize)
		fmt.Printf("  Ciphertext size: %d bytes\n", results.SignatureSize)
		fmt.Printf("  Shared secret size: %d bytes\n", len(sharedSecret))
	}
	
	return results
}

// Benchmark functions for testing performance
func BenchmarkDilithiumKeyGen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, _ = dilithium.Mode2.GenerateKey(rand.Reader)
	}
}

func BenchmarkFalconKeyGen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, _ = falcon.Mode512.GenerateKey(rand.Reader)
	}
}

func BenchmarkKyberKeyGen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, _ = kyber512.GenerateKey(rand.Reader)
	}
}