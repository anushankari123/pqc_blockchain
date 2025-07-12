# PQC Blockchain - Hybrid Certificate Authority

This project implements a hybrid certificate authority that uses both **classical cryptography (ECDSA)** and **post-quantum cryptography (Kyber512, Falcon-512, Dilithium2)** to issue certificates based on user roles.

Certificates are generated through a REST API and stored securely in **Hyperledger Fabric** using a Go-based smart contract.

- **User → Kyber512**
- **Admin → Falcon-512**
- **SuperAdmin → Dilithium2**

The system ensures future-proof identity management by combining post-quantum security with blockchain-backed integrity.
