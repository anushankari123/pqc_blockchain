# 🛡️ PQC Blockchain: Quantum-Resistant Certificate Authority using Hyperledger Fabric

This project implements a **hybrid certificate authority (CA)** system that integrates **post-quantum cryptography (PQC)** with **Hyperledger Fabric** to provide secure, role-based identity management for blockchain applications in the post-quantum era.

## 🌐 Overview

- 🔐 **Classical + PQC Hybrid Certificates**: Combines ECDSA with Kyber512, Falcon-512, and Dilithium2 algorithms.
- 🧑‍💻 **Role-Based Keying**:
  - `User` → Kyber512 (KEM)
  - `Admin` → Falcon-512 (Signature)
  - `SuperAdmin` → Dilithium2 (Signature)
- 📄 **X.509 Certificates**: Classical key signs the certificate, while PQC keys are embedded in custom OIDs.
- 🔗 **Hyperledger Fabric Chaincode**: Certificates and metadata are stored securely in Fabric’s world state.
- 🌐 **REST API Backend (Go)**: Certificate generation and download endpoints using `liboqs-go` and `mux`.

---

## 📁 Project Structure

