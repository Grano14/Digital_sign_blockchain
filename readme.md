# Blockchain Digital Signature System

A Python-based system for securely notarizing and verifying files using digital signatures on a private blockchain.  
This project combines **local signing** with a **FastAPI blockchain server** for immutably storing file hashes and signatures.

---

## Table of Contents

- [Overview](#overview)  
- [Installation](#installation)  
- [Configuration](#configuration)  
- [Usage](#usage)  
  - [Generate Keys](#generate-keys)  
  - [Sign a File](#sign-a-file)  
  - [Validate a File](#validate-a-file)  
 


---

## Overview

This project allows users to:

1. **Generate RSA key pairs** locally.
2. **Sign files locally** using a private key.
3. **Send file hash, signature, and public key** to the blockchain.
4. **Verify file authenticity** using the blockchain and digital signatures.

All signing is done **locally** for security, while the blockchain guarantees **immutability** and **traceability.

---

- **Client**: Generates keys, signs files, sends signature JSON to the API.  
- **Server**: Maintains blockchain, verifies signatures, provides endpoints for notarization and verification.

---

## Configuration

THe conf.json file is used to configure the ip and port uf the server, it is set to http://localhost:8000, if you change the port of the server modify this file.

## Installation

Run the following command to install correctly the repository

```bash

python3 -m venv venv
source venv/bin/activate  # Linux 
mkdir src
cd src
git clone https://github.com/Grano14/Digital_sign_blockchain.git
pip install -r requirements.txt
```

## Usage

Run the server using:
```bash
uvicorn api.app:app --reload
```

The main client script is `client.py`. It supports the following command-line options:

### Generate RSA Keys

Generate a new 2048-bit RSA key pair (private and public keys):

```bash
python3 client.py -gen
```

## Sign a file

Sign a file using your private key. This computes the SHA-256 hash, signs it, saves a signature.json file, and uploads the data to the blockchain.
```bash
python3 client.py -sign <file> <private_key.pem>
```

## Validate a File

Validate a file against the blockchain. This computes the file's hash, queries the blockchain, and checks the signature.
```bash
python3 client.py -validate <file> <signature.json>
```