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
- [API Reference](#api-reference)  


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

## Installation

1. Clone the repository:

```bash

python -m venv venv
source venv/bin/activate  # Linux 
mkdir src
cd src
git clone https://github.com/Grano14/Digital_sign_blockchain.git
pip install -r requirements.txt
```

## Usage

The main client script is `local_script.py`. It supports the following command-line options:

### Generate RSA Keys

Generate a new 2048-bit RSA key pair (private and public keys):

```bash
python local_script.py -gen