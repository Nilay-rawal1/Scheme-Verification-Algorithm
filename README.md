# Modular Signature Scheme Verification Algorithm

## Overview
This project provides a modular algorithm for verifying digital signatures across various cryptographic schemes such as **ECDSA** and **Schnorr**. The algorithm can identify the signature type, process the verification accordingly, and ensure that the signed address matches the recovered address, offering universal compatibility with different signature formats.

## Features
- **Supports Multiple Signature Schemes**: Easily extensible to support new signature schemes.
- **Optimized for Efficiency**: Reduces computational cost by handling common failure cases early.
- **Flexible Input Format**: Accepts signatures as byte arrays, with dynamic signature scheme identification.

## Folder Structure
```
modular_signature_verification/
├── src/
│   ├── signature_verifier.py         # Main verifier class for handling scheme selection and verification
│   ├── signature_schemes/
│   │   ├── ecdsa_scheme.py           # ECDSA verification logic
│   │   └── schnorr_scheme.py         # Schnorr verification logic
├── tests/
│   ├── test_signature_verifier.py    # Unit tests for verifier functionality
├── README.md                         # Project documentation
└── requirements.txt                  # Required libraries
```
## Requirements
- **Python 3.8 or later**
- Required libraries listed in `requirements.txt`

## Setup Instructions

1. **Clone the Repository**
    ```bash
   git clone https://github.com/your-username/modular_signature_verification.git
   cd modular_signature_verification
3. **Install Required Libraries Install libraries using:**
   
    ```bash
    pip install -r requirements.txt

## Usage Instructions
Initialize the SignatureVerifier Use the SignatureVerifier class, which can dynamically select the verification algorithm based on input.
from src.signature_verifier import SignatureVerifier

### Define example inputs for signature verification
```
  signer_address = "04bfcab3ebc69d23b5b63d7a034bd3466b14f6e3b4f7c9e9af9f4f04f8f8aaba7127b0c37f9b6bd086c2c15f589ece1d7e7aeab85be905c8ae3d55bb92f567cbb3"
  signed_hash = b'\x93\xa1...\x1b'  # Example 32-byte hash
  signature = bytes.fromhex("304402200e3d4f73a8ec45d207842a5c03e81c7d1c060ca125e8d3af86")
```
### Initialize verifier for ECDSA scheme
  ```blash
  verifier = SignatureVerifier(scheme_type="ecdsa")
  result = verifier.verify(signer_address, signature, signed_hash)
  
  print(f"Signature verification result: {result}") 
```
### Run Tests Run tests to validate different signature schemes:
  ```blas
python -m unittest discover -s tests
```
## Example
  ### Verify an ECDSA signature with the following code:
  ```
  from src.signature_verifier import SignatureVerifier
  ```
  ## Define inputs
```  signer_address = "04bfcab3ebc69d23b5b63d7a034bd3466b14f6e3b4f7c9e9af9f4f04f8f8aaba7127b0c37f9b6bd086c2c15f589ece1d7e7aeab85be905c8ae3d55bb92f567cbb3"
  signed_hash = b'\x93\xa1...\x1b'  # Example 32-byte hash
  ecdsa_signature = bytes.fromhex("304402200e3d4f73a8ec45d207842a5c03e81c7d1c060ca125e8d3af86")
  ```
  ## Create the verifier for ECDSA
```
 verifier = SignatureVerifier(scheme_type="ecdsa")
  result = verifier.verify(signer_address, ecdsa_signature, signed_hash)
  print("ECDSA signature is valid:", result)
```
#  License
  This project is licensed under the MIT License.


This markdown file covers setup, usage, and example code to make getting started with your project straightforward. Let me know if any other details would be useful!


