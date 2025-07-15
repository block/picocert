
# picocert: Minimal Certificate Library

`picocert` is a minimal certificate library for handling compact X.509-like certificates, designed for embedded systems. It provides certificate chain validation and data signature verification using ECDSA (P-256) and SHA-256.

The library consists of:

- **C Library**: Core certificate validation and signature verification (`picocert.c/h`)
- **Go Package**: Certificate management tools and CLI (`pkg/picocert`, `cmd/picocert`)
- **CLI Tool**: Command-line interface for certificate operations
- **PKI Scripts**: Helper scripts for setting up certificate hierarchies

## Certificate Structure in Memory

Certificates are represented by the `picocert_t` struct (see `picocert.h`):

```c
typedef struct {
  uint8_t version;
  char issuer[PICOCERT_MAX_NAME_LEN];
  char subject[PICOCERT_MAX_NAME_LEN];
  uint64_t valid_from;  // Any monotonic timestamp, e.g. a unix timestamp or counter
  uint64_t valid_to;    // Ditto
  picocert_curve_t curve; // Only PICOCERT_P256 supported
  picocert_hash_t hash;   // Only PICOCERT_SHA256 supported
  uint32_t reserved;      // Must be zero
  uint8_t public_key[PICOCERT_MAX_PUBKEY_LEN]; // Uncompressed ECC public key
  uint8_t signature[PICOCERT_MAX_SIG_LEN];     // ECDSA signature
} PACKED picocert_t;
```

**Field layout:**

| Field         | Size (bytes) | Description                        |
|-------------- |--------------|------------------------------------|
| version       | 1            | Certificate version                |
| issuer        | 32           | Issuer name (null-terminated)      |
| subject       | 32           | Subject name (null-terminated)     |
| valid_from    | 8            | Start of validity                  |
| valid_to      | 8            | End of validity                    |
| curve         | 1            | Curve ID (0 = P-256)               |
| hash          | 1            | Hash ID (0 = SHA-256)              |
| reserved      | 4            | Reserved, must be zero             |
| public_key    | 65           | Uncompressed ECC public key (SEC1) |
| signature     | 64           | ECDSA signature raw (r||s)         |

Total size: **184 bytes** (packed)

## C Library API

### Setting Up Time Callback

Before using the library, set up a time callback for certificate validity checking:

```c
#include "picocert.h"

uint64_t get_current_time(void) {
    // Return current Unix timestamp
    return (uint64_t)time(NULL);
}

int main() {
    picocert_set_time_fn(get_current_time);
    // ... rest of your code
}
```

### Verifying Data with a Certificate Chain

The main API functions are:

```c
// Verify a hash with certificate chain validation
picocert_err_t picocert_verify_hash_and_validate_chain(const picocert_t* cert_chain,
                                                       const uint32_t chain_len,
                                                       const uint8_t hash[HASH_SHA256_DIGEST_SIZE],
                                                       const uint8_t signature[ECC_SIG_SIZE]);

// Verify hash with a single certificate (no chain validation)
picocert_err_t picocert_verify_hash(const picocert_t* cert,
                                    const uint8_t hash[HASH_SHA256_DIGEST_SIZE],
                                    const uint8_t signature[ECC_SIG_SIZE]);

// Validate certificate chain (without data verification)
picocert_err_t picocert_validate_cert_chain(const picocert_t* cert_chain,
                                           const uint32_t chain_len);
```

- `cert_chain`: Array of certificates, starting with the leaf and ending with the root.
- `chain_len`: Number of certificates in the chain.
- `hash`: Pre-computed SHA-256 hash of the data.
- `signature`: ECDSA signature to verify.

Returns `PICOCERT_OK` (0) on success, or an error code.

#### Example

```c
#include "picocert.h"

picocert_t certs[2]; // [0] = leaf, [1] = root
// ... fill certs, hash the data, and obtain signature ...
uint8_t data_hash[HASH_SHA256_DIGEST_SIZE] = { ... };
uint8_t signature[ECC_SIG_SIZE] = { ... };

picocert_err_t err = picocert_verify_hash_and_validate_chain(certs, 2, data_hash, signature);
if (err == PICOCERT_OK) {
    // Data is valid and cert chain is trusted
} else {
    // Handle error
}
```

### Debug Functions

```c
// Print certificate contents in human-readable format
void picocert_print_cert(const picocert_t* cert);
```

### Certificate Validation Details

The validation functions perform:

1. **Certificate chain validation:**
    - Each cert is signed by the next (issuer).
    - The root cert must be self-signed.
    - Validity periods are checked against current time.
    - Reserved fields must be zero.
    - Version numbers must match.
    - Issuer/subject name consistency is verified.
2. **Signature verification:**
    - The leaf cert's public key is used to verify the data signature.

### Error Codes

| Error Code                  | Value | Meaning                        |
|-----------------------------|-------|--------------------------------|
| PICOCERT_OK                 | 0     | Success                        |
| PICOCERT_ERR_INVALID        | 1     | Invalid argument               |
| PICOCERT_ERR_EXPIRED        | 2     | Certificate expired/not yet valid |
| PICOCERT_ERR_SIGNATURE      | 3     | Signature verification failed  |
| PICOCERT_ERR_ISSUER         | 4     | Issuer/subject mismatch        |
| PICOCERT_ERR_VERSION        | 5     | Version mismatch               |
| PICOCERT_ERR_RESERVED       | 6     | Reserved field nonzero         |
| PICOCERT_ERR_NOT_SELF_SIGNED| 7     | Root not self-signed           |
| PICOCERT_ERR_UNKNOWN        | 255   | Unknown error                  |

## CLI Tool

The `picocert` command-line tool provides certificate management functionality:

### Installation

```bash
cd cmd/picocert
go build -o picocert
```

### Commands

#### Issue Certificates

```bash
# Create a self-signed root certificate
picocert issue --subject "MyRoot" --validity_in_days 3650 --self_signed

# Create a certificate signed by an issuer
picocert issue --subject "MyLeaf" --validity_in_days 365 \
  --issuer root.pct --issuer_key root.priv.der
```

#### Sign Binary Files

```bash
# Sign a binary file
picocert sign --key private.priv.der --binary firmware.bin --output firmware.sig

# Sign and print signature to stdout
picocert sign --key private.priv.der --binary firmware.bin
```

#### Verify Signatures

```bash
# Verify a signed binary
picocert verify --cert certificate.pct --binary firmware.bin --signature firmware.sig
```

### Global Flags

- `--quiet, -q`: Suppress output messages

## Setting Up a Three-Tier PKI

Use the included script to set up a complete PKI hierarchy:

```bash
# Set up a three-tier PKI for firmware signing
./three-tier-pki.sh ./cmd/picocert/picocert firmware

# This creates:
# - firmware-root.pct/priv.der (Root CA, 10-year validity)
# - firmware-intermediate.pct/priv.der (Intermediate CA, 6-year validity)
# - firmware-leaf.pct/priv.der (Leaf certificate, 4-year validity)
```

**⚠️ Warning**: The script uses long validity periods suitable for testing. For production use, consider shorter validity periods and proper key management practices.

## Go Package

The Go package `github.com/block/picocert/pkg/picocert` provides high-level certificate operations.

### Go Installation

```bash
go get github.com/block/picocert/pkg/picocert
```

### Usage

#### Certificate Issuance

```go
package main

import (
    "time"
    "github.com/block/picocert/pkg/picocert"
)

func main() {
    // Issue a self-signed certificate
    validFrom := uint64(time.Now().Unix())
    validTo := validFrom + 365*24*60*60 // 1 year

    cert, err := picocert.Issue(nil, "MyDevice", validFrom, validTo)
    if err != nil {
        panic(err)
    }

    // cert.Cert contains the certificate
    // cert.PrivateKey contains the PKCS#8 encoded private key
}
```

#### Certificate Signing

```go
// Issue a certificate signed by an issuer
issuerCert := &picocert.CertificateWithKey{
    Cert:       issuerCertificate,
    PrivateKey: issuerPrivateKeyBytes,
}

signedCert, err := picocert.Issue(issuerCert, "SubjectName", validFrom, validTo)
if err != nil {
    panic(err)
}
```

#### Data Signing and Verification

```go
// Sign data
privateKey, err := picocert.ParsePrivateKey(privateKeyBytes)
if err != nil {
    panic(err)
}

signature, err := picocert.Sign(privateKey, data)
if err != nil {
    panic(err)
}

// Verify signature
err = picocert.Verify(&certificate, data, signature)
if err != nil {
    // Verification failed
}
```

#### Certificate Chain Validation

```go
// Validate a certificate chain
chain := []picocert.Certificate{leafCert, intermediateCert, rootCert}

err := picocert.ValidateCertChain(chain)
if err != nil {
    // Chain validation failed
}

// Verify data against the chain
err = picocert.VerifyAndValidateChain(chain, data, signature)
if err != nil {
    // Verification or validation failed
}
```

#### Parsing Certificates and Keys

```go
// Parse certificate from bytes
cert, err := picocert.ParseCertificate(certBytes)
if err != nil {
    panic(err)
}

// Parse private key from PKCS#8 format
privateKey, err := picocert.ParsePrivateKey(keyBytes)
if err != nil {
    panic(err)
}

// Convert certificate to bytes
certBytes := cert.ToBytes()
```

### Go Package Types

```go
type Certificate struct {
    Version   uint8
    Issuer    [32]byte
    Subject   [32]byte
    ValidFrom uint64
    ValidTo   uint64
    Curve     Curve
    Hash      Hash
    Reserved  uint32
    PubKey    [65]byte
    Signature [64]byte
}

type CertificateWithKey struct {
    Cert       Certificate
    PrivateKey []byte  // PKCS#8 encoded
}

// Constants
const (
    P256 Curve = 0     // ECDSA P-256
    Sha256 Hash = 0    // SHA-256
)
```

## Notes

- Only ECDSA P-256 and SHA-256 are supported.
- All fields are packed; no padding.
- Names are fixed-length, null-terminated strings.
- Public key is uncompressed (0x04 | X | Y, 65 bytes).
- Signature is raw ECDSA (r||s, 64 bytes).
- Timestamps are Unix epoch seconds.
- The C library requires a time callback to be set for certificate validation.

## File Formats

- **Certificates**: Binary format (`.pct` extension), 184 bytes each
- **Private Keys**: PKCS#8 DER format (`.priv.der` extension)
- **Signatures**: Raw binary, 64 bytes (r||s format)

## Security Considerations

- Private keys should be stored securely and never transmitted in plaintext
- Consider using hardware security modules (HSMs) for root CA key storage
- Implement proper key rotation and certificate renewal procedures
- Validate certificate chains completely before trusting signatures
- Use appropriate validity periods for your security requirements
