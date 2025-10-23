#pragma once

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define HASH_SHA256_DIGEST_SIZE 32

#ifndef ECC_SIG_SIZE
#define ECC_SIG_SIZE 64
#endif

#ifndef ECC_PUBKEY_SIZE_ECDSA_UNCOMPRESSED
#define ECC_PUBKEY_SIZE_ECDSA_UNCOMPRESSED 64
#endif

// Attribute macros
#ifndef PACKED
#ifdef __GNUC__
#define PACKED __attribute__((packed))
#else
#define PACKED
#endif
#endif

// Maximum length for names (issuer and subject) in the certificate
#define PICOCERT_MAX_NAME_LEN (32)

// Maximum length for the public key in the certificate
#define PICOCERT_MAX_PUBKEY_LEN (65)  // Uncompressed SEC1 encoding

// Maximum length for the signature in the certificate
#define PICOCERT_MAX_SIG_LEN (64)

// Maximum length for certificate chains (prevents DoS attacks)
#define PICOCERT_MAX_CHAIN_LEN (10)

// Current version of the picocert library
#define PICOCERT_CURRENT_VERSION 1

typedef uint8_t picocert_curve_t;
enum {
  PICOCERT_P256 = 0,
};

typedef uint8_t picocert_hash_t;
enum {
  PICOCERT_SHA256 = 0,
};

typedef enum {
  PICOCERT_OK = 0,
  PICOCERT_ERR_INVALID = 1,
  PICOCERT_ERR_EXPIRED = 2,
  PICOCERT_ERR_SIGNATURE = 3,
  PICOCERT_ERR_ISSUER = 4,
  PICOCERT_ERR_VERSION = 5,
  PICOCERT_ERR_RESERVED = 6,
  PICOCERT_ERR_NOT_SELF_SIGNED = 7,
  PICOCERT_ERR_INVALID_FORMAT = 8,
  PICOCERT_ERR_CONTEXT_NOT_INITIALIZED = 9,
  PICOCERT_ERR_HASH_FAILED = 10,
  PICOCERT_ERR_UNSUPPORTED_CURVE = 11,
  PICOCERT_ERR_UNSUPPORTED_HASH = 12,
  PICOCERT_ERR_INVALID_VALIDITY_PERIOD = 13,
  PICOCERT_ERR_CHAIN_TOO_LONG = 14,
  PICOCERT_ERR_UNKNOWN = 255,
} picocert_err_t;

typedef struct {
  uint8_t version;

  char issuer[PICOCERT_MAX_NAME_LEN];
  char subject[PICOCERT_MAX_NAME_LEN];

  uint64_t valid_from;  // Start of the validity period
  uint64_t valid_to;    // End of the validity period

  picocert_curve_t curve;
  picocert_hash_t hash;

  uint32_t reserved;  // Reserved for future use, should be zero

  uint8_t public_key[PICOCERT_MAX_PUBKEY_LEN];
  uint8_t signature[PICOCERT_MAX_SIG_LEN];
} PACKED picocert_t;

/*
 * A certificate chain, stored as a contiguous array of picocert_t structures
 * in memory, ordered from leaf to root
 */
typedef picocert_t* picocert_chain_t;

// System time callback function type. Could be unix timestamps, but any
// monotonic counter is fine.
typedef uint64_t (*picocert_time_fn_t)(void);

// =============================================================================
// ENDIANNESS CONVERSION HELPERS
// =============================================================================

// On-wire format is little-endian for better embedded compatibility
static inline uint64_t picocert_le64_to_host(const uint8_t* bytes) {
  return ((uint64_t)bytes[0]) | ((uint64_t)bytes[1] << 8) |
         ((uint64_t)bytes[2] << 16) | ((uint64_t)bytes[3] << 24) |
         ((uint64_t)bytes[4] << 32) | ((uint64_t)bytes[5] << 40) |
         ((uint64_t)bytes[6] << 48) | ((uint64_t)bytes[7] << 56);
}

static inline void picocert_host_to_le64(uint64_t value, uint8_t* bytes) {
  bytes[0] = (uint8_t)(value & 0xFF);
  bytes[1] = (uint8_t)((value >> 8) & 0xFF);
  bytes[2] = (uint8_t)((value >> 16) & 0xFF);
  bytes[3] = (uint8_t)((value >> 24) & 0xFF);
  bytes[4] = (uint8_t)((value >> 32) & 0xFF);
  bytes[5] = (uint8_t)((value >> 40) & 0xFF);
  bytes[6] = (uint8_t)((value >> 48) & 0xFF);
  bytes[7] = (uint8_t)((value >> 56) & 0xFF);
}

static inline uint32_t picocert_le32_to_host(const uint8_t* bytes) {
  return ((uint32_t)bytes[0]) | ((uint32_t)bytes[1] << 8) |
         ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static inline void picocert_host_to_le32(uint32_t value, uint8_t* bytes) {
  bytes[0] = (uint8_t)(value & 0xFF);
  bytes[1] = (uint8_t)((value >> 8) & 0xFF);
  bytes[2] = (uint8_t)((value >> 16) & 0xFF);
  bytes[3] = (uint8_t)((value >> 24) & 0xFF);
}

// =============================================================================
// SAFE ACCESSORS FOR POTENTIALLY UNALIGNED FIELDS
// =============================================================================

static inline uint64_t picocert_get_valid_from(const picocert_t* cert) {
  return picocert_le64_to_host((const uint8_t*)&cert->valid_from);
}

static inline void picocert_set_valid_from(picocert_t* cert, uint64_t value) {
  picocert_host_to_le64(value, (uint8_t*)&cert->valid_from);
}

static inline uint64_t picocert_get_valid_to(const picocert_t* cert) {
  return picocert_le64_to_host((const uint8_t*)&cert->valid_to);
}

static inline void picocert_set_valid_to(picocert_t* cert, uint64_t value) {
  picocert_host_to_le64(value, (uint8_t*)&cert->valid_to);
}

static inline uint32_t picocert_get_reserved(const picocert_t* cert) {
  return picocert_le32_to_host((const uint8_t*)&cert->reserved);
}

static inline void picocert_set_reserved(picocert_t* cert, uint32_t value) {
  picocert_host_to_le32(value, (uint8_t*)&cert->reserved);
}

// =============================================================================
// CRYPTO FUNCTION POINTER TYPES
// =============================================================================

/**
 * Hash function pointer type
 * @param data Input data to hash
 * @param data_len Length of input data
 * @param digest Output buffer for hash (must be at least
 * HASH_SHA256_DIGEST_SIZE bytes)
 * @param digest_len Size of output buffer
 * @return true on success, false on failure
 */
typedef bool (*picocert_hash_fn_t)(const uint8_t* data, uint32_t data_len,
                                   uint8_t* digest, uint32_t digest_len);

/**
 * ECC signature verification function pointer type
 * @param key Pointer to the public key data (X,Y coordinates)
 * @param key_size Size of the public key data
 * @param hash Hash to verify (HASH_SHA256_DIGEST_SIZE bytes)
 * @param hash_len Length of hash
 * @param signature Signature to verify (ECC_SIG_SIZE bytes)
 * @return true if signature is valid, false otherwise
 */
typedef bool (*picocert_ecc_verify_fn_t)(const uint8_t* key, size_t key_size,
                                         const uint8_t* hash, uint32_t hash_len,
                                         const uint8_t* signature);

// =============================================================================
// LIBRARY CONTEXT
// =============================================================================

typedef struct {
  picocert_hash_fn_t hash_fn;
  picocert_ecc_verify_fn_t ecc_verify_fn;
  picocert_time_fn_t time_fn;
} picocert_context_t;

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Extract public key from certificate
 * @param cert Certificate containing the public key
 * @param key_out Output parameter for pointer to key (X,Y coordinates)
 * @param key_size_out Output parameter for key size
 * @return PICOCERT_OK on success, error code on failure
 */
static inline picocert_err_t picocert_cert_to_key(const picocert_t* cert,
                                                  const uint8_t** key_out,
                                                  size_t* key_size_out) {
  if (!cert || !key_out || !key_size_out) {
    return PICOCERT_ERR_INVALID;
  }

  // Validate SEC1 uncompressed format (must start with 0x04)
  if (cert->public_key[0] != 0x04) {
    return PICOCERT_ERR_INVALID_FORMAT;
  }

  // Extract X,Y coordinates
  *key_out = &cert->public_key[1];
  *key_size_out = ECC_PUBKEY_SIZE_ECDSA_UNCOMPRESSED;

  return PICOCERT_OK;
}

static picocert_err_t picocert_current_time(const picocert_context_t* ctx,
                                            uint64_t* time_out) {
  if (!ctx || !time_out) {
    return PICOCERT_ERR_INVALID;
  }
  if (!ctx->time_fn) {
    return PICOCERT_ERR_INVALID;
  }
  *time_out = ctx->time_fn();
  return PICOCERT_OK;
}

static bool picocert_is_self_signed(const picocert_t* cert) {
  return (strncmp(cert->issuer, cert->subject, PICOCERT_MAX_NAME_LEN) == 0);
}

// =============================================================================
// CORE IMPLEMENTATION
// =============================================================================

/**
 * @brief Verify that a certificate was properly signed by its issuer
 *
 * This function verifies that the certificate's signature was created by
 * signing all the certificate data (except the signature field itself) with the
 * issuer's private key.
 *
 * @param ctx Library context
 * @param cert Certificate to verify (contains the signature to check)
 * @param issuer Issuer certificate (contains the public key to verify against)
 * @return PICOCERT_OK if signature is valid, error code otherwise
 */
static picocert_err_t picocert_verify_cert_signature(
    const picocert_context_t* ctx, const picocert_t* cert,
    const picocert_t* issuer) {
  if (!ctx || !cert || !issuer) {
    return PICOCERT_ERR_INVALID;
  }

  if (!ctx->hash_fn || !ctx->ecc_verify_fn) {
    return PICOCERT_ERR_CONTEXT_NOT_INITIALIZED;
  }

  // Extract the signable data from the certificate (everything except
  // signature)
  const uint32_t signable_data_size = offsetof(picocert_t, signature);

  // Hash the signable certificate data
  uint8_t digest[HASH_SHA256_DIGEST_SIZE] = {0};
  if (!ctx->hash_fn((const uint8_t*)cert, signable_data_size, digest,
                    sizeof(digest))) {
    return PICOCERT_ERR_HASH_FAILED;
  }

  // Verify the signature using issuer's public key
  const uint8_t* pubkey;
  size_t pubkey_size;
  picocert_err_t key_err = picocert_cert_to_key(issuer, &pubkey, &pubkey_size);
  if (key_err != PICOCERT_OK) {
    return key_err;
  }
  if (!ctx->ecc_verify_fn(pubkey, pubkey_size, digest, HASH_SHA256_DIGEST_SIZE,
                          cert->signature)) {
    return PICOCERT_ERR_SIGNATURE;
  }

  return PICOCERT_OK;
}

// =============================================================================
// PUBLIC API
// =============================================================================

/**
 * Initialize a picocert context with crypto function pointers
 * @param ctx Context to initialize
 * @param hash_fn Function pointer for SHA-256 hashing
 * @param ecc_verify_fn Function pointer for ECC signature verification
 * @param time_fn Optional time callback function (can be NULL)
 * @return PICOCERT_OK on success, error code on failure
 */
static picocert_err_t __attribute__((used)) picocert_init_context(
    picocert_context_t* ctx, picocert_hash_fn_t hash_fn,
    picocert_ecc_verify_fn_t ecc_verify_fn, picocert_time_fn_t time_fn) {
  if (!ctx) {
    return PICOCERT_ERR_INVALID;
  }

  if (!hash_fn || !ecc_verify_fn) {
    // Reset context state on invalid initialization
    ctx->hash_fn = NULL;
    ctx->ecc_verify_fn = NULL;
    ctx->time_fn = NULL;
    return PICOCERT_ERR_INVALID;
  }

  ctx->hash_fn = hash_fn;
  ctx->ecc_verify_fn = ecc_verify_fn;
  ctx->time_fn = time_fn;

  return PICOCERT_OK;
}

/**
 * @brief Validate a single certificate against its issuer
 *
 * This function performs comprehensive validation of a certificate including:
 * - Version compatibility check
 * - Cryptographic algorithm support (curve and hash)
 * - Reserved field validation
 * - Certificate signature verification (that issuer signed the subject)
 * - Issuer/subject name consistency
 * - Validity period consistency (valid_from <= valid_to)
 * - Certificate validity period (not expired)
 *
 * @param ctx Library context (must be initialized)
 * @param issuer Issuer certificate (contains public key to verify subject's
 * signature)
 * @param subject Subject certificate to validate
 * @return PICOCERT_OK if certificate is valid, error code otherwise
 */
static picocert_err_t picocert_validate_cert(picocert_context_t* ctx,
                                             const picocert_t* issuer,
                                             const picocert_t* subject) {
  if (!ctx || !issuer || !subject) {
    return PICOCERT_ERR_INVALID;
  }

  // Version check
  if (issuer->version != PICOCERT_CURRENT_VERSION ||
      subject->version != PICOCERT_CURRENT_VERSION) {
    return PICOCERT_ERR_VERSION;
  }

  // Validate curve - only P256 is currently supported
  if (issuer->curve != PICOCERT_P256 || subject->curve != PICOCERT_P256) {
    return PICOCERT_ERR_UNSUPPORTED_CURVE;
  }

  // Validate hash algorithm - only SHA256 is currently supported
  if (issuer->hash != PICOCERT_SHA256 || subject->hash != PICOCERT_SHA256) {
    return PICOCERT_ERR_UNSUPPORTED_HASH;
  }

  // Reserved fields must be zero
  if (picocert_get_reserved(issuer) != 0 ||
      picocert_get_reserved(subject) != 0) {
    return PICOCERT_ERR_RESERVED;
  }

  // Ensure validity periods are logical (start <= end)
  if (picocert_get_valid_from(subject) > picocert_get_valid_to(subject)) {
    return PICOCERT_ERR_INVALID_VALIDITY_PERIOD;
  }
  if (picocert_get_valid_from(issuer) > picocert_get_valid_to(issuer)) {
    return PICOCERT_ERR_INVALID_VALIDITY_PERIOD;
  }

  // Ensure the issuer signed the subject's certificate
  picocert_err_t err = picocert_verify_cert_signature(ctx, subject, issuer);
  if (err != PICOCERT_OK) {
    return err;
  }

  // Ensure the names match
  if (strncmp(issuer->subject, subject->issuer, PICOCERT_MAX_NAME_LEN) != 0) {
    return PICOCERT_ERR_ISSUER;
  }

  // Ensure the certificate is not expired
  uint64_t now;
  picocert_err_t time_err = picocert_current_time(ctx, &now);
  if (time_err != PICOCERT_OK) {
    return time_err;
  }
  if (now < picocert_get_valid_from(subject) ||
      now > picocert_get_valid_to(subject)) {
    return PICOCERT_ERR_EXPIRED;
  }
  if (now < picocert_get_valid_from(issuer) ||
      now > picocert_get_valid_to(issuer)) {
    return PICOCERT_ERR_EXPIRED;
  }

  return PICOCERT_OK;
}

/**
 * @brief Validate a complete certificate chain
 *
 * This function validates a certificate chain from leaf to root by:
 * - Enforcing maximum chain length (PICOCERT_MAX_CHAIN_LEN)
 * - Validating each certificate in the chain against its issuer
 * - Ensuring the root certificate is self-signed
 * - Validating the root certificate against itself
 *
 * The chain should be ordered from leaf certificate (index 0) to root
 * certificate (index chain_len-1). Each certificate must be signed by
 * the next certificate in the chain.
 *
 * @param ctx Library context (must be initialized)
 * @param cert_chain Array of certificates ordered from leaf to root
 * @param chain_len Number of certificates in the chain (1 <= chain_len <=
 * PICOCERT_MAX_CHAIN_LEN)
 * @return PICOCERT_OK if entire chain is valid, error code otherwise
 */
static picocert_err_t picocert_validate_cert_chain(picocert_context_t* ctx,
                                                   const picocert_t* cert_chain,
                                                   const uint32_t chain_len) {
  if (!ctx || !cert_chain || chain_len == 0) {
    return PICOCERT_ERR_INVALID;
  }

  // Enforce maximum chain length to prevent DoS attacks
  if (chain_len > PICOCERT_MAX_CHAIN_LEN) {
    return PICOCERT_ERR_CHAIN_TOO_LONG;
  }

  // Verify each certificate in the chain
  for (uint32_t i = 0; i < chain_len - 1; i++) {
    const picocert_t* subject = &cert_chain[i];
    const picocert_t* issuer = &cert_chain[i + 1];
    picocert_err_t err = picocert_validate_cert(ctx, issuer, subject);
    if (err != PICOCERT_OK) {
      return err;
    }
  }

  // Ensure the root certificate is self-signed
  const picocert_t* root = &cert_chain[chain_len - 1];
  if (!picocert_is_self_signed(root)) {
    return PICOCERT_ERR_NOT_SELF_SIGNED;
  }
  if (picocert_validate_cert(ctx, root, root) != PICOCERT_OK) {
    return PICOCERT_ERR_SIGNATURE;
  }

  return PICOCERT_OK;
}

/**
 * @brief Verify a signature against a hash using a certificate's public key
 *
 * @param ctx Library context
 * @param cert Certificate containing the public key to use for verification
 * @param hash SHA-256 hash of the data that was signed
 * @param signature ECDSA signature to verify against the hash
 * @return PICOCERT_OK if signature is valid, error code otherwise
 */
static picocert_err_t __attribute__((used)) picocert_verify_hash(
    picocert_context_t* ctx, const picocert_t* cert,
    const uint8_t hash[HASH_SHA256_DIGEST_SIZE],
    const uint8_t signature[ECC_SIG_SIZE]) {
  if (!ctx || !cert || !hash) {
    return PICOCERT_ERR_INVALID;
  }

  if (!ctx->hash_fn || !ctx->ecc_verify_fn) {
    return PICOCERT_ERR_CONTEXT_NOT_INITIALIZED;
  }

  // Verify the signature
  const uint8_t* pubkey;
  size_t pubkey_size;
  picocert_err_t key_err = picocert_cert_to_key(cert, &pubkey, &pubkey_size);
  if (key_err != PICOCERT_OK) {
    return key_err;
  }
  if (!ctx->ecc_verify_fn(pubkey, pubkey_size, hash, HASH_SHA256_DIGEST_SIZE,
                          signature)) {
    return PICOCERT_ERR_SIGNATURE;
  }

  return PICOCERT_OK;
}

/**
 * Verify if a SHA-256 hash has been signed by the public key in the leaf
 * certificate and ensure the certificate chains back to a root certificate.
 *
 * @param ctx Library context
 * @param cert_chain  Pointer to an array of certificates (chain), ending with
 * the root certificate
 * @param chain_len   Length of the certificate chain
 * @param hash        Pointer to the SHA-256 hash of the data to verify
 * @param signature   Pointer to the signature of the hash
 * @return            PICOCERT_OK if verification is successful and the chain is
 * valid, otherwise an error code
 */
static picocert_err_t __attribute__((used)) picocert_verify_hash_and_validate_chain(
    picocert_context_t* ctx, const picocert_t* cert_chain,
    const uint32_t chain_len, const uint8_t hash[HASH_SHA256_DIGEST_SIZE],
    const uint8_t signature[ECC_SIG_SIZE]) {
  if (!ctx || !cert_chain || chain_len == 0 || !hash || !signature) {
    return PICOCERT_ERR_INVALID;
  }

  picocert_err_t err = picocert_validate_cert_chain(ctx, cert_chain, chain_len);
  if (err != PICOCERT_OK) {
    return err;
  }

  // Verify the signature against the hash
  const uint8_t* pubkey;
  size_t pubkey_size;
  picocert_err_t key_err =
      picocert_cert_to_key(&cert_chain[0], &pubkey, &pubkey_size);
  if (key_err != PICOCERT_OK) {
    return key_err;
  }
  if (!ctx->ecc_verify_fn(pubkey, pubkey_size, hash, HASH_SHA256_DIGEST_SIZE,
                          signature)) {
    return PICOCERT_ERR_SIGNATURE;
  }

  return PICOCERT_OK;
}

static void picocert_print_key_bytes(const uint8_t* key,
                                     const size_t key_size) {
  for (size_t i = 0; i < key_size; i++) {
    printf("%02x", key[i]);
    if ((i + 1) % 32 == 0 && i + 1 < key_size) {
      printf("\n  ");
    }
  }
  printf("\n");
}

/**
 * @brief Print the contents of a certificate in a human-readable format.
 *
 * @param cert Pointer to the certificate to print
 */
static void __attribute__((used)) picocert_print_cert(const picocert_t* cert) {
  if (!cert) {
    return;
  }

  printf("Certificate:\n");
  printf("  Version: %u\n", cert->version);
  printf("  Issuer: %.*s\n", PICOCERT_MAX_NAME_LEN, cert->issuer);
  printf("  Subject: %.*s\n", PICOCERT_MAX_NAME_LEN, cert->subject);
  printf("  Valid From: %llu\n",
         (unsigned long long)picocert_get_valid_from(cert));
  printf("  Valid To: %llu\n", (unsigned long long)picocert_get_valid_to(cert));
  printf("  Curve: %u\n", cert->curve);
  printf("  Hash: %u\n", cert->hash);
  printf("  Reserved: %lu\n", (unsigned long)picocert_get_reserved(cert));
  printf("Public Key:\n  ");
  picocert_print_key_bytes(
      cert->public_key + 1,
      sizeof(cert->public_key) -
          1);  // Skip the first byte for uncompressed key format
  printf("Signature:\n  ");
  picocert_print_key_bytes(cert->signature, sizeof(cert->signature));
}
