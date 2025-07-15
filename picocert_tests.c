#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "picocert.h"

// Test framework macros
#define TEST_ASSERT(condition, message)             \
  do {                                              \
    if (!(condition)) {                             \
      printf("FAIL: %s - %s\n", __func__, message); \
      return 0;                                     \
    }                                               \
  } while (0)

#define TEST_PASS()                 \
  do {                              \
    printf("PASS: %s\n", __func__); \
    return 1;                       \
  } while (0)

// Mock time function for testing
static uint64_t mock_current_time = 1000000000;  // Some base time

uint64_t mock_time_callback(void) { return mock_current_time; }

// =============================================================================
// OPENSSL CRYPTO FUNCTIONS
// =============================================================================

bool openssl_sha256_hash(const uint8_t* data, uint32_t data_len,
                         uint8_t* digest, uint32_t digest_len) {
  if (digest_len < HASH_SHA256_DIGEST_SIZE) {
    return false;
  }

  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) {
    return false;
  }

  if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
    EVP_MD_CTX_free(ctx);
    return false;
  }

  if (EVP_DigestUpdate(ctx, data, data_len) != 1) {
    EVP_MD_CTX_free(ctx);
    return false;
  }

  unsigned int digest_len_out;
  if (EVP_DigestFinal_ex(ctx, digest, &digest_len_out) != 1) {
    EVP_MD_CTX_free(ctx);
    return false;
  }

  EVP_MD_CTX_free(ctx);
  return (digest_len_out == HASH_SHA256_DIGEST_SIZE);
}

/**
 * Real ECC signature verification using OpenSSL
 */
bool openssl_ecc_verify(const uint8_t* key, size_t key_size,
                        const uint8_t* hash, uint32_t hash_len,
                        const uint8_t* signature) {
  if (!key || !hash || !signature || hash_len != HASH_SHA256_DIGEST_SIZE) {
    return false;
  }

  if (key_size != ECC_PUBKEY_SIZE_ECDSA_UNCOMPRESSED) {
    return false;
  }

  // Create EC_KEY from public key data
  EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (!ec_key) {
    return false;
  }

  // The public key data is 64 bytes (32 bytes X + 32 bytes Y)
  const uint8_t* pubkey = key;

  BIGNUM* x = BN_bin2bn(pubkey, 32, NULL);
  BIGNUM* y = BN_bin2bn(pubkey + 32, 32, NULL);

  if (!x || !y) {
    EC_KEY_free(ec_key);
    if (x) BN_free(x);
    if (y) BN_free(y);
    return false;
  }

  EC_POINT* point = EC_POINT_new(EC_KEY_get0_group(ec_key));
  if (!point) {
    EC_KEY_free(ec_key);
    BN_free(x);
    BN_free(y);
    return false;
  }

  if (EC_POINT_set_affine_coordinates_GFp(EC_KEY_get0_group(ec_key), point, x,
                                          y, NULL) != 1) {
    EC_KEY_free(ec_key);
    EC_POINT_free(point);
    BN_free(x);
    BN_free(y);
    return false;
  }

  if (EC_KEY_set_public_key(ec_key, point) != 1) {
    EC_KEY_free(ec_key);
    EC_POINT_free(point);
    BN_free(x);
    BN_free(y);
    return false;
  }

  // Parse signature (r, s) from DER format or raw format
  // For simplicity, assume raw format: first 32 bytes r, next 32 bytes s
  ECDSA_SIG* ecdsa_sig = ECDSA_SIG_new();
  if (!ecdsa_sig) {
    EC_KEY_free(ec_key);
    EC_POINT_free(point);
    BN_free(x);
    BN_free(y);
    return false;
  }

  BIGNUM* r = BN_bin2bn(signature, 32, NULL);
  BIGNUM* s = BN_bin2bn(signature + 32, 32, NULL);

  if (!r || !s) {
    ECDSA_SIG_free(ecdsa_sig);
    EC_KEY_free(ec_key);
    EC_POINT_free(point);
    BN_free(x);
    BN_free(y);
    if (r) BN_free(r);
    if (s) BN_free(s);
    return false;
  }

  if (ECDSA_SIG_set0(ecdsa_sig, r, s) != 1) {
    ECDSA_SIG_free(ecdsa_sig);
    EC_KEY_free(ec_key);
    EC_POINT_free(point);
    BN_free(x);
    BN_free(y);
    BN_free(r);
    BN_free(s);
    return false;
  }

  // Verify signature
  int result = ECDSA_do_verify(hash, hash_len, ecdsa_sig, ec_key);

  // Cleanup
  ECDSA_SIG_free(ecdsa_sig);
  EC_KEY_free(ec_key);
  EC_POINT_free(point);
  BN_free(x);
  BN_free(y);

  return (result == 1);
}

// Helper function to initialize picocert context for testing with OpenSSL
picocert_err_t init_picocert_context_for_testing(picocert_context_t* ctx) {
  return picocert_init_context(ctx, openssl_sha256_hash, openssl_ecc_verify,
                               mock_time_callback);
}

// Helper function to create a test certificate
picocert_t create_test_cert(const char* issuer, const char* subject,
                            uint64_t valid_from, uint64_t valid_to) {
  picocert_t cert = {0};

  cert.version = PICOCERT_CURRENT_VERSION;
  strncpy(cert.issuer, issuer, PICOCERT_MAX_NAME_LEN - 1);
  cert.issuer[PICOCERT_MAX_NAME_LEN - 1] = '\0';  // Ensure null termination
  strncpy(cert.subject, subject, PICOCERT_MAX_NAME_LEN - 1);
  cert.subject[PICOCERT_MAX_NAME_LEN - 1] = '\0';  // Ensure null termination
  picocert_set_valid_from(&cert, valid_from);
  picocert_set_valid_to(&cert, valid_to);
  cert.curve = PICOCERT_P256;
  cert.hash = PICOCERT_SHA256;
  picocert_set_reserved(&cert, 0);

  // Generate a real key pair for testing
  EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (ec_key && EC_KEY_generate_key(ec_key) == 1) {
    const EC_POINT* pubkey_point = EC_KEY_get0_public_key(ec_key);
    const EC_GROUP* group = EC_KEY_get0_group(ec_key);

    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();

    if (x && y &&
        EC_POINT_get_affine_coordinates_GFp(group, pubkey_point, x, y, NULL) ==
            1) {
      cert.public_key[0] = 0x04;  // Uncompressed key marker

      // Convert BIGNUMs to binary
      int x_len = BN_num_bytes(x);
      int y_len = BN_num_bytes(y);

      // Pad with zeros if needed
      memset(&cert.public_key[1], 0, 32);
      memset(&cert.public_key[33], 0, 32);

      BN_bn2bin(x, &cert.public_key[1 + (32 - x_len)]);
      BN_bn2bin(y, &cert.public_key[33 + (32 - y_len)]);

      // Create a signature using the private key
      uint8_t cert_data[sizeof(picocert_t) - sizeof(cert.signature)];
      memcpy(cert_data, &cert, sizeof(cert_data));

      uint8_t hash[HASH_SHA256_DIGEST_SIZE];
      if (openssl_sha256_hash(cert_data, sizeof(cert_data), hash,
                              sizeof(hash))) {
        ECDSA_SIG* sig = ECDSA_do_sign(hash, sizeof(hash), ec_key);
        if (sig) {
          const BIGNUM* r = ECDSA_SIG_get0_r(sig);
          const BIGNUM* s = ECDSA_SIG_get0_s(sig);

          // Convert signature to raw format
          memset(cert.signature, 0, sizeof(cert.signature));

          int r_len = BN_num_bytes(r);
          int s_len = BN_num_bytes(s);

          BN_bn2bin(r, &cert.signature[32 - r_len]);
          BN_bn2bin(s, &cert.signature[64 - s_len]);

          ECDSA_SIG_free(sig);
        }
      }
    }

    if (x) BN_free(x);
    if (y) BN_free(y);
  }

  if (ec_key) {
    EC_KEY_free(ec_key);
  }

  return cert;
}

// Helper structure to hold a certificate with its private key
typedef struct {
  picocert_t cert;
  EC_KEY* private_key;
} cert_with_key_t;

// Create a certificate with a real key pair that can be signed by another
// cert's private key
cert_with_key_t create_cert_with_key(const char* issuer, const char* subject,
                                     uint64_t valid_from, uint64_t valid_to,
                                     EC_KEY* issuer_private_key) {
  cert_with_key_t cert_with_key = {0};
  picocert_t* cert = &cert_with_key.cert;

  cert->version = PICOCERT_CURRENT_VERSION;
  strncpy(cert->issuer, issuer, PICOCERT_MAX_NAME_LEN - 1);
  cert->issuer[PICOCERT_MAX_NAME_LEN - 1] = '\0';
  strncpy(cert->subject, subject, PICOCERT_MAX_NAME_LEN - 1);
  cert->subject[PICOCERT_MAX_NAME_LEN - 1] = '\0';
  picocert_set_valid_from(cert, valid_from);
  picocert_set_valid_to(cert, valid_to);
  cert->curve = PICOCERT_P256;
  cert->hash = PICOCERT_SHA256;
  picocert_set_reserved(cert, 0);

  // Generate a new key pair for this certificate
  EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (!ec_key || EC_KEY_generate_key(ec_key) != 1) {
    if (ec_key) EC_KEY_free(ec_key);
    return cert_with_key;  // Return empty cert on error
  }

  cert_with_key.private_key = ec_key;

  // Set the public key in the certificate
  const EC_POINT* pubkey_point = EC_KEY_get0_public_key(ec_key);
  const EC_GROUP* group = EC_KEY_get0_group(ec_key);

  BIGNUM* x = BN_new();
  BIGNUM* y = BN_new();

  if (x && y &&
      EC_POINT_get_affine_coordinates_GFp(group, pubkey_point, x, y, NULL) ==
          1) {
    cert->public_key[0] = 0x04;  // Uncompressed key marker

    // Convert BIGNUMs to binary
    int x_len = BN_num_bytes(x);
    int y_len = BN_num_bytes(y);

    // Pad with zeros if needed
    memset(&cert->public_key[1], 0, 32);
    memset(&cert->public_key[33], 0, 32);

    BN_bn2bin(x, &cert->public_key[1 + (32 - x_len)]);
    BN_bn2bin(y, &cert->public_key[33 + (32 - y_len)]);

    // Create certificate data to be signed (everything except signature)
    uint8_t cert_data[sizeof(picocert_t) - sizeof(cert->signature)];
    memcpy(cert_data, cert, sizeof(cert_data));

    // Hash the certificate data
    uint8_t hash[HASH_SHA256_DIGEST_SIZE];
    if (openssl_sha256_hash(cert_data, sizeof(cert_data), hash, sizeof(hash))) {
      // Sign with the issuer's private key (or own key if self-signed)
      EC_KEY* signing_key = issuer_private_key ? issuer_private_key : ec_key;
      ECDSA_SIG* sig = ECDSA_do_sign(hash, sizeof(hash), signing_key);
      if (sig) {
        const BIGNUM* r = ECDSA_SIG_get0_r(sig);
        const BIGNUM* s = ECDSA_SIG_get0_s(sig);

        // Convert signature to raw format
        memset(cert->signature, 0, sizeof(cert->signature));

        int r_len = BN_num_bytes(r);
        int s_len = BN_num_bytes(s);

        BN_bn2bin(r, &cert->signature[32 - r_len]);
        BN_bn2bin(s, &cert->signature[64 - s_len]);

        ECDSA_SIG_free(sig);
      }
    }
  }

  if (x) BN_free(x);
  if (y) BN_free(y);

  return cert_with_key;
}

// Clean up cert_with_key_t structure
void cleanup_cert_with_key(cert_with_key_t* cert_with_key) {
  if (cert_with_key && cert_with_key->private_key) {
    EC_KEY_free(cert_with_key->private_key);
    cert_with_key->private_key = NULL;
  }
}

// Test proper 3-tier PKI validation with real certificates
int test_3tier_pki_validation(void) {
  picocert_context_t ctx = {0};
  init_picocert_context_for_testing(&ctx);

  printf("\n=== 3-Tier PKI Validation Test ===\n");

  // Create root CA (self-signed)
  cert_with_key_t root_ca =
      create_cert_with_key("RootCA", "RootCA", mock_current_time - 1000,
                           mock_current_time + 10000, NULL);

  TEST_ASSERT(root_ca.private_key != NULL, "Root CA should have private key");
  TEST_ASSERT(picocert_is_self_signed(&root_ca.cert),
              "Root CA should be self-signed");

  printf("Created Root CA: %s\n", root_ca.cert.subject);

  // Create intermediate CA signed by root CA
  cert_with_key_t intermediate_ca =
      create_cert_with_key("RootCA", "IntermediateCA", mock_current_time - 500,
                           mock_current_time + 8000, root_ca.private_key);

  TEST_ASSERT(intermediate_ca.private_key != NULL,
              "Intermediate CA should have private key");
  TEST_ASSERT(!picocert_is_self_signed(&intermediate_ca.cert),
              "Intermediate CA should not be self-signed");

  printf("Created Intermediate CA: %s (signed by %s)\n",
         intermediate_ca.cert.subject, intermediate_ca.cert.issuer);

  // Create leaf certificate signed by intermediate CA
  cert_with_key_t leaf_cert = create_cert_with_key(
      "IntermediateCA", "LeafCert", mock_current_time - 100,
      mock_current_time + 5000, intermediate_ca.private_key);

  TEST_ASSERT(leaf_cert.private_key != NULL,
              "Leaf cert should have private key");
  TEST_ASSERT(!picocert_is_self_signed(&leaf_cert.cert),
              "Leaf cert should not be self-signed");

  printf("Created Leaf Certificate: %s (signed by %s)\n",
         leaf_cert.cert.subject, leaf_cert.cert.issuer);

  // Test individual certificate validations
  printf("\n--- Individual Certificate Validations ---\n");

  // Validate root CA (self-signed)
  picocert_err_t err =
      picocert_validate_cert(&ctx, &root_ca.cert, &root_ca.cert);
  TEST_ASSERT(err == PICOCERT_OK, "Root CA self-validation should succeed");
  printf("✓ Root CA self-validation passed\n");

  // Validate intermediate CA against root CA
  err = picocert_validate_cert(&ctx, &root_ca.cert, &intermediate_ca.cert);
  TEST_ASSERT(err == PICOCERT_OK,
              "Intermediate CA validation against root should succeed");
  printf("✓ Intermediate CA validation against root passed\n");

  // Validate leaf cert against intermediate CA
  err = picocert_validate_cert(&ctx, &intermediate_ca.cert, &leaf_cert.cert);
  TEST_ASSERT(err == PICOCERT_OK,
              "Leaf cert validation against intermediate should succeed");
  printf("✓ Leaf cert validation against intermediate passed\n");

  // Test full certificate chain validation
  printf("\n--- Full Certificate Chain Validation ---\n");

  picocert_t cert_chain[3] = {leaf_cert.cert, intermediate_ca.cert,
                              root_ca.cert};
  err = picocert_validate_cert_chain(&ctx, cert_chain, 3);
  TEST_ASSERT(err == PICOCERT_OK,
              "Full 3-tier certificate chain validation should succeed");
  printf("✓ Full 3-tier certificate chain validation passed\n");

  // Test data signing and verification with the leaf certificate
  printf("\n--- Data Signing and Verification ---\n");

  const char* test_data =
      "This is important data signed by the leaf certificate";
  uint32_t data_len = strlen(test_data);

  // Hash the data
  uint8_t data_hash[HASH_SHA256_DIGEST_SIZE];
  TEST_ASSERT(openssl_sha256_hash((const uint8_t*)test_data, data_len,
                                  data_hash, sizeof(data_hash)),
              "Data hashing should succeed");

  // Sign the hash with the leaf certificate's private key
  ECDSA_SIG* sig =
      ECDSA_do_sign(data_hash, sizeof(data_hash), leaf_cert.private_key);
  TEST_ASSERT(sig != NULL, "Data signing should succeed");

  // Convert signature to raw format
  uint8_t signature[ECC_SIG_SIZE] = {0};
  const BIGNUM* r = ECDSA_SIG_get0_r(sig);
  const BIGNUM* s = ECDSA_SIG_get0_s(sig);

  int r_len = BN_num_bytes(r);
  int s_len = BN_num_bytes(s);

  BN_bn2bin(r, &signature[32 - r_len]);
  BN_bn2bin(s, &signature[64 - s_len]);

  ECDSA_SIG_free(sig);

  printf("✓ Data signed with leaf certificate's private key\n");

  // Verify the signature using the leaf certificate's public key
  err = picocert_verify_hash(&ctx, &leaf_cert.cert, data_hash, signature);
  TEST_ASSERT(err == PICOCERT_OK,
              "Signature verification with leaf cert should succeed");
  printf("✓ Signature verification with leaf certificate passed\n");

  // Test full end-to-end verification: validate chain + verify data
  err = picocert_verify_hash_and_validate_chain(&ctx, cert_chain, 3, data_hash,
                                                signature);
  TEST_ASSERT(err == PICOCERT_OK,
              "Full end-to-end verification should succeed");
  printf("✓ Full end-to-end verification (chain + data) passed\n");

  // Test the hash-based data verification API with certificate chain validation
  err = picocert_verify_hash_and_validate_chain(&ctx, cert_chain, 3, data_hash,
                                                signature);
  TEST_ASSERT(err == PICOCERT_OK,
              "Full data verification with chain should succeed");
  printf("✓ Full data verification with chain passed\n");

  // Test negative cases
  printf("\n--- Negative Test Cases ---\n");

  // Test with tampered data
  const char* tampered_data =
      "This is TAMPERED data signed by the leaf certificate";
  uint32_t tampered_len = strlen(tampered_data);

  // Hash the tampered data
  uint8_t tampered_hash[HASH_SHA256_DIGEST_SIZE];
  TEST_ASSERT(openssl_sha256_hash((const uint8_t*)tampered_data, tampered_len,
                                  tampered_hash, sizeof(tampered_hash)),
              "Tampered data hashing should succeed");

  // Try to verify with original signature (should fail)
  err = picocert_verify_hash_and_validate_chain(&ctx, cert_chain, 3,
                                                tampered_hash, signature);
  TEST_ASSERT(err == PICOCERT_ERR_SIGNATURE,
              "Tampered data should fail verification");
  printf("✓ Tampered data correctly rejected\n");

  // Test with wrong certificate order
  picocert_t wrong_order_chain[3] = {root_ca.cert, intermediate_ca.cert,
                                     leaf_cert.cert};
  err = picocert_validate_cert_chain(&ctx, wrong_order_chain, 3);
  TEST_ASSERT(err != PICOCERT_OK,
              "Wrong certificate order should fail validation");
  printf("✓ Wrong certificate order correctly rejected\n");

  // Test with missing intermediate certificate
  picocert_t incomplete_chain[2] = {leaf_cert.cert, root_ca.cert};
  err = picocert_validate_cert_chain(&ctx, incomplete_chain, 2);
  TEST_ASSERT(err != PICOCERT_OK,
              "Incomplete certificate chain should fail validation");
  printf("✓ Incomplete certificate chain correctly rejected\n");

  // Clean up
  cleanup_cert_with_key(&root_ca);
  cleanup_cert_with_key(&intermediate_ca);
  cleanup_cert_with_key(&leaf_cert);

  printf("=== End 3-Tier PKI Validation Test ===\n\n");

  TEST_PASS();
}

// =============================================================================
// TESTS
// =============================================================================

// Test library initialization
int test_library_initialization(void) {
  picocert_context_t ctx = {0};

  // Test with invalid parameters - NULL context
  picocert_err_t err = picocert_init_context(
      NULL, openssl_sha256_hash, openssl_ecc_verify, mock_time_callback);
  TEST_ASSERT(err == PICOCERT_ERR_INVALID, "Should fail with NULL context");

  // Test with invalid parameters - NULL hash function
  err =
      picocert_init_context(&ctx, NULL, openssl_ecc_verify, mock_time_callback);
  TEST_ASSERT(err == PICOCERT_ERR_INVALID,
              "Should fail with NULL hash function");

  // Test with invalid parameters - NULL ECC verify function
  err = picocert_init_context(&ctx, openssl_sha256_hash, NULL,
                              mock_time_callback);
  TEST_ASSERT(err == PICOCERT_ERR_INVALID,
              "Should fail with NULL ECC verify function");

  // Test with valid parameters
  err = picocert_init_context(&ctx, openssl_sha256_hash, openssl_ecc_verify,
                              mock_time_callback);
  TEST_ASSERT(err == PICOCERT_OK, "Should succeed with valid parameters");

  // Test time callback can be NULL
  err = picocert_init_context(&ctx, openssl_sha256_hash, openssl_ecc_verify,
                              NULL);
  TEST_ASSERT(err == PICOCERT_OK, "Should succeed with NULL time callback");

  TEST_PASS();
}

// Test key extraction from certificate
int test_key_extraction(void) {
  picocert_t cert = create_test_cert(
      "TestIssuer", "TestSubject", mock_current_time, mock_current_time + 3600);

  // Test successful key extraction
  const uint8_t* key;
  size_t key_size;
  picocert_err_t err = picocert_cert_to_key(&cert, &key, &key_size);
  TEST_ASSERT(err == PICOCERT_OK, "Should successfully extract key");
  TEST_ASSERT(key != NULL, "Key pointer should not be NULL");
  TEST_ASSERT(key_size == ECC_PUBKEY_SIZE_ECDSA_UNCOMPRESSED,
              "Key size should be correct");
  TEST_ASSERT(key == &cert.public_key[1],
              "Key should point to correct location");

  // Test with NULL certificate
  err = picocert_cert_to_key(NULL, &key, &key_size);
  TEST_ASSERT(err == PICOCERT_ERR_INVALID, "Should fail with NULL cert");

  // Test with NULL key_out
  err = picocert_cert_to_key(&cert, NULL, &key_size);
  TEST_ASSERT(err == PICOCERT_ERR_INVALID, "Should fail with NULL key_out");

  // Test with NULL key_size_out
  err = picocert_cert_to_key(&cert, &key, NULL);
  TEST_ASSERT(err == PICOCERT_ERR_INVALID,
              "Should fail with NULL key_size_out");

  // Test with invalid public key format (not starting with 0x04)
  picocert_t invalid_cert = cert;
  invalid_cert.public_key[0] = 0x03;  // compressed format
  err = picocert_cert_to_key(&invalid_cert, &key, &key_size);
  TEST_ASSERT(err == PICOCERT_ERR_INVALID_FORMAT,
              "Should fail with invalid key format");

  TEST_PASS();
}

// Test basic certificate structure
int test_certificate_structure(void) {
  picocert_context_t ctx = {0};
  init_picocert_context_for_testing(&ctx);

  picocert_t cert = create_test_cert(
      "TestIssuer", "TestSubject", mock_current_time, mock_current_time + 3600);

  TEST_ASSERT(cert.version == PICOCERT_CURRENT_VERSION,
              "Version should be current");
  TEST_ASSERT(strcmp(cert.issuer, "TestIssuer") == 0, "Issuer should match");
  TEST_ASSERT(strcmp(cert.subject, "TestSubject") == 0, "Subject should match");
  TEST_ASSERT(cert.curve == PICOCERT_P256, "Curve should be P256");
  TEST_ASSERT(cert.hash == PICOCERT_SHA256, "Hash should be SHA256");
  TEST_ASSERT(picocert_get_reserved(&cert) == 0,
              "Reserved field should be zero");
  TEST_ASSERT(cert.public_key[0] == 0x04, "Public key should start with 0x04");

  TEST_PASS();
}

// Test self-signed certificate detection
int test_self_signed_detection(void) {
  picocert_context_t ctx = {0};
  init_picocert_context_for_testing(&ctx);

  picocert_t self_signed = create_test_cert(
      "SelfSigned", "SelfSigned", mock_current_time, mock_current_time + 3600);
  picocert_t not_self_signed = create_test_cert(
      "Issuer", "Subject", mock_current_time, mock_current_time + 3600);

  TEST_ASSERT(picocert_is_self_signed(&self_signed),
              "Should detect self-signed cert");
  TEST_ASSERT(!picocert_is_self_signed(&not_self_signed),
              "Should detect non-self-signed cert");

  TEST_PASS();
}

// Test time callback functionality
int test_time_callback(void) {
  picocert_context_t ctx = {0};

  // Test without initialized context
  uint64_t time1;
  picocert_err_t err = picocert_current_time(NULL, &time1);
  TEST_ASSERT(err == PICOCERT_ERR_INVALID, "Should fail with NULL context");

  // Test with uninitialized context
  uint64_t time2;
  err = picocert_current_time(&ctx, &time2);
  TEST_ASSERT(err == PICOCERT_ERR_INVALID, "Should fail when no callback set");

  // Test with callback
  init_picocert_context_for_testing(&ctx);
  uint64_t time3;
  err = picocert_current_time(&ctx, &time3);
  TEST_ASSERT(err == PICOCERT_OK, "Should succeed with callback");
  TEST_ASSERT(time3 == mock_current_time, "Should return callback time");

  // Test initialization with NULL time callback
  picocert_context_t ctx_no_time = {0};
  err = picocert_init_context(&ctx_no_time, openssl_sha256_hash,
                              openssl_ecc_verify, NULL);
  TEST_ASSERT(err == PICOCERT_OK, "Should initialize without time callback");

  uint64_t time4;
  err = picocert_current_time(&ctx_no_time, &time4);
  TEST_ASSERT(err == PICOCERT_ERR_INVALID,
              "Should fail when NULL callback was set during init");

  // Test initialization with valid time callback
  picocert_context_t ctx_with_time = {0};
  err = picocert_init_context(&ctx_with_time, openssl_sha256_hash,
                              openssl_ecc_verify, mock_time_callback);
  TEST_ASSERT(err == PICOCERT_OK, "Should initialize with time callback");

  uint64_t time5;
  err = picocert_current_time(&ctx_with_time, &time5);
  TEST_ASSERT(err == PICOCERT_OK, "Should succeed with valid callback");
  TEST_ASSERT(time5 == mock_current_time, "Should return callback time");

  TEST_PASS();
}

// Test certificate validation with time
int test_certificate_time_validation(void) {
  picocert_context_t ctx = {0};
  init_picocert_context_for_testing(&ctx);

  // Create valid certificate
  picocert_t valid_cert = create_test_cert(
      "Root", "Root", mock_current_time - 1000, mock_current_time + 1000);

  // Create expired certificate
  picocert_t expired_cert = create_test_cert(
      "Root", "Root", mock_current_time - 2000, mock_current_time - 1000);

  // Create not-yet-valid certificate
  picocert_t future_cert = create_test_cert(
      "Root", "Root", mock_current_time + 1000, mock_current_time + 2000);

  // Test validation without time callback should fail
  picocert_context_t ctx_no_time = {0};
  picocert_err_t err = picocert_init_context(&ctx_no_time, openssl_sha256_hash,
                                             openssl_ecc_verify, NULL);
  TEST_ASSERT(err == PICOCERT_OK, "Should initialize without time callback");

  err = picocert_validate_cert(&ctx_no_time, &valid_cert, &valid_cert);
  TEST_ASSERT(err == PICOCERT_ERR_INVALID,
              "Should fail validation without time callback");

  // Test validation with time callback
  picocert_err_t err1 = picocert_validate_cert(&ctx, &valid_cert, &valid_cert);
  TEST_ASSERT(err1 == PICOCERT_OK, "Valid certificate should pass validation");

  picocert_err_t err2 =
      picocert_validate_cert(&ctx, &expired_cert, &expired_cert);
  TEST_ASSERT(err2 == PICOCERT_ERR_EXPIRED,
              "Expired certificate should fail validation");

  picocert_err_t err3 =
      picocert_validate_cert(&ctx, &future_cert, &future_cert);
  TEST_ASSERT(err3 == PICOCERT_ERR_EXPIRED,
              "Future certificate should fail validation");

  TEST_PASS();
}

// Test hash verification
int test_hash_verification(void) {
  picocert_context_t ctx = {0};
  init_picocert_context_for_testing(&ctx);

  picocert_t cert =
      create_test_cert("TestCert", "TestCert", mock_current_time - 1000,
                       mock_current_time + 1000);

  uint8_t test_hash[HASH_SHA256_DIGEST_SIZE] = {0};
  for (int i = 0; i < HASH_SHA256_DIGEST_SIZE; i++) {
    test_hash[i] = (uint8_t)(i + 0x30);
  }

  uint8_t test_signature[ECC_SIG_SIZE] = {0};
  for (int i = 0; i < ECC_SIG_SIZE; i++) {
    test_signature[i] = (uint8_t)(i + 0x40);
  }

  // Test hash verification (will fail with dummy data, but tests the API)
  picocert_err_t err =
      picocert_verify_hash(&ctx, &cert, test_hash, test_signature);
  TEST_ASSERT(err == PICOCERT_ERR_SIGNATURE,
              "Hash verification should fail with dummy data");

  // Test with NULL context
  err = picocert_verify_hash(NULL, &cert, test_hash, test_signature);
  TEST_ASSERT(err == PICOCERT_ERR_INVALID, "NULL context should fail");

  // Test with NULL certificate
  err = picocert_verify_hash(&ctx, NULL, test_hash, test_signature);
  TEST_ASSERT(err == PICOCERT_ERR_INVALID, "NULL certificate should fail");

  // Test with NULL hash
  err = picocert_verify_hash(&ctx, &cert, NULL, test_signature);
  TEST_ASSERT(err == PICOCERT_ERR_INVALID, "NULL hash should fail");

  TEST_PASS();
}

// Test data verification
int test_data_verification(void) {
  picocert_context_t ctx = {0};
  init_picocert_context_for_testing(&ctx);

  picocert_t cert =
      create_test_cert("TestCert", "TestCert", mock_current_time - 1000,
                       mock_current_time + 1000);

  uint8_t test_hash[HASH_SHA256_DIGEST_SIZE] = {0};
  uint8_t test_signature[ECC_SIG_SIZE] = {0};

  // Test hash verification (will fail with random signature, but tests the API)
  picocert_err_t err =
      picocert_verify_hash(&ctx, &cert, test_hash, test_signature);
  TEST_ASSERT(err == PICOCERT_ERR_SIGNATURE,
              "Hash verification should fail with random signature");

  // Test with NULL context
  err = picocert_verify_hash(NULL, &cert, test_hash, test_signature);
  TEST_ASSERT(err == PICOCERT_ERR_INVALID, "NULL context should fail");

  // Test with NULL hash
  err = picocert_verify_hash(&ctx, &cert, NULL, test_signature);
  TEST_ASSERT(err == PICOCERT_ERR_INVALID, "NULL hash should fail");

  // Test with NULL certificate
  err = picocert_verify_hash(&ctx, NULL, test_hash, test_signature);
  TEST_ASSERT(err == PICOCERT_ERR_INVALID, "NULL certificate should fail");

  TEST_PASS();
}

// Test certificate chain validation
int test_certificate_chain_validation(void) {
  picocert_context_t ctx = {0};
  init_picocert_context_for_testing(&ctx);

  // Create a simple 2-certificate chain
  picocert_t root = create_test_cert("Root", "Root", mock_current_time - 1000,
                                     mock_current_time + 1000);

  picocert_t leaf = create_test_cert("Root", "Leaf", mock_current_time - 500,
                                     mock_current_time + 500);

  picocert_t chain[2] = {leaf, root};

  // Test chain validation (will fail with mismatched keys, but tests the API)
  picocert_err_t err = picocert_validate_cert_chain(&ctx, chain, 2);
  TEST_ASSERT(err == PICOCERT_ERR_SIGNATURE,
              "Chain validation should fail with mismatched keys");

  // Test with NULL context
  err = picocert_validate_cert_chain(NULL, chain, 2);
  TEST_ASSERT(err == PICOCERT_ERR_INVALID, "NULL context should fail");

  // Test with NULL chain
  err = picocert_validate_cert_chain(&ctx, NULL, 2);
  TEST_ASSERT(err == PICOCERT_ERR_INVALID, "NULL chain should fail");

  // Test with zero length
  err = picocert_validate_cert_chain(&ctx, chain, 0);
  TEST_ASSERT(err == PICOCERT_ERR_INVALID, "Zero length chain should fail");

  TEST_PASS();
}

// Test certificate version validation
int test_version_validation(void) {
  picocert_context_t ctx = {0};
  init_picocert_context_for_testing(&ctx);

  picocert_t cert = create_test_cert("Root", "Root", mock_current_time - 1000,
                                     mock_current_time + 1000);

  // Test with invalid version
  cert.version = 99;
  picocert_err_t err = picocert_validate_cert(&ctx, &cert, &cert);
  TEST_ASSERT(err == PICOCERT_ERR_VERSION, "Invalid version should fail");

  // Test with valid version
  cert.version = PICOCERT_CURRENT_VERSION;
  err = picocert_validate_cert(&ctx, &cert, &cert);
  TEST_ASSERT(err == PICOCERT_OK, "Valid version should pass");

  TEST_PASS();
}

// Test reserved field validation
int test_reserved_field_validation(void) {
  picocert_context_t ctx = {0};
  init_picocert_context_for_testing(&ctx);

  picocert_t cert = create_test_cert("Root", "Root", mock_current_time - 1000,
                                     mock_current_time + 1000);

  // Test with non-zero reserved field
  picocert_set_reserved(&cert, 1);
  picocert_err_t err = picocert_validate_cert(&ctx, &cert, &cert);
  TEST_ASSERT(err == PICOCERT_ERR_RESERVED,
              "Non-zero reserved field should fail");

  // Test with zero reserved field
  picocert_set_reserved(&cert, 0);
  err = picocert_validate_cert(&ctx, &cert, &cert);
  TEST_ASSERT(err == PICOCERT_OK, "Zero reserved field should pass");

  TEST_PASS();
}

// Test uninitialized library behavior
int test_uninitialized_library(void) {
  picocert_context_t ctx = {0};  // Uninitialized context

  // Try to use functions without proper initialization
  picocert_t cert = create_test_cert("Test", "Test", mock_current_time - 1000,
                                     mock_current_time + 1000);

  uint8_t test_hash[HASH_SHA256_DIGEST_SIZE] = {0};
  uint8_t test_signature[ECC_SIG_SIZE] = {0};

  // These should fail because context is not initialized
  picocert_err_t err =
      picocert_verify_hash(&ctx, &cert, test_hash, test_signature);
  TEST_ASSERT(err == PICOCERT_ERR_CONTEXT_NOT_INITIALIZED,
              "Should fail when not initialized");

  // Test certificate signature verification with uninitialized context
  err = picocert_verify_cert_signature(&ctx, &cert, &cert);
  TEST_ASSERT(err == PICOCERT_ERR_CONTEXT_NOT_INITIALIZED,
              "Should fail when not initialized");

  TEST_PASS();
}

// Test public key format validation
int test_public_key_format_validation(void) {
  picocert_context_t ctx = {0};
  init_picocert_context_for_testing(&ctx);

  picocert_t cert =
      create_test_cert("TestCert", "TestCert", mock_current_time - 1000,
                       mock_current_time + 1000);

  // Test with valid uncompressed format (0x04)
  const uint8_t* key;
  size_t key_size;
  picocert_err_t err = picocert_cert_to_key(&cert, &key, &key_size);
  TEST_ASSERT(err == PICOCERT_OK, "Valid uncompressed key should succeed");

  // Test with compressed format (0x02) - should fail
  cert.public_key[0] = 0x02;
  err = picocert_cert_to_key(&cert, &key, &key_size);
  TEST_ASSERT(err == PICOCERT_ERR_INVALID_FORMAT,
              "Compressed key format should fail");

  // Test with compressed format (0x03) - should fail
  cert.public_key[0] = 0x03;
  err = picocert_cert_to_key(&cert, &key, &key_size);
  TEST_ASSERT(err == PICOCERT_ERR_INVALID_FORMAT,
              "Compressed key format should fail");

  // Test with invalid format (0x01) - should fail
  cert.public_key[0] = 0x01;
  err = picocert_cert_to_key(&cert, &key, &key_size);
  TEST_ASSERT(err == PICOCERT_ERR_INVALID_FORMAT,
              "Invalid key format should fail");

  // Test with NULL certificate
  err = picocert_cert_to_key(NULL, &key, &key_size);
  TEST_ASSERT(err == PICOCERT_ERR_INVALID, "NULL certificate should fail");

  // Test with NULL output parameter for key data
  cert.public_key[0] = 0x04;  // Reset to valid format
  err = picocert_cert_to_key(&cert, NULL, &key_size);
  TEST_ASSERT(err == PICOCERT_ERR_INVALID, "NULL key output should fail");

  // Test with NULL output parameter for key size
  err = picocert_cert_to_key(&cert, &key, NULL);
  TEST_ASSERT(err == PICOCERT_ERR_INVALID, "NULL key_size output should fail");

  TEST_PASS();
}

// Test enum field validation
int test_enum_field_validation(void) {
  picocert_context_t ctx = {0};
  init_picocert_context_for_testing(&ctx);

  picocert_t cert = create_test_cert("Root", "Root", mock_current_time - 1000,
                                     mock_current_time + 1000);

  // Test with valid curve and hash
  picocert_err_t err = picocert_validate_cert(&ctx, &cert, &cert);
  TEST_ASSERT(err == PICOCERT_OK, "Valid curve and hash should pass");

  // Test with invalid curve value
  uint8_t original_curve = cert.curve;
  cert.curve = 99;  // Invalid curve value
  err = picocert_validate_cert(&ctx, &cert, &cert);
  TEST_ASSERT(err == PICOCERT_ERR_UNSUPPORTED_CURVE,
              "Invalid curve should fail");

  // Test issuer with invalid curve
  cert.curve = original_curve;  // Reset subject curve
  picocert_t issuer_bad_curve = cert;
  issuer_bad_curve.curve = 88;  // Invalid curve value
  err = picocert_validate_cert(&ctx, &issuer_bad_curve, &cert);
  TEST_ASSERT(err == PICOCERT_ERR_UNSUPPORTED_CURVE,
              "Issuer with invalid curve should fail");

  // Test with invalid hash value
  uint8_t original_hash = cert.hash;
  cert.hash = 77;  // Invalid hash value
  err = picocert_validate_cert(&ctx, &cert, &cert);
  TEST_ASSERT(err == PICOCERT_ERR_UNSUPPORTED_HASH, "Invalid hash should fail");

  // Test issuer with invalid hash
  cert.hash = original_hash;  // Reset subject hash
  picocert_t issuer_bad_hash = cert;
  issuer_bad_hash.hash = 66;  // Invalid hash value
  err = picocert_validate_cert(&ctx, &issuer_bad_hash, &cert);
  TEST_ASSERT(err == PICOCERT_ERR_UNSUPPORTED_HASH,
              "Issuer with invalid hash should fail");

  // Verify valid values still work after tests
  err = picocert_validate_cert(&ctx, &cert, &cert);
  TEST_ASSERT(err == PICOCERT_OK,
              "Valid certificate should still pass after tests");

  TEST_PASS();
}

// Test certificate chain length limits
int test_chain_length_limits(void) {
  picocert_context_t ctx = {0};
  init_picocert_context_for_testing(&ctx);

  // Test with valid chain length (within limit)
  picocert_t valid_chain[3] = {
      create_test_cert("Intermediate", "Leaf", mock_current_time - 500,
                       mock_current_time + 500),
      create_test_cert("Root", "Intermediate", mock_current_time - 1000,
                       mock_current_time + 1000),
      create_test_cert("Root", "Root", mock_current_time - 1000,
                       mock_current_time + 1000)};

  picocert_err_t err = picocert_validate_cert_chain(&ctx, valid_chain, 3);
  // Note: This will fail due to signature mismatch, but that's after the length
  // check
  TEST_ASSERT(err != PICOCERT_ERR_INVALID || err == PICOCERT_ERR_SIGNATURE,
              "Valid chain length should pass length check");

  // Test with maximum allowed chain length
  picocert_t max_chain[PICOCERT_MAX_CHAIN_LEN];
  for (int i = 0; i < PICOCERT_MAX_CHAIN_LEN; i++) {
    max_chain[i] = create_test_cert("Test", "Test", mock_current_time - 1000,
                                    mock_current_time + 1000);
  }

  err = picocert_validate_cert_chain(&ctx, max_chain, PICOCERT_MAX_CHAIN_LEN);
  // Should pass the length check (may fail later for other reasons)
  TEST_ASSERT(err != PICOCERT_ERR_INVALID || err == PICOCERT_ERR_SIGNATURE,
              "Maximum chain length should pass length check");

  // Test with chain length exceeding the limit
  picocert_t oversized_chain[PICOCERT_MAX_CHAIN_LEN + 1];
  for (int i = 0; i < PICOCERT_MAX_CHAIN_LEN + 1; i++) {
    oversized_chain[i] = create_test_cert(
        "Test", "Test", mock_current_time - 1000, mock_current_time + 1000);
  }

  err = picocert_validate_cert_chain(&ctx, oversized_chain,
                                     PICOCERT_MAX_CHAIN_LEN + 1);
  TEST_ASSERT(
      err == PICOCERT_ERR_CHAIN_TOO_LONG,
      "Oversized chain should be rejected with PICOCERT_ERR_CHAIN_TOO_LONG");

  // Test with zero length (edge case)
  err = picocert_validate_cert_chain(&ctx, valid_chain, 0);
  TEST_ASSERT(err == PICOCERT_ERR_INVALID,
              "Zero length chain should be rejected");

  TEST_PASS();
}

// Test validity period consistency check
int test_validity_period_consistency(void) {
  picocert_context_t ctx = {0};
  init_picocert_context_for_testing(&ctx);

  // Create a certificate with invalid validity period (valid_from > valid_to)
  picocert_t cert =
      create_test_cert("Root", "Root", mock_current_time + 1000,
                       mock_current_time - 1000);  // Invalid: start > end

  // Test should fail with invalid validity period
  picocert_err_t err = picocert_validate_cert(&ctx, &cert, &cert);
  TEST_ASSERT(err == PICOCERT_ERR_INVALID_VALIDITY_PERIOD,
              "Certificate with invalid validity period should fail");

  // Test with valid validity period
  cert = create_test_cert("Root", "Root", mock_current_time - 1000,
                          mock_current_time + 1000);  // Valid: start < end
  err = picocert_validate_cert(&ctx, &cert, &cert);
  TEST_ASSERT(err == PICOCERT_OK,
              "Certificate with valid validity period should pass");

  // Test with equal validity period (edge case: start == end)
  cert = create_test_cert("Root", "Root", mock_current_time,
                          mock_current_time);  // Valid: start == end
  err = picocert_validate_cert(&ctx, &cert, &cert);
  TEST_ASSERT(err == PICOCERT_OK,
              "Certificate with equal validity period should pass");

  // Test with issuer having invalid validity period
  picocert_t issuer =
      create_test_cert("Issuer", "Issuer", mock_current_time + 1000,
                       mock_current_time - 1000);  // Invalid: start > end
  picocert_t subject =
      create_test_cert("Issuer", "Subject", mock_current_time - 500,
                       mock_current_time + 500);  // Valid validity period

  err = picocert_validate_cert(&ctx, &issuer, &subject);
  TEST_ASSERT(err == PICOCERT_ERR_INVALID_VALIDITY_PERIOD,
              "Issuer with invalid validity period should fail");

  TEST_PASS();
}

// Test string handling
int test_string_handling(void) {
  picocert_context_t ctx = {0};
  init_picocert_context_for_testing(&ctx);

  // Test 1: Short strings (should work normally)
  picocert_t cert1 = create_test_cert("Short", "Name", mock_current_time - 1000,
                                      mock_current_time + 1000);
  TEST_ASSERT(strlen(cert1.issuer) == 5, "Short issuer should be 5 chars");
  TEST_ASSERT(strlen(cert1.subject) == 4, "Short subject should be 4 chars");
  TEST_ASSERT(cert1.issuer[strlen(cert1.issuer) + 1] == 0,
              "Memory after short issuer should be zeroed");

  // Test 2: Strings exactly at max length (31 chars + null terminator)
  char max_len_string[PICOCERT_MAX_NAME_LEN];
  memset(max_len_string, 'A', PICOCERT_MAX_NAME_LEN - 1);
  max_len_string[PICOCERT_MAX_NAME_LEN - 1] = '\0';

  picocert_t cert2 =
      create_test_cert(max_len_string, max_len_string, mock_current_time - 1000,
                       mock_current_time + 1000);
  TEST_ASSERT(strlen(cert2.issuer) == PICOCERT_MAX_NAME_LEN - 1,
              "Max length issuer should be exactly max-1");
  TEST_ASSERT(strlen(cert2.subject) == PICOCERT_MAX_NAME_LEN - 1,
              "Max length subject should be exactly max-1");
  TEST_ASSERT(cert2.issuer[PICOCERT_MAX_NAME_LEN - 1] == '\0',
              "Max length issuer should be null-terminated");
  TEST_ASSERT(cert2.subject[PICOCERT_MAX_NAME_LEN - 1] == '\0',
              "Max length subject should be null-terminated");

  // Test 3: Strings longer than max length (should be truncated)
  char long_string[PICOCERT_MAX_NAME_LEN + 10];
  memset(long_string, 'B', PICOCERT_MAX_NAME_LEN + 9);
  long_string[PICOCERT_MAX_NAME_LEN + 9] = '\0';

  picocert_t cert3 =
      create_test_cert(long_string, long_string, mock_current_time - 1000,
                       mock_current_time + 1000);
  TEST_ASSERT(strlen(cert3.issuer) == PICOCERT_MAX_NAME_LEN - 1,
              "Long issuer should be truncated to max-1");
  TEST_ASSERT(strlen(cert3.subject) == PICOCERT_MAX_NAME_LEN - 1,
              "Long subject should be truncated to max-1");
  TEST_ASSERT(cert3.issuer[PICOCERT_MAX_NAME_LEN - 1] == '\0',
              "Truncated issuer should be null-terminated");
  TEST_ASSERT(cert3.subject[PICOCERT_MAX_NAME_LEN - 1] == '\0',
              "Truncated subject should be null-terminated");

  // Test 4: Verify print function works
  printf("\n=== String Handling Test ===\n");
  printf("Short strings:\n");
  picocert_print_cert(&cert1);
  printf("\nMax length strings:\n");
  picocert_print_cert(&cert2);
  printf("\nTruncated strings:\n");
  picocert_print_cert(&cert3);
  printf("=== End String Handling Test ===\n\n");

  // Test 5: Verify cert validation still works with various string lengths
  // Create proper self-signed certificates for validation testing
  picocert_t self_signed_short = create_test_cert(
      "Short", "Short", mock_current_time - 1000, mock_current_time + 1000);
  picocert_t self_signed_max =
      create_test_cert(max_len_string, max_len_string, mock_current_time - 1000,
                       mock_current_time + 1000);
  picocert_t self_signed_long =
      create_test_cert(long_string, long_string, mock_current_time - 1000,
                       mock_current_time + 1000);

  picocert_err_t err =
      picocert_validate_cert(&ctx, &self_signed_short, &self_signed_short);
  TEST_ASSERT(err == PICOCERT_OK, "Short string cert should validate");

  err = picocert_validate_cert(&ctx, &self_signed_max, &self_signed_max);
  TEST_ASSERT(err == PICOCERT_OK, "Max length string cert should validate");

  err = picocert_validate_cert(&ctx, &self_signed_long, &self_signed_long);
  TEST_ASSERT(err == PICOCERT_OK, "Truncated string cert should validate");

  TEST_PASS();
}

// Test certificate printing (visual inspection)
int test_certificate_printing(void) {
  picocert_context_t ctx = {0};
  init_picocert_context_for_testing(&ctx);

  picocert_t cert = create_test_cert(
      "TestIssuer", "TestSubject", mock_current_time, mock_current_time + 3600);

  printf("\n=== Certificate Print Test ===\n");
  picocert_print_cert(&cert);
  printf("=== End Certificate Print Test ===\n\n");

  // Test with NULL certificate
  printf("Testing NULL certificate print (should do nothing):\n");
  picocert_print_cert(NULL);
  printf("NULL certificate print test complete.\n");

  TEST_PASS();
}

// Test runner
int main(void) {
  int total_tests = 0;
  int passed_tests = 0;

  int (*tests[])(void) = {
      test_library_initialization,
      test_key_extraction,
      test_certificate_structure,
      test_self_signed_detection,
      test_time_callback,
      test_certificate_time_validation,
      test_hash_verification,
      test_data_verification,
      test_certificate_chain_validation,
      test_version_validation,
      test_reserved_field_validation,
      test_uninitialized_library,
      test_public_key_format_validation,
      test_enum_field_validation,
      test_chain_length_limits,
      test_validity_period_consistency,
      test_string_handling,
      test_certificate_printing,
      test_3tier_pki_validation,
  };

  size_t num_tests = sizeof(tests) / sizeof(tests[0]);

  for (size_t i = 0; i < num_tests; i++) {
    total_tests++;
    if (tests[i]()) {
      passed_tests++;
    }
  }

  printf("\n=== Test Summary ===\n");
  printf("Total tests: %d\n", total_tests);
  printf("Passed: %d\n", passed_tests);
  printf("Failed: %d\n", total_tests - passed_tests);

  if (passed_tests == total_tests) {
    printf("All tests passed!\n");
    return 0;
  } else {
    printf("Some tests failed!\n");
    return 1;
  }
}
