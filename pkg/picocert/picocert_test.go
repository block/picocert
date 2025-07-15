package picocert_test

import (
	"testing"
	"time"

	"github.com/block/picocert/pkg/picocert"
	"github.com/stretchr/testify/require"
)

func TestIssueSelfSignedCert(t *testing.T) {
	subject := "selfsigned"
	validFrom := uint64(time.Now().Unix())
	validTo := validFrom + 60*60*24

	certWithKey, err := picocert.Issue(nil, subject, validFrom, validTo)
	require.NoError(t, err)
	require.Equal(t, subject, string(certWithKey.Cert.Subject[:len(subject)]))
	require.Equal(t, certWithKey.Cert.Issuer, certWithKey.Cert.Subject)

	data := []byte("hello world")

	// Parse the private key first, since it's stored in PKCS8 format
	privateKey, err := picocert.ParsePrivateKey(certWithKey.PrivateKey)
	require.NoError(t, err)

	sig, err := picocert.Sign(privateKey, data)
	require.NoError(t, err)

	err = picocert.Verify(&certWithKey.Cert, data, sig)
	require.NoError(t, err)

	err = picocert.VerifyAndValidateChain([]picocert.Certificate{certWithKey.Cert}, data, sig)
	require.NoError(t, err)
}

func TestIssueCertChain(t *testing.T) {
	rootSubject := "root"
	interSubject := "intermediate"
	leafSubject := "leaf"
	now := uint64(time.Now().Unix())
	oneYear := uint64(365 * 24 * 60 * 60)

	// Create root certificate
	rootCert, err := picocert.Issue(nil, rootSubject, now, now+oneYear)
	require.NoError(t, err)
	require.NotNil(t, rootCert)

	// Create intermediate certificate signed by root
	interCert, err := picocert.Issue(rootCert, interSubject, now, now+oneYear)
	require.NoError(t, err)
	require.NotNil(t, interCert)

	// Create leaf certificate signed by intermediate
	leafCert, err := picocert.Issue(interCert, leafSubject, now, now+oneYear)
	require.NoError(t, err)
	require.NotNil(t, leafCert)

	// Verify each certificate individually
	require.Equal(t, rootSubject, string(rootCert.Cert.Subject[:len(rootSubject)]))
	require.Equal(t, interSubject, string(interCert.Cert.Subject[:len(interSubject)]))
	require.Equal(t, leafSubject, string(leafCert.Cert.Subject[:len(leafSubject)]))

	// Create proper certificate chain
	chain := []picocert.Certificate{leafCert.Cert, interCert.Cert, rootCert.Cert}
	err = picocert.ValidateCertChain(chain)
	require.NoError(t, err)
}

func TestInvalidSignature(t *testing.T) {
	subject := "selfsigned"
	validFrom := uint64(time.Now().Unix())
	validTo := validFrom + 60*60*24

	certWithKey, err := picocert.Issue(nil, subject, validFrom, validTo)
	require.NoError(t, err)

	data := []byte("valid data")

	// Parse the private key first, since it's stored in PKCS8 format
	privateKey, err := picocert.ParsePrivateKey(certWithKey.PrivateKey)
	require.NoError(t, err)

	sig, err := picocert.Sign(privateKey, data)
	require.NoError(t, err)

	tampered := []byte("tampered data")
	err = picocert.VerifyAndValidateChain([]picocert.Certificate{certWithKey.Cert}, tampered, sig)
	require.Error(t, err)
}

func TestExpiredCert(t *testing.T) {
	subject := "expired"
	validFrom := uint64(time.Now().Add(-48 * time.Hour).Unix())
	validTo := validFrom + 24*60*60

	certWithKey, err := picocert.Issue(nil, subject, validFrom, validTo)
	require.NoError(t, err)

	err = picocert.ValidateCertChain([]picocert.Certificate{certWithKey.Cert})
	require.ErrorIs(t, err, picocert.ErrExpired)
}

func TestNotSelfSignedRoot(t *testing.T) {
	subject := "root"
	now := uint64(time.Now().Unix())
	oneYear := uint64(365 * 24 * 60 * 60)

	certWithKey, err := picocert.Issue(nil, subject, now, now+oneYear)
	require.NoError(t, err)

	// Tamper with issuer
	copy(certWithKey.Cert.Issuer[:], []byte("notroot"))

	err = picocert.ValidateCertChain([]picocert.Certificate{certWithKey.Cert})
	require.ErrorIs(t, err, picocert.ErrNotSelfSigned)
}

func TestIssueWithIssuer(t *testing.T) {
	issuerSubject := "issuer"
	subjectName := "subject"

	now := uint64(time.Now().Unix())
	oneYear := uint64(365 * 24 * 60 * 60)

	// Create an issuer cert first (self-signed)
	issuerCertWithKey, err := picocert.Issue(nil, issuerSubject, now, now+oneYear)
	require.NoError(t, err)
	require.Equal(t, issuerSubject, string(issuerCertWithKey.Cert.Subject[:len(issuerSubject)]))
	require.Equal(t, issuerCertWithKey.Cert.Issuer, issuerCertWithKey.Cert.Subject)

	// Create a subject cert signed by the issuer
	subjCertWithKey, err := picocert.Issue(issuerCertWithKey, subjectName, now, now+oneYear)
	require.NoError(t, err)
	require.Equal(t, subjectName, string(subjCertWithKey.Cert.Subject[:len(subjectName)]))
	require.Equal(t, issuerSubject, string(subjCertWithKey.Cert.Issuer[:len(issuerSubject)]))

	// Check issuer and subject are correctly set
	require.NotEqual(t, subjCertWithKey.Cert.Issuer, subjCertWithKey.Cert.Subject)

	// Sign data with the subject key
	data := []byte("data to be signed")

	// Parse the private key first
	privateKey, err := picocert.ParsePrivateKey(subjCertWithKey.PrivateKey)
	require.NoError(t, err)

	sig, err := picocert.Sign(privateKey, data)
	require.NoError(t, err)

	// Verify the data with certificate chain
	certChain := []picocert.Certificate{subjCertWithKey.Cert, issuerCertWithKey.Cert}
	err = picocert.VerifyAndValidateChain(certChain, data, sig)
	require.NoError(t, err)
}

func TestCertificateSerialization(t *testing.T) {
	subject := "serialtest"
	validFrom := uint64(time.Now().Unix())
	validTo := validFrom + 60*60*24

	// Create a certificate
	certWithKey, err := picocert.Issue(nil, subject, validFrom, validTo)
	require.NoError(t, err)

	// Convert to binary form
	certBytes := certWithKey.Cert.ToBytes()
	require.NotEmpty(t, certBytes)

	// Parse it back
	parsedCert, err := picocert.ParseCertificate(certBytes)
	require.NoError(t, err)

	// Verify the values are preserved
	require.Equal(t, certWithKey.Cert.Version, parsedCert.Version)
	require.Equal(t, certWithKey.Cert.Subject, parsedCert.Subject)
	require.Equal(t, certWithKey.Cert.Issuer, parsedCert.Issuer)
	require.Equal(t, certWithKey.Cert.ValidFrom, parsedCert.ValidFrom)
	require.Equal(t, certWithKey.Cert.ValidTo, parsedCert.ValidTo)
	require.Equal(t, certWithKey.Cert.Curve, parsedCert.Curve)
	require.Equal(t, certWithKey.Cert.Hash, parsedCert.Hash)
	require.Equal(t, certWithKey.Cert.Reserved, parsedCert.Reserved)
	require.Equal(t, certWithKey.Cert.PubKey, parsedCert.PubKey)
	require.Equal(t, certWithKey.Cert.Signature, parsedCert.Signature)
}

func TestValidate3TierCertChain(t *testing.T) {
	rootSubject := "root"
	intermediateSubject := "intermediate"
	leafSubject := "leaf"
	now := uint64(time.Now().Unix())
	oneYear := uint64(365 * 24 * 60 * 60)

	// Create root certificate
	rootCert, err := picocert.Issue(nil, rootSubject, now, now+oneYear)
	require.NoError(t, err)
	require.Equal(t, rootSubject, string(rootCert.Cert.Subject[:len(rootSubject)]))
	require.Equal(t, rootCert.Cert.Issuer, rootCert.Cert.Subject) // Self-signed

	// Create intermediate certificate signed by root
	intermediateCert, err := picocert.Issue(rootCert, intermediateSubject, now, now+oneYear)
	require.NoError(t, err)
	require.Equal(t, intermediateSubject, string(intermediateCert.Cert.Subject[:len(intermediateSubject)]))
	require.Equal(t, rootSubject, string(intermediateCert.Cert.Issuer[:len(rootSubject)]))

	// Create leaf certificate signed by intermediate
	leafCert, err := picocert.Issue(intermediateCert, leafSubject, now, now+oneYear)
	require.NoError(t, err)
	require.Equal(t, leafSubject, string(leafCert.Cert.Subject[:len(leafSubject)]))
	require.Equal(t, intermediateSubject, string(leafCert.Cert.Issuer[:len(intermediateSubject)]))

	// Create and validate the certificate chain
	certChain := []picocert.Certificate{leafCert.Cert, intermediateCert.Cert, rootCert.Cert}
	err = picocert.ValidateCertChain(certChain)
	require.NoError(t, err)

	// Sign data with the leaf private key
	data := []byte("data signed with leaf cert")
	leafPrivKey, err := picocert.ParsePrivateKey(leafCert.PrivateKey)
	require.NoError(t, err)

	sig, err := picocert.Sign(leafPrivKey, data)
	require.NoError(t, err)

	// Verify the data with the full certificate chain
	err = picocert.VerifyAndValidateChain(certChain, data, sig)
	require.NoError(t, err)

	// Test with missing intermediate cert
	invalidChain := []picocert.Certificate{leafCert.Cert, rootCert.Cert}
	err = picocert.ValidateCertChain(invalidChain)
	require.Error(t, err) // Should fail without intermediate
}

func TestParseInvalidCertificate(t *testing.T) {
	// Test with too short data
	_, err := picocert.ParseCertificate([]byte("too short"))
	require.Error(t, err)
	require.Equal(t, picocert.ErrInvalid, err)
}

func TestVersionMismatch(t *testing.T) {
	subject := "version-test"
	now := uint64(time.Now().Unix())
	oneYear := uint64(365 * 24 * 60 * 60)

	certWithKey, err := picocert.Issue(nil, subject, now, now+oneYear)
	require.NoError(t, err)

	// Tamper with the version
	certWithKey.Cert.Version = 99 // Invalid version

	err = picocert.ValidateCertChain([]picocert.Certificate{certWithKey.Cert})
	require.Error(t, err)
	require.Equal(t, picocert.ErrVersionMismatch, err)
}

func TestReservedFieldNonZero(t *testing.T) {
	subject := "reserved-test"
	now := uint64(time.Now().Unix())
	oneYear := uint64(365 * 24 * 60 * 60)

	certWithKey, err := picocert.Issue(nil, subject, now, now+oneYear)
	require.NoError(t, err)

	// Tamper with reserved field
	certWithKey.Cert.Reserved = 42 // Should be zero

	err = picocert.ValidateCertChain([]picocert.Certificate{certWithKey.Cert})
	require.Error(t, err)
	require.Equal(t, picocert.ErrReserved, err)
}

func TestInvalidCertSignature(t *testing.T) {
	rootSubject := "root"
	leafSubject := "leaf"
	now := uint64(time.Now().Unix())
	oneYear := uint64(365 * 24 * 60 * 60)

	// Create root certificate
	rootCert, err := picocert.Issue(nil, rootSubject, now, now+oneYear)
	require.NoError(t, err)

	// Create leaf certificate signed by root
	leafCert, err := picocert.Issue(rootCert, leafSubject, now, now+oneYear)
	require.NoError(t, err)

	// Tamper with the signature
	for i := 0; i < 8; i++ {
		leafCert.Cert.Signature[i] ^= 0xFF // Flip some bits
	}

	// Create chain
	chain := []picocert.Certificate{leafCert.Cert, rootCert.Cert}

	// Validation should fail
	err = picocert.ValidateCertChain(chain)
	require.Error(t, err)
}

func TestEmptyCertChain(t *testing.T) {
	// Test validate empty chain
	err := picocert.ValidateCertChain([]picocert.Certificate{})
	require.Error(t, err)
	require.Equal(t, picocert.ErrInvalid, err)

	// Test verify and validate with empty chain
	err = picocert.VerifyAndValidateChain([]picocert.Certificate{}, []byte("data"), []byte("sig"))
	require.Error(t, err)
	require.Equal(t, picocert.ErrInvalid, err)
}

func TestOutOfOrderChain(t *testing.T) {
	rootSubject := "root"
	intermediateSubject := "intermediate"
	leafSubject := "leaf"
	now := uint64(time.Now().Unix())
	oneYear := uint64(365 * 24 * 60 * 60)

	// Create root certificate
	rootCert, err := picocert.Issue(nil, rootSubject, now, now+oneYear)
	require.NoError(t, err)

	// Create intermediate certificate
	intermediateCert, err := picocert.Issue(rootCert, intermediateSubject, now, now+oneYear)
	require.NoError(t, err)

	// Create leaf certificate
	leafCert, err := picocert.Issue(intermediateCert, leafSubject, now, now+oneYear)
	require.NoError(t, err)

	// Test with out of order chain
	outOfOrderChain := []picocert.Certificate{rootCert.Cert, intermediateCert.Cert, leafCert.Cert}
	err = picocert.ValidateCertChain(outOfOrderChain)
	require.Error(t, err) // Should fail with out of order chain
}
