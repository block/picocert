package picocert

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"math/big"
	"time"
)

const (
	MaxNameLen     = 32
	MaxPubKeyLen   = 65
	MaxSigLen      = 64
	CurrentVersion = 1
)

type Curve uint8
type Hash uint8

const (
	P256 Curve = 0
)

const (
	Sha256 Hash = 0
)

var (
	ErrInvalid         = errors.New("invalid")
	ErrExpired         = errors.New("expired")
	ErrSignature       = errors.New("signature")
	ErrIssuerMismatch  = errors.New("issuer mismatch")
	ErrVersionMismatch = errors.New("version mismatch")
	ErrReserved        = errors.New("reserved")
	ErrNotSelfSigned   = errors.New("not self-signed")
	ErrUnknown         = errors.New("unknown")
)

type Certificate struct {
	Version   uint8
	Issuer    [MaxNameLen]byte
	Subject   [MaxNameLen]byte
	ValidFrom uint64
	ValidTo   uint64
	Curve     Curve
	Hash      Hash
	Reserved  uint32
	PubKey    [MaxPubKeyLen]byte
	Signature [MaxSigLen]byte
}

type CertificateWithKey struct {
	Cert       Certificate
	PrivateKey []uint8 // In PKCS8
}

// Helper functions
func copyWithZeros(src []byte) [MaxNameLen]byte {
	var dst [MaxNameLen]byte
	copy(dst[:], src)
	return dst
}

func currentTime() uint64 {
	return uint64(time.Now().Unix())
}

func (c *Certificate) IsSelfSigned() bool {
	return c.Issuer == c.Subject
}

func (c *Certificate) SignableBytes() []byte {
	buf := bytes.Buffer{}
	buf.WriteByte(c.Version)
	buf.Write(c.Issuer[:])
	buf.Write(c.Subject[:])
	binary.Write(&buf, binary.LittleEndian, c.ValidFrom)
	binary.Write(&buf, binary.LittleEndian, c.ValidTo)
	buf.WriteByte(byte(c.Curve))
	buf.WriteByte(byte(c.Hash))
	binary.Write(&buf, binary.LittleEndian, c.Reserved)
	buf.Write(c.PubKey[:])
	return buf.Bytes()
}

func (c *Certificate) ToBytes() []byte {
	b := c.SignableBytes()
	b = append(b, c.Signature[:]...)
	return b
}

func ParseCertificate(data []byte) (*Certificate, error) {
	if len(data) < 1+MaxNameLen*2+8*2+1+1+4+MaxPubKeyLen+MaxSigLen {
		return nil, ErrInvalid
	}
	var cert Certificate
	i := 0
	cert.Version = data[i]
	i++

	copy(cert.Issuer[:], data[i:i+MaxNameLen])
	i += MaxNameLen

	copy(cert.Subject[:], data[i:i+MaxNameLen])
	i += MaxNameLen

	cert.ValidFrom = binary.LittleEndian.Uint64(data[i : i+8])
	i += 8
	cert.ValidTo = binary.LittleEndian.Uint64(data[i : i+8])
	i += 8

	cert.Curve = Curve(data[i])
	i++
	cert.Hash = Hash(data[i])
	i++

	cert.Reserved = binary.LittleEndian.Uint32(data[i : i+4])
	i += 4

	copy(cert.PubKey[:], data[i:i+MaxPubKeyLen])
	i += MaxPubKeyLen

	copy(cert.Signature[:], data[i:i+MaxSigLen])
	return &cert, nil
}

func Issue(issuer *CertificateWithKey, subject string, validFrom, validTo uint64) (*CertificateWithKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Ensure x, y are exactly 32 bytes when constructing the pubkey
	xBytes := priv.PublicKey.X.FillBytes(make([]byte, 32))
	yBytes := priv.PublicKey.Y.FillBytes(make([]byte, 32))
	pub := append([]byte{0x04}, append(xBytes, yBytes...)...)

	var pubKey [MaxPubKeyLen]byte
	copy(pubKey[:], pub)

	cert := Certificate{
		Version:   CurrentVersion,
		Subject:   copyWithZeros([]byte(subject)),
		ValidFrom: validFrom,
		ValidTo:   validTo,
		Curve:     P256,
		Hash:      Sha256,
		PubKey:    pubKey,
	}

	if issuer != nil {
		cert.Issuer = issuer.Cert.Subject

		// Parse issuer's private key from PKCS8 format
		issuerPrivKey, err := ParsePrivateKey(issuer.PrivateKey)
		if err != nil {
			return nil, err
		}

		sig, err := Sign(issuerPrivKey, cert.SignableBytes())
		if err != nil {
			return nil, err
		}
		copy(cert.Signature[:], sig)
	} else {
		cert.Issuer = cert.Subject
		sig, err := Sign(priv, cert.SignableBytes())
		if err != nil {
			return nil, err
		}
		copy(cert.Signature[:], sig)
	}

	// Convert private key to PKCS8 format
	pkcs8PrivKey, err := EncodePrivateKeyToPKCS8(priv)
	if err != nil {
		return nil, err
	}

	return &CertificateWithKey{Cert: cert, PrivateKey: pkcs8PrivKey}, nil
}

// EncodePrivateKeyToPKCS8 encodes a private key to PKCS8 format
func EncodePrivateKeyToPKCS8(privateKey *ecdsa.PrivateKey) ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(privateKey)
}

// ParsePrivateKey parses a PKCS8 encoded private key
func ParsePrivateKey(pkcs8Key []byte) (*ecdsa.PrivateKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(pkcs8Key)
	if err != nil {
		return nil, err
	}

	// Assert that it's an ECDSA private key
	ecdsaKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an ECDSA private key")
	}

	return ecdsaKey, nil
}

func Sign(priv *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
	if err != nil {
		return nil, err
	}
	// Fixed length
	rb := r.Bytes()
	sb := s.Bytes()
	sig := make([]byte, MaxSigLen)
	copy(sig[32-len(rb):32], rb)
	copy(sig[64-len(sb):64], sb)
	return sig, nil
}

func Verify(cert *Certificate, data, sig []byte) error {
	hash := sha256.Sum256(data)

	// Use ecdh.P256 to parse the public key bytes
	pubKey, err := ecdh.P256().NewPublicKey(cert.PubKey[:])
	if err != nil {
		return ErrInvalid
	}
	// Extract X and Y from the public key bytes (uncompressed format)
	pubBytes := pubKey.Bytes()
	if len(pubBytes) != 65 || pubBytes[0] != 0x04 {
		return ErrInvalid
	}
	x := new(big.Int).SetBytes(pubBytes[1:33])
	y := new(big.Int).SetBytes(pubBytes[33:65])

	pub := ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	ok := ecdsa.Verify(&pub, hash[:], r, s)
	if !ok {
		return ErrSignature
	}
	return nil
}

func ValidateCert(issuer, subject *Certificate) error {
	if issuer.Version != CurrentVersion || subject.Version != CurrentVersion {
		return ErrVersionMismatch
	}
	if issuer.Reserved != 0 || subject.Reserved != 0 {
		return ErrReserved
	}
	if issuer.Subject != subject.Issuer {
		return ErrIssuerMismatch
	}
	now := currentTime()
	if now < subject.ValidFrom || now > subject.ValidTo ||
		now < issuer.ValidFrom || now > issuer.ValidTo {
		return ErrExpired
	}
	return Verify(issuer, subject.SignableBytes(), subject.Signature[:])
}

func ValidateCertChain(chain []Certificate) error {
	if len(chain) == 0 {
		return ErrInvalid
	}
	for i := 0; i < len(chain)-1; i++ {
		err := ValidateCert(&chain[i+1], &chain[i])
		if err != nil {
			return err
		}
	}
	root := chain[len(chain)-1]
	if !root.IsSelfSigned() {
		return ErrNotSelfSigned
	}
	return ValidateCert(&root, &root)
}

func VerifyAndValidateChain(chain []Certificate, data, sig []byte) error {
	if len(chain) == 0 || len(data) == 0 {
		return ErrInvalid
	}
	if err := ValidateCertChain(chain); err != nil {
		return err
	}
	return Verify(&chain[0], data, sig)
}
