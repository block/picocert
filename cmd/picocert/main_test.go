package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/block/picocert/pkg/picocert"
	"github.com/stretchr/testify/require"
)

func TestWriteCertificateAndKeyProtectsPrivateKey(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "test.pct")
	keyPath := filepath.Join(dir, "test.priv.der")

	err := writeCertificateAndKey(certPath, keyPath, []byte("certificate"), []byte("private key"))
	require.NoError(t, err)

	keyInfo, err := os.Stat(keyPath)
	require.NoError(t, err)
	require.Equal(t, fs.FileMode(0600), keyInfo.Mode().Perm())
}

func TestWriteCertificateAndKeyRefusesToClobber(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "test.pct")
	keyPath := filepath.Join(dir, "test.priv.der")
	require.NoError(t, os.WriteFile(keyPath, []byte("existing key"), 0600))

	err := writeCertificateAndKey(certPath, keyPath, []byte("new certificate"), []byte("new key"))
	require.Error(t, err)
	require.ErrorIs(t, err, fs.ErrExist)

	keyData, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	require.Equal(t, []byte("existing key"), keyData)
	_, err = os.Stat(certPath)
	require.True(t, errors.Is(err, fs.ErrNotExist))
}

func TestSignCommandAcceptsExistingPrivateKeyPermissions(t *testing.T) {
	dir := t.TempDir()
	now := uint64(time.Now().Unix())
	cert, err := picocert.Issue(nil, "signer", now, now+60)
	require.NoError(t, err)

	keyPath := filepath.Join(dir, "signer.priv.der")
	binaryPath := filepath.Join(dir, "firmware.bin")
	require.NoError(t, os.WriteFile(keyPath, cert.PrivateKey, 0600))
	require.NoError(t, os.Chmod(keyPath, 0644))
	require.NoError(t, os.WriteFile(binaryPath, []byte("firmware"), 0644))

	err = newApp().Run([]string{
		"picocert", "--quiet", "sign",
		"--key", keyPath,
		"--binary", binaryPath,
	})
	require.NoError(t, err)
}

func TestIssueCommandSeparatesSubjectFromOutputPath(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "device-files")
	subject := "devices/device-subject"

	err := newApp().Run([]string{
		"picocert", "--quiet", "issue",
		"--self_signed",
		"--subject", subject,
		"--output", output,
		"--validity_in_days", "1",
	})
	require.NoError(t, err)

	certBytes, err := os.ReadFile(output + ".pct")
	require.NoError(t, err)
	cert, err := picocert.ParseCertificate(certBytes)
	require.NoError(t, err)
	require.Equal(t, subject, string(cert.Subject[:len(subject)]))
	_, err = os.Stat(output + ".priv.der")
	require.NoError(t, err)
}

func TestVerifyCommandValidatesChainAgainstTrustedRoot(t *testing.T) {
	dir := t.TempDir()
	now := uint64(time.Now().Unix())
	oneYear := uint64(365 * 24 * 60 * 60)

	root, err := picocert.Issue(nil, "root", now, now+oneYear)
	require.NoError(t, err)
	intermediate, err := picocert.Issue(root, "intermediate", now, now+oneYear)
	require.NoError(t, err)
	leaf, err := picocert.Issue(intermediate, "leaf", now, now+oneYear)
	require.NoError(t, err)

	data := []byte("firmware")
	leafKey, err := picocert.ParsePrivateKey(leaf.PrivateKey)
	require.NoError(t, err)
	signature, err := picocert.Sign(leafKey, data)
	require.NoError(t, err)

	paths := writeVerificationFixture(t, dir, root, intermediate, leaf, data, signature)
	err = newApp().Run([]string{
		"picocert", "--quiet", "verify",
		"--cert", paths.leaf,
		"--intermediate", paths.intermediate,
		"--root", paths.root,
		"--binary", paths.binary,
		"--signature", paths.signature,
	})
	require.NoError(t, err)
}

func TestVerifyCommandRequiresTrustedRoot(t *testing.T) {
	err := newApp().Run([]string{
		"picocert", "verify",
		"--cert", "leaf.pct",
		"--binary", "firmware.bin",
		"--signature", "firmware.sig",
	})
	require.ErrorContains(t, err, "root")
}

func TestVerifyCommandRejectsUntrustedRoot(t *testing.T) {
	dir := t.TempDir()
	now := uint64(time.Now().Unix())
	oneYear := uint64(365 * 24 * 60 * 60)

	root, err := picocert.Issue(nil, "root", now, now+oneYear)
	require.NoError(t, err)
	leaf, err := picocert.Issue(root, "leaf", now, now+oneYear)
	require.NoError(t, err)
	untrustedRoot, err := picocert.Issue(nil, "untrusted", now, now+oneYear)
	require.NoError(t, err)

	data := []byte("firmware")
	leafKey, err := picocert.ParsePrivateKey(leaf.PrivateKey)
	require.NoError(t, err)
	signature, err := picocert.Sign(leafKey, data)
	require.NoError(t, err)

	paths := writeVerificationFixture(t, dir, untrustedRoot, nil, leaf, data, signature)
	err = newApp().Run([]string{
		"picocert", "--quiet", "verify",
		"--cert", paths.leaf,
		"--root", paths.root,
		"--binary", paths.binary,
		"--signature", paths.signature,
	})
	require.Error(t, err)
}

func TestVerifyCommandRejectsExpiredCertificate(t *testing.T) {
	dir := t.TempDir()
	now := uint64(time.Now().Unix())
	oneYear := uint64(365 * 24 * 60 * 60)

	root, err := picocert.Issue(nil, "root", now-oneYear, now+oneYear)
	require.NoError(t, err)
	leaf, err := picocert.Issue(root, "leaf", now-48*60*60, now-24*60*60)
	require.NoError(t, err)

	data := []byte("firmware")
	leafKey, err := picocert.ParsePrivateKey(leaf.PrivateKey)
	require.NoError(t, err)
	signature, err := picocert.Sign(leafKey, data)
	require.NoError(t, err)

	paths := writeVerificationFixture(t, dir, root, nil, leaf, data, signature)
	err = newApp().Run([]string{
		"picocert", "--quiet", "verify",
		"--cert", paths.leaf,
		"--root", paths.root,
		"--binary", paths.binary,
		"--signature", paths.signature,
	})
	require.ErrorIs(t, err, picocert.ErrExpired)
}

type verificationFixture struct {
	root         string
	intermediate string
	leaf         string
	binary       string
	signature    string
}

func writeVerificationFixture(
	t *testing.T,
	dir string,
	root *picocert.CertificateWithKey,
	intermediate *picocert.CertificateWithKey,
	leaf *picocert.CertificateWithKey,
	data, signature []byte,
) verificationFixture {
	t.Helper()

	fixture := verificationFixture{
		root:      filepath.Join(dir, "root.pct"),
		leaf:      filepath.Join(dir, "leaf.pct"),
		binary:    filepath.Join(dir, "firmware.bin"),
		signature: filepath.Join(dir, "firmware.sig"),
	}
	require.NoError(t, os.WriteFile(fixture.root, root.Cert.ToBytes(), 0644))
	require.NoError(t, os.WriteFile(fixture.leaf, leaf.Cert.ToBytes(), 0644))
	require.NoError(t, os.WriteFile(fixture.binary, data, 0644))
	require.NoError(t, os.WriteFile(fixture.signature, signature, 0644))
	if intermediate != nil {
		fixture.intermediate = filepath.Join(dir, "intermediate.pct")
		require.NoError(t, os.WriteFile(fixture.intermediate, intermediate.Cert.ToBytes(), 0644))
	}
	return fixture
}
