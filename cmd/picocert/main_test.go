package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

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
