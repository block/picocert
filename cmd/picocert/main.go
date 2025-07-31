package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/block/picocert/pkg/picocert"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "picocert",
		Usage: "Manage certificates",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "quiet",
				Aliases: []string{"q"},
				Usage:   "Suppress output messages",
			},
		},
		Commands: []*cli.Command{
			{
				Name:  "issue",
				Usage: "Issue a certificate",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "self_signed",
						Usage: "Create a self-signed certificate",
					},
					&cli.StringFlag{
						Name:  "issuer",
						Usage: "Path to issuer certificate",
					},
					&cli.StringFlag{
						Name:  "issuer_key",
						Usage: "Path to issuer private key",
					},
					&cli.StringFlag{
						Name:     "subject",
						Usage:    "Subject name",
						Required: true,
					},
					&cli.Uint64Flag{
						Name:     "validity_in_days",
						Usage:    "Validity period in days",
						Required: true,
					},
				},
				Action: issueCertificate,
			},
			{
				Name:  "sign",
				Usage: "Sign a binary file with a private key",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "key",
						Usage:    "Path to the private key file",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "binary",
						Usage:    "Path to the binary file to sign",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "output",
						Usage:    "Path to save the binary signature",
						Required: false,
						Value:    "",
					},
				},
				Action: signBinary,
			},
			{
				Name:  "verify",
				Usage: "Verify a binary and signature file",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "cert",
						Usage:    "Path to the certificate file",
						Required: true,
					},
					&cli.StringFlag{

						Name:     "binary",
						Usage:    "Path to the binary file to verify",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "signature",
						Usage:    "Path to the signature file",
						Required: true,
					},
				},
				Action: verifyBinary,
			},
			{
				Name:  "print",
				Usage: "Print certificate details",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "cert",
						Usage:    "Path to the certificate file",
						Required: true,
					},
				},
				Action: printCertificate,
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

// Helper function to print output only if quiet mode is not enabled
func printOutput(c *cli.Context, format string, a ...interface{}) {
	if !c.Bool("quiet") {
		fmt.Printf(format, a...)
	}
}

func issueCertificate(c *cli.Context) error {
	selfSigned := c.Bool("self_signed")
	issuerPath := c.String("issuer")
	issuerKeyPath := c.String("issuer_key")
	subject := c.String("subject")
	validityDays := c.Uint64("validity_in_days")

	if selfSigned && issuerPath != "" {
		return errors.New("cannot specify both --self_signed and --issuer options")
	}
	if !selfSigned && (issuerPath == "" || issuerKeyPath == "") {
		return errors.New("must specify both --issuer and --issuer_key for CA-signed certificate")
	}

	var issuer *picocert.CertificateWithKey

	if !selfSigned {
		certBytes, err := os.ReadFile(issuerPath)
		if err != nil {
			return fmt.Errorf("unable to read issuer certificate: %w", err)
		}
		cert, err := picocert.ParseCertificate(certBytes)
		if err != nil {
			return fmt.Errorf("unable to parse issuer certificate: %w", err)
		}
		keyBytes, err := os.ReadFile(issuerKeyPath)
		if err != nil {
			return fmt.Errorf("unable to read issuer private key: %w", err)
		}
		issuer = &picocert.CertificateWithKey{
			Cert:       *cert,
			PrivateKey: keyBytes,
		}
	}

	validFrom := uint64(time.Now().Unix())
	validTo := validFrom + validityDays*24*60*60

	issued, err := picocert.Issue(issuer, subject, validFrom, validTo)
	if err != nil {
		return fmt.Errorf("failed to issue certificate: %w", err)
	}

	certPath := fmt.Sprintf("%s.pct", subject)
	keyPath := fmt.Sprintf("%s.priv.der", subject)

	if err := os.WriteFile(certPath, issued.Cert.ToBytes(), 0644); err != nil {
		return fmt.Errorf("unable to write certificate: %w", err)
	}

	if err := os.WriteFile(keyPath, issued.PrivateKey, 0644); err != nil {
		return fmt.Errorf("unable to write private key: %w", err)
	}

	printOutput(c, "New certificate issued.\nCert: %s\nPrivate key: %s\n", certPath, keyPath)
	return nil
}

func signBinary(c *cli.Context) error {
	keyPath := c.String("key")
	binaryPath := c.String("binary")
	outoutPath := c.String("output")

	// Read the private key
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("unable to read private key: %w", err)
	}

	// Parse the private key
	privKey, err := picocert.ParsePrivateKey(keyBytes)
	if err != nil {
		return fmt.Errorf("unable to parse private key: %w", err)
	}

	// Read the binary file to be signed
	binaryData, err := os.ReadFile(binaryPath)
	if err != nil {
		return fmt.Errorf("unable to read binary file: %w", err)
	}

	// Sign the binary data
	signedBinary, err := picocert.Sign(privKey, binaryData)
	if err != nil {
		return fmt.Errorf("unable to sign binary: %w", err)
	}

	// If no output path is specified, print the signature to stdout
	if outoutPath == "" {
		printOutput(c, "Signature: %x\n", signedBinary)
		return nil
	}

	// Write the signed binary to the specified output path
	if err := os.WriteFile(outoutPath, signedBinary, 0644); err != nil {
		return fmt.Errorf("unable to write signed binary: %w", err)
	}
	printOutput(c, "Signature file created successfully: %s\n", outoutPath)

	return nil
}

func verifyBinary(c *cli.Context) error {
	certPath := c.String("cert")
	binaryPath := c.String("binary")
	signaturePath := c.String("signature")

	// Read the certificate
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("unable to read certificate: %w", err)
	}
	cert, err := picocert.ParseCertificate(certBytes)
	if err != nil {
		return fmt.Errorf("unable to parse certificate: %w", err)
	}

	// Read the binary file
	binaryData, err := os.ReadFile(binaryPath)

	if err != nil {
		return fmt.Errorf("unable to read binary file: %w", err)
	}

	// Read the signature file
	signatureData, err := os.ReadFile(signaturePath)
	if err != nil {
		return fmt.Errorf("unable to read signature file: %w", err)
	}

	// Verify the signature
	if err := picocert.Verify(cert, binaryData, signatureData); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	fmt.Println("Signature verification succeeded.")

	return nil
}

func printCertificate(c *cli.Context) error {
	certPath := c.String("cert")

	// Read the certificate
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("unable to read certificate: %w", err)
	}
	cert, err := picocert.ParseCertificate(certBytes)
	if err != nil {
		return fmt.Errorf("unable to parse certificate: %w", err)
	}

	fmt.Println(cert)

	return nil
}
