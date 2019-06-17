// Package pkcs12 allows a user to read in a PKCS12 file and return a private key and
// public certificates that can be used in both TLS services. The official PKCS12 library
// is not the friendliest when you have more than 1 public key for the purpose of checking
// the certificates signing by intermediates and the root CA. This uses a vendored
// version of the golang.org/x/crypto/pkcs12 package, as the original cannot accurately decode a
// Microsoft pkcs12 due to unsupported OIDs, some of which do not have any documentation
// I can find. These changes are actually based on https://go-review.googlesource.com/c/crypto/+/166520
// that has been pending for a review and not the current checked in code.
//
// Usage Note: skipVerify == true makes the assumtion that the first public cert found is the site
// certificate. While that seems to be the defacto standard, I did not find a reference that says
// this is always the case.
//
// Note: I haven't tried to push these OID changes up into the repo. I am not an expert on TLS and
// some of these OIDs are mysterious in nature. I ignore these attributes as they aren't necessary
// for Go's purpose of serving content or validating certificate signatures. Some are related to
// OSCP and allowed usages. I do not understand these enough to implement (I can see these have
// entries in x509.Certificate struct). Some of the Microsoft ones don't have any documentation
// I can find online.
//
// Note2: There aren't tests here. I've only tested this with certificates I cannot store here
// and I will need to duplicate this with some throw away certs or bring up a CA in my test code
// to do the generation. This is more involved than I can deal with right now. Your mileage may
// vary, as I ain't Brad Fitzpatrick.
package pkcs12

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/pkcs12"
)

func extraction(pkcs12Bytes []byte, password string, skipVerify bool) (*pem.Block, []*x509.Certificate, error) {
	// Sometimes the data is base64 encoded, in those cases decode it.
	p12, err := base64.StdEncoding.DecodeString(string(pkcs12Bytes))
	if err == nil {
		pkcs12Bytes = p12
	}

	blocks, err := pkcs12.ToPEM(pkcs12Bytes, password)
	if err != nil {
		return nil, nil, err
	}

	if len(blocks) < 2 {
		return nil, nil, fmt.Errorf("this pkcs12 file does not contain 1 private key and at least one certificate, found only %d blocks", len(blocks))
	}

	certs := []*x509.Certificate{}
	for i, block := range blocks[1:] {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("block %d did not appear to be a x509 certificate", i)
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, nil, fmt.Errorf("no public certs were found")
	}

	if !skipVerify {
		intermediates := x509.NewCertPool()
		roots := x509.NewCertPool()

		switch len(certs) {
		case 1:
			// Do nothing
		default:
			for _, cert := range certs[1:] {
				if cert.BasicConstraintsValid && cert.IsCA {
					roots.AddCert(cert)
				} else {
					intermediates.AddCert(cert)
				}
			}
		}

		opts := x509.VerifyOptions{Roots: roots, Intermediates: intermediates}
		if _, err := certs[0].Verify(opts); err != nil {
			return nil, nil, fmt.Errorf("certificate chain did not verify: %s", err)
		}
	}

	return &pem.Block{Type: "PRIVATE KEY", Bytes: blocks[0].Bytes}, certs, nil
}

// parsePrivateKey is lifted from somewhere in the standard library.
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}

	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("tls: found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("tls: failed to parse private key")
}

// FromFile opens a PKCS12 file at filePath with password and returns the PrivateKey, public certificates
// and a ready made tls.Certificate.
func FromFile(filePath string, password string, skipVerify bool) (crypto.PrivateKey, []*x509.Certificate, tls.Certificate, error) {
	b, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, nil, tls.Certificate{}, fmt.Errorf("could not oopen file %s: %s", filePath, err)
	}

	keyBlock, certs, err := extraction(b, password, skipVerify)
	if err != nil {
		return nil, nil, tls.Certificate{}, err
	}

	// NOTE: I'm not really sure what the hell is underneath here. I might be able to use this as is,
	// but I KNOW if I encode/decode here it is going to be fine. And it happens so fast, this shouldn't
	// matter. Now this is TERRIBLE, and I should do better, but I really don't want to screw around
	// with this at the moment to get right, as I am pressed for time. Sorry, but I suck right now.
	privKey, err := parsePrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, tls.Certificate{}, fmt.Errorf("could not parse the private key: %s", err)
	}

	tlsCert := tls.Certificate{PrivateKey: privKey}

	for _, cert := range certs {
		tlsCert.Certificate = append(tlsCert.Certificate, cert.Raw)
	}

	return privKey, certs, tlsCert, nil
}

// WriteFromFileToPEM writes PEM encoded key and certificate from a PCKS12 file. The certificates are
// concatenated together. You can use PEMFilesToTLS to read these into a TLS certificate for use.
// This is useful when you don't want to use the PKCS12 archive in your secret storage and would
// prefer PEM encoded data. The certPath will store all certificate (minues private key) in the
// archive, useful for certificate validation with intermediate and root CA public keys.
func WriteFromFileToPEM(pkcs12Path string, password string, skipVerify bool, keyPath, certPath string) error {
	b, err := ioutil.ReadFile(pkcs12Path)
	if err != nil {
		return fmt.Errorf("could not read PKCS12 file %s: %s", pkcs12Path, err)
	}

	keyFile, err := os.Create(keyPath)
	if err != nil {
		return fmt.Errorf("could not create file %s: %s", keyPath, err)
	}
	defer keyFile.Close()

	certFile, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("could not create file %s: %s", certPath, err)
	}
	defer certFile.Close()

	keyBlock, certs, err := extraction(b, password, skipVerify)

	if err := pem.Encode(keyFile, keyBlock); err != nil {
		return fmt.Errorf("could not PEM encode the private key block: %s", err)
	}

	for i, cert := range certs {
		if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return fmt.Errorf("could not PEM encode certificate %d: %s", i, err)
		}
	}
	return nil
}

// PEMFilesToTLS takes in a private key and certificates in tow files generated by WritePEMFiles()
// and returns a TLS certificate to use in your service.
func PEMFilesToTLS(keyPath, certPath string) (tls.Certificate, error) {
	keyBytes, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("could not read private key at %s: %s", keyPath, err)
	}

	certPEMBlock, err := ioutil.ReadFile(certPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("could not read cert file at %s: %s", certPath, err)
	}

	privKey, _ := pem.Decode(keyBytes)

	pk, err := parsePrivateKey(privKey.Bytes)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("could not parse the private key at %s: %s", keyPath, err)
	}

	tlsCert := tls.Certificate{PrivateKey: pk}

	for {
		var certDERBlock *pem.Block
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			tlsCert.Certificate = append(tlsCert.Certificate, certDERBlock.Bytes)
		}
	}

	return tlsCert, nil
}
