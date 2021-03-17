package pkcs11client

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"github.com/rs/zerolog/log"
	"io/ioutil"
	"math/big"
	"reflect"
	"time"
)

type rfc5480ECDSASignature struct {
	R, S *big.Int
}

func LoadCertRequestFromFile(filename string) (*x509.CertificateRequest, error) {

	fileData, err := ioutil.ReadFile(filename)

	if err != nil {
		return nil, err
	}

	return x509.ParseCertificateRequest(fileData)
}

func LoadCertFromFile(filename string) (*x509.Certificate, error) {

	fileData, err := ioutil.ReadFile(filename)

	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(fileData)
}

func LoadPEMCertFromFile(filename string) (*x509.Certificate, error) {

	fileData, err := ioutil.ReadFile(filename)

	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(fileData)

	if block == nil {
		return nil, errors.New("failed to parse certificate PEM")
	}

	return x509.ParseCertificate(block.Bytes)
	//return x509.ParseCertificate(fileData)
}

func LoadFromFileAsString(filename string) (*string, error) {

	fileData, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	strData := string(fileData)
	return &strData, err
}

func SaveCertToFile(filename string, cert *x509.Certificate) error {

	err := ioutil.WriteFile(filename, cert.Raw, 0644)

	return err
}

func LoadPubkeyFromFile(filename string) (interface{}, error) {

	fileData, err := ioutil.ReadFile(filename)

	if err != nil {
		return nil, err
	}

	pubPem, _ := pem.Decode(fileData)

	if pubPem == nil {
		return nil, errors.New("no public key in file")
	}

	var parsedKey interface{}

	if parsedKey, err = x509.ParsePKIXPublicKey(pubPem.Bytes); err != nil {
		return nil, errors.New("Unable to parse pubkey")
	}

	return parsedKey, err
}

func SaveDataToFile(filename string, fileData *[]byte) (err error) {

	err = ioutil.WriteFile(filename, *fileData, 0644)

	if err != nil {
		return err
	}
	return nil
}

func GenSignedCert(csr *x509.CertificateRequest,
	caCert *x509.Certificate,
	caSigner *HsmSigner) (signedCert *x509.Certificate, err error) {

	//	log.Info().Msgf("CA exp=%d", caPubKey.E)

	if caSigner.SignatureAlgo == x509.UnknownSignatureAlgorithm {
		return nil, errors.New("Please specify a signature algorith, eg. x509.ECDSAwithSHA512")
	}

	// https://pkg.go.dev/crypto/x509#Certificate
	template := &x509.Certificate{
		Subject:        csr.Subject,
		SerialNumber:   big.NewInt(caSigner.Serial),
		DNSNames:       csr.DNSNames, //[]string { "localhost2", "mode51.software" },
		EmailAddresses: csr.EmailAddresses,
		IPAddresses:    csr.IPAddresses,
		URIs:           csr.URIs,
		//ExtraExtensions: 		csr.ExtraExtensions,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  false,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, //x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    caSigner.SignatureAlgo,
	}

	log.Info().Msgf("pubkey algo=%s", csr.PublicKeyAlgorithm)

	// Chrome rejects a cert that only has a common name and no SubjectAlternativeName
	// The X.509 module automatically adds a SAN entry when any of DNSNames or IPAddresses are populated
	//if len(csr.DNSNames) == 0 && len(csr.IPAddresses) == 0 { //} && len(csr.EmailAddresses) == 0 {
	//	template.DNSNames = []string{csr.Subject.CommonName}
	//}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, csr.PublicKey, *caSigner)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certBytes)

	return cert, err
}

// https://github.com/letsencrypt/pkcs11key/blob/c9e453037c675bb913cde3388b43a9828b2b6a1d/v4/key.go#L508
func ecdsaPKCS11ToRFC5480(pkcs11Signature []byte) (rfc5480Signature []byte, err error) {
	mid := len(pkcs11Signature) / 2

	r := &big.Int{}
	s := &big.Int{}

	return asn1.Marshal(rfc5480ECDSASignature{
		R: r.SetBytes(pkcs11Signature[:mid]),
		S: s.SetBytes(pkcs11Signature[mid:]),
	})
}

// used in the CA cert
func GenSubjectKeyID(publicKey crypto.PublicKey) ([]byte, error) {

	marshaledKey, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	subjKeyID := sha1.Sum(marshaledKey)

	return subjKeyID[:], nil
}

func GetPubKeyType(publicKey crypto.PublicKey) (keyType x509.PublicKeyAlgorithm, err error) {
	if reflect.TypeOf(publicKey) == reflect.TypeOf(&rsa.PublicKey{}) {
		keyType = x509.RSA
	} else if reflect.TypeOf(publicKey) == reflect.TypeOf(&ecdsa.PublicKey{}) {
		keyType = x509.ECDSA
	} else {
		keyType = x509.UnknownPublicKeyAlgorithm
		err = errors.New("Unsupported PublicKeyAlgorithm")
	}
	return
}
