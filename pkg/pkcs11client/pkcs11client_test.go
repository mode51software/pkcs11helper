package pkcs11client

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/miekg/pkcs11"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"testing"
)

var pkcs11Client Pkcs11Client

// test signing
var caFiles = CASigningRequest{
	csrFile: "../../data/localhost512.csr.der",
	//	caPubkeyFile: "../../data/softhsm-inter-0002.ca.pub.pem",
	caPubkeyFile: "../../data/safenet-inter-0016.ca.pub.pem",
	//	caCertFile:   "../../data/softhsm-inter-0002.ca.cert.der",
	caCertFile: "../../data/safenet-inter-0016.ca.cert.der",
}

// test encryption
var keyConfig = KeyConfig{Label: "RSATestKey0020", Type: pkcs11.CKK_RSA}

func init() {

	/*	pkcs11Client.HsmConfig = &HsmConfig{
		Lib:             "/opt/server/softhsm/current/lib/softhsm/libsofthsm2.so",
		SlotId:          288648064,
		Pin:             "1234",
		ConnectTimeoutS: 10,
		ReadTimeoutS:    30,
	}*/

	pkcs11Client.HsmConfig = &HsmConfig{
		Lib:             "/opt/apps/safenet/dpod/current/libs/64/libCryptoki2.so",
		SlotId:          3,
		Pin:             "9e9515e556bd995e",
		ConnectTimeoutS: 10,
		ReadTimeoutS:    30,
	}

}

func registerTest(t *testing.T) {
	registerCleanup(t)
	registerConnection(t)
}

func registerConnection(t *testing.T) {
	if err := pkcs11Client.InitAndLoginWithTimeout(); err != nil {
		t.Fatal(err)
	}
}

func registerCleanup(t *testing.T) {
	t.Cleanup(func() {
		//pkcs11Client.Logout()
		pkcs11Client.Cleanup()
		log.Info().Msg("Cleaned up!")
	})
}

func TestCASigner(t *testing.T) {
	registerTest(t)

	csr, err := LoadCertRequestFromFile(caFiles.csrFile)
	if err != nil {
		t.Fatal(err)
	} else {
		log.Info().Msg("Loaded CSR with CN=" + csr.Subject.CommonName)

		if caCert, err := LoadCertFromFile(caFiles.caCertFile); err != nil {
			t.Fatal(err)
		} else {
			log.Info().Msg("Loaded CA cert with CN=" + caCert.Subject.CommonName)

			if caPubKey, err := LoadPubkeyFromFile(caFiles.caPubkeyFile); err != nil {
				t.Fatalf("Err %s %s", err, " check -----BEGIN RSA PUBLIC KEY-----")
			} else {
				log.Info().Msgf("Loaded CA pubkey") // with E=%d", caPubKey.E)

				var caSigner HsmSigner
				caSigner.Serial = int64(rand.Uint64())
				caSigner.PublicKey = caPubKey
				caSigner.KeyConfig.Label = "RSATestCAInterKey0002"
				caSigner.Pkcs11Client = &pkcs11Client
				caSigner.SignatureAlgo = x509.SHA512WithRSA //ECDSAWithSHA512

				if signedCsr, err := GenSignedCert(csr, caCert, &caSigner); err != nil {
					t.Fatal(err)
				} else {
					log.Info().Msg("Signed CSR with CN=" + signedCsr.Subject.CommonName)
					if err = SaveCertToFile("../../data/signedcert.der", signedCsr); err != nil {
						t.Fatal(err)
					} else {
						log.Info().Msg("Saved signed cert")
					}
				}
			}
		}
	}
}

func TestReadExistsPubKey(t *testing.T) {
	registerTest(t)
	keyConfig := &KeyConfig{
		Label: "ECTestCAInterKey0016",
	}
	data, err := pkcs11Client.ReadExistsPublicKey(keyConfig)

	pubPem, _ := pem.Decode(data)

	if pubPem == nil {
		t.Fatal(errors.New("no public key in file"))
	}

	var _ interface{}
	_, err = x509.ParsePKIXPublicKey(pubPem.Bytes)

	if err != nil {
		t.Fatal(err)
	}

	log.Info().Msgf("Found Public Key")

}

func TestReadECPubKey(t *testing.T) {
	registerCleanup(t)
	keyConfig := &KeyConfig{
		Label: "ECTestCAInterKey0016",
	}
	pubKey, err := pkcs11Client.ReadECPublicKey(keyConfig)

	if err != nil {
		t.Fatal(err)
	} else {
		log.Info().Msgf("Pubkey data=%s", (pubKey.(*ecdsa.PublicKey)).Params().Name)
	}

	log.Info().Msgf("Found Public Key")

}

func TestEncrypt(t *testing.T) {
	registerTest(t)
	plainText := []byte("Test")
	var encryptedText []byte
	//var cipherText []byte // = make([]byte, 16)
	testOverflow := "overflow"
	log.Info().Msgf("encryptedText addr=%p overflow=%p", &encryptedText, &testOverflow)
	err := pkcs11Client.EncryptRsaPkcsOaep(&plainText, &encryptedText, keyConfig, crypto.SHA256)
	if err != nil {
		assert.NoError(t, err)
	} else {
		log.Info().Msgf("cipherText testoverflow=%s testoverflow addr=%p sz=%d dat=%s",
			testOverflow, &testOverflow, len(encryptedText), encryptedText)
		log.Info().Msgf("cipheredText sz=%d", len(encryptedText))
	}
}

func TestEncryptThenDecrypt(t *testing.T) {
	registerTest(t)
	plainText := []byte("Test")
	var encryptedText []byte
	log.Info().Msgf("encryptedText addr=%p", &encryptedText)
	err := pkcs11Client.EncryptRsaPkcsOaep(&plainText, &encryptedText, keyConfig, crypto.SHA512)
	if err != nil {
		t.Fatal(err)
	} else {
		log.Info().Msgf("encryptedText addr=%p", &encryptedText)
		log.Info().Msgf("encryptedText sz=%d", len(encryptedText))
		//SaveDataToFile("/tmp/out.bin", &encryptedText)
		var decryptedText []byte
		err = pkcs11Client.DecryptRsaPkcsOaep(&encryptedText, &decryptedText, keyConfig, crypto.SHA512)
		if err != nil {
			t.Fatal(err)
		} else {
			log.Info().Msgf("decrypted text %s", decryptedText)
			assert.Equal(t, plainText, decryptedText)
		}
	}
}

func TestCreateRSAKeyPair(t *testing.T) {
	registerTest(t)

	if err := pkcs11Client.CheckExistsCreateKeyPair(
		&KeyConfig{Label: "testkeytest6", Id: []byte{31}, Type: pkcs11.CKK_RSA, KeyBits: 2048}); err != nil {
		t.Error(err)
	}
}

func TestCreateECKeyPair(t *testing.T) {
	registerTest(t)

	if err := pkcs11Client.CheckExistsCreateKeyPair(
		&KeyConfig{Label: "testkey42", Id: []byte{42}, Type: pkcs11.CKK_EC, KeyBits: 521}); err != nil {
		t.Error(err)
	}
}

func TestDeleteKeyPair(t *testing.T) {
	registerTest(t)

	if err := pkcs11Client.DeleteKeyPair(
		&KeyConfig{Label: "testkey42", Type: pkcs11.CKK_EC}); err != nil {
		t.Error(err)
	}
}
