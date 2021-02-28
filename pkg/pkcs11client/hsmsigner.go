package pkcs11client

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"github.com/rs/zerolog/log"
	"io"
	"reflect"
	"sync"
	"time"
)

type HsmSigner struct {
	CryptoSigner  crypto.Signer
	refreshMutex  sync.Mutex
	Pkcs11Client  *Pkcs11Client
	PublicKey     crypto.PublicKey
	KeyConfig     KeyConfig
	SignerOpts    crypto.SignerOpts
	Serial        int64
	SignatureAlgo x509.SignatureAlgorithm
}

type CASigningRequest struct {
	csrFile      string
	caPubkeyFile string
	caCertFile   string
}

// In PKCS#1 padding if the message digest is not set then the supplied data is signed or verified directly
// instead of using a DigestInfo structure. If a digest is set then the a
// DigestInfo structure is used and its the length must correspond to the digest type.
// https://www.openssl.org/docs/man1.1.1/man1/openssl-pkeyutl.html
// RFC 8017 Specifies the DigestInfo structures
// https://github.com/letsencrypt/pkcs11key/blob/master/key.go#L85
var digestInfos = map[crypto.Hash][]byte{
	crypto.MD5:       {0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10},
	crypto.SHA1:      {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA224:    {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256:    {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384:    {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512:    {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
	crypto.MD5SHA1:   {}, // A special TLS case which doesn't use an ASN1 prefix.
	crypto.RIPEMD160: {0x30, 0x20, 0x30, 0x08, 0x06, 0x06, 0x28, 0xcf, 0x06, 0x03, 0x00, 0x31, 0x04, 0x14},
}

func (t HsmSigner) Public() crypto.PublicKey {
	return t.PublicKey
}

func (t HsmSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signedCsr []byte, err error) {

	t.refreshMutex.Lock()

	defer t.refreshMutex.Unlock()

	log.Debug().Msgf("hashiFunc=%s id=%d len=%d type=%s",
		opts.HashFunc().String(), opts.HashFunc(), len(digest), reflect.TypeOf(opts))

	t.Pkcs11Client.LastErrCode = 0

	chan1 := make(chan error, 1)
	go func() {

		switch t.PublicKey.(type) {
		case *rsa.PublicKey:
			if pssOpts, ok := opts.(*rsa.PSSOptions); ok {
				t.SignerOpts = pssOpts
				signedCsr, err = t.Pkcs11Client.SignCertRSAPSS(digest, &t)
			} else {
				digestWithHeader := append(digestInfos[opts.HashFunc()], digest...)
				signedCsr, err = t.Pkcs11Client.SignCertRSA(digestWithHeader, &t)
			}
		case *dsa.PublicKey:
			signedCsr, err = t.Pkcs11Client.SignCertDSA(digest, &t)
		case *ecdsa.PublicKey:
			signedCsr, err = t.Pkcs11Client.SignCertECDSA(digest, &t)
		case *ed25519.PublicKey:
			signedCsr, err = t.Pkcs11Client.SignCertEDDSA(digest, &t)
		default:
			err = errors.New("Unsupported PublicKey type")
		}
		chan1 <- err

	}()

	select {
	case res := <-chan1:
		if res != nil {
			log.Debug().Msg("generic error here")
			t.Pkcs11Client.LastErrCode = PKCS11ERR_GENERICERROR
			return nil, res
		}
	case <-time.After(time.Duration(t.Pkcs11Client.HsmConfig.ReadTimeoutS) * time.Second):
		log.Debug().Msg("read timeout error here")
		t.Pkcs11Client.LastErrCode = PKCS11ERR_READTIMEOUT
		return nil, errors.New("PKCS#11 connection timeout")
	}

	if err != nil {
		t.Pkcs11Client.LastErrCode = PKCS11ERR_GENERICERROR
		return nil, err
	} else {
		return signedCsr, nil
	}
}
