package pkcs11client

import (
	"crypto"
	"crypto/rsa"
	"errors"
	"github.com/miekg/pkcs11"
	"github.com/rs/zerolog/log"
)

// https://github.com/letsencrypt/pkcs11key/blob/v4.0.0/v4/key.go#L35
// https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/csprd01/pkcs11-curr-v3.0-csprd01.html#_Toc10560827
type pssParams struct {
	ckmHash uint // CKM constant for hash function
	ckgMGF  uint // CKG constant for mask generation function
}

var hashPSSParams = map[crypto.Hash]pssParams{
	crypto.SHA1:   {pkcs11.CKM_SHA_1, pkcs11.CKG_MGF1_SHA1},
	crypto.SHA224: {pkcs11.CKM_SHA224, pkcs11.CKG_MGF1_SHA224},
	crypto.SHA256: {pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256},
	crypto.SHA384: {pkcs11.CKM_SHA384, pkcs11.CKG_MGF1_SHA384},
	crypto.SHA512: {pkcs11.CKM_SHA512, pkcs11.CKG_MGF1_SHA512},
}

// For mechanisms that don't need additional params
//case pkcs11.CKM_RSA_PKCS: // PKCS#1 RSASSA v1.5 sign
//case pkcs11.CKM_RSA_X_509: // not in FIPS mode
func GenMechanismById(mechanismId uint) (mechanism []*pkcs11.Mechanism, err error) {
	mechanism = []*pkcs11.Mechanism{pkcs11.NewMechanism(mechanismId, nil)}
	return
}

func GenSignerMechanismById(mechanismId uint, opts crypto.SignerOpts) ([]*pkcs11.Mechanism, error) {
	switch mechanismId {
	case pkcs11.CKM_RSA_PKCS_PSS:
		pssOpts := opts.(*rsa.PSSOptions)
		pssParams, err := genPSSParamsForMechanism(pssOpts)
		if err != nil {
			return nil, err
		}
		return []*pkcs11.Mechanism{pkcs11.NewMechanism(mechanismId, pssParams)}, nil
	case pkcs11.CKM_RSA_PKCS: // PKCS#1 RSASSA v1.5 sign
		fallthrough
	case pkcs11.CKM_RSA_X_509: // not in FIPS mode
		fallthrough
	case pkcs11.CKM_DSA:
		fallthrough
	case pkcs11.CKM_ECDSA:
		fallthrough
	case CKM_EDDSA:
		return []*pkcs11.Mechanism{pkcs11.NewMechanism(mechanismId, nil)}, nil
	}

	return nil, nil
}

func genKeyGenMechanismById(id uint) ([]*pkcs11.Mechanism, error) {

	switch id {
	case pkcs11.CKK_RSA:
		return []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)}, nil
	case pkcs11.CKK_EC:
		return []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)}, nil
	default:
		return nil, errors.New(ERR_NOMECHANISMCREATE)
	}
}

// mechanisms vs functions: http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/os/pkcs11-curr-v2.40-os.html#_Toc416959967
func genMechanismByIdWithOaepParams(mechanismId uint, hashAlg crypto.Hash) (mechanism []*pkcs11.Mechanism, err error) {
	switch mechanismId {
	case pkcs11.CKM_RSA_PKCS_OAEP: // PKCS OAEP enc/dec
		if hashAlg == 0 {
			return nil, errors.New("OAEP requires a SHA algo")
		}
		oaepParams, err := genOaepParamsForMechanism(hashAlg, []byte{})
		if err != nil {
			return nil, err
		}
		mechanism = []*pkcs11.Mechanism{pkcs11.NewMechanism(mechanismId, oaepParams)}
	default:
		mechanism = nil
	}
	return
}

// https://go.googlesource.com/go/+/refs/tags/go1.16beta1/src/crypto/rsa/rsa.go#393
func genOaepParamsForMechanism(hashAlg crypto.Hash, label []byte) (*pkcs11.OAEPParams, error) {
	pkcsHashAlg, pkcsMgfAlg, err := genHashParamsForMechanism(hashAlg)
	if err != nil {
		return nil, err
	}
	return pkcs11.NewOAEPParams(pkcsHashAlg, pkcsMgfAlg, pkcs11.CKZ_DATA_SPECIFIED, label), nil
}

func genHashParamsForMechanism(hashAlg crypto.Hash) (pkcs11HashAlg uint, pkcs11MgfAlg uint, err error) {
	switch hashAlg {
	case crypto.SHA1:
		return pkcs11.CKM_SHA_1, pkcs11.CKG_MGF1_SHA1, nil //	20
	case crypto.SHA224:
		return pkcs11.CKM_SHA224, pkcs11.CKG_MGF1_SHA224, nil // 28
	case crypto.SHA256:
		return pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256, nil // 32
	case crypto.SHA384:
		return pkcs11.CKM_SHA384, pkcs11.CKG_MGF1_SHA384, nil // 48
	case crypto.SHA512:
		return pkcs11.CKM_SHA512, pkcs11.CKG_MGF1_SHA512, nil // 64
	default:
		return 0, 0, errors.New("Unknown hash algo")
	}
}

func genPSSParamsForMechanism(opts *rsa.PSSOptions) (pssParams []byte, err error) {
	params, ok := hashPSSParams[opts.Hash]
	if !ok {
		err = errors.New("pkcs11key: unknown hash function")
		return
	}

	if opts.SaltLength == rsa.PSSSaltLengthAuto || opts.SaltLength == rsa.PSSSaltLengthEqualsHash {
		opts.SaltLength = opts.Hash.Size()
	}
	pssParams = pkcs11.NewPSSParams(params.ckmHash, params.ckgMGF, uint(opts.SaltLength))
	log.Info().Msgf("pssParams hash=%d mgf=%d saltlen=%d", params.ckmHash, params.ckgMGF, opts.SaltLength)
	return
}
