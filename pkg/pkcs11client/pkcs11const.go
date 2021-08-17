package pkcs11client

import (
	"crypto/elliptic"
	"encoding/asn1"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/miekg/pkcs11"
)

const (
	CKM_EDDSA_NACL = (pkcs11.CKM_VENDOR_DEFINED + 0xC02) // ed25519 sign/verify - NaCl compatible
	CKM_EDDSA      = (pkcs11.CKM_VENDOR_DEFINED + 0xC03) // ed25519 sign/verify

	CKK_EC_EDWARDS = (pkcs11.CKK_VENDOR_DEFINED + 0x12)

	ERR_NEWKEYINTEGRITY      = "For new keys check that all of KeyBits, ID and Label are set"
	ERR_NEWKEYALREADYEXISTS  = "Key already exists"
	ERR_NOMECHANISMCREATE    = "Unable to find a key mechanism for key creation"
	ERR_UNSUPPORTEDKEYTYPE   = "Unsupported key type. Please use CKK_RSA or CKK_EC"
	ERR_UNSUPPORTEDCURVESIZE = "No curve for key bit size"

	CURVE_P224   = "P-224"
	CURVE_P256   = "P-256"
	CURVE_P384   = "P-384"
	CURVE_P521   = "P-521"
	CURVE_P256K1 = "P-256k1"
)

// https://tools.ietf.org/html/rfc5480 Appendix A p.19
var curveOIDs = map[string]asn1.ObjectIdentifier{
	CURVE_P224:   {1, 3, 132, 0, 33},
	CURVE_P256:   {1, 2, 840, 10045, 3, 1, 7},
	CURVE_P384:   {1, 3, 132, 0, 34},
	CURVE_P521:   {1, 3, 132, 0, 35},
	CURVE_P256K1: {1, 3, 132, 0, 10},
}

// https://github.com/letsencrypt/boulder/blob/release-2021-02-08/pkcs11helpers/helpers.go#L208
// oidDERToCurve maps the hex of the DER encoding of the various curve OIDs to
// the relevant curve parameters
// openssl ecparam -out ec_param.der -outform DER -name secp256k1
var oidDERToCurve = map[string]elliptic.Curve{
	"06052B81040021":       elliptic.P224(),
	"06082A8648CE3D030107": elliptic.P256(),
	"06052B81040022":       elliptic.P384(),
	"06052B81040023":       elliptic.P521(),
	"06052B8104000A":       secp256k1.S256(),
}
