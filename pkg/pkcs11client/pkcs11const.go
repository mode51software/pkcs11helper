package pkcs11client

import (
	"crypto/elliptic"
	"encoding/asn1"
	"github.com/miekg/pkcs11"
)

const (
	CKM_EDDSA_NACL = (pkcs11.CKM_VENDOR_DEFINED + 0xC02) // ed25519 sign/verify - NaCl compatible
	CKM_EDDSA      = (pkcs11.CKM_VENDOR_DEFINED + 0xC03) // ed25519 sign/verify

	CKK_EC_EDWARDS = (pkcs11.CKK_VENDOR_DEFINED + 0x12)
)

// https://tools.ietf.org/html/rfc5759#section-3.2
var curveOIDs = map[string]asn1.ObjectIdentifier{
	"P-256": {1, 2, 840, 10045, 3, 1, 7},
	"P-384": {1, 3, 132, 0, 34},
}

// https://github.com/letsencrypt/boulder/blob/release-2021-02-08/pkcs11helpers/helpers.go#L208
// oidDERToCurve maps the hex of the DER encoding of the various curve OIDs to
// the relevant curve parameters
var oidDERToCurve = map[string]elliptic.Curve{
	"06052B81040021":       elliptic.P224(),
	"06082A8648CE3D030107": elliptic.P256(),
	"06052B81040022":       elliptic.P384(),
	"06052B81040023":       elliptic.P521(),
}
