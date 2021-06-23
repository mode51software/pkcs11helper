package pkcs11client

import (
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"github.com/miekg/pkcs11"
)

type KeyConfig struct {
	// CKA_LABEL
	Label string

	// CKA_ID doesn't appear to work with SoftHSM
	Id []byte

	// for CKA_KEY_TYPE
	Type uint

	// CKA_MODULUS BITS only needed for key creation
	KeyBits int

	// The mechanism will be auto populated but it can be manually set
	Mechanism []*pkcs11.Mechanism

	CurveType int
}

const (
	EC_UNSPECIFIED = 0
	EC_SECPRIME    = 1
	EC_BRAINPOOL   = 2
	EC_BRAINTWIST  = 3
	EC_SECPK       = 4
	EC_EDWARDS     = 5
)

type KeyConfigKeyPairTemplate struct {
	keyConfig             KeyConfig
	keyTemplatePrivConfig KeyTemplatePrivConfig
	keyTemplatePubConfig  KeyTemplatePubConfig
	keyTemplateSecurity   KeyTemplateSecurity
}

type KeyTemplatePrivConfig struct {

	// CKA_DECRYPT
	IsDecrypt bool

	// CKA_UNWRAP
	IsUnwrap bool

	// CKA_SIGN
	IsSign bool

	// CKA_DERIVE
	IsDerive bool
}

type KeyTemplatePubConfig struct {

	// CKA_ENCRYPT
	IsEncrypt bool

	// CKA_WRAP
	IsWrap bool

	// CKA_VERIFY
	IsVerify bool

	// CKA_PUBLIC_EXPONTENT
	Exponent []byte
}

type KeyTemplateSecurity struct {

	// CKA_TOKEN token or session object
	IsToken bool

	// CKA_PRIVATE requires elevated privileges to report the presence of a key object
	IsPrivate bool

	// CKA_SENSITIVE
	IsSensitive bool

	// CKA_ALWAYS_SENSITIVE
	IsAlwaysSensitive bool

	// CKA_MODIFIABLE
	IsModifiable bool

	// CKA_EXTRACTABLE
	IsExtractable bool

	// CKA_NEVER_EXTRACTABLE
	IsNeverExtractable bool
}

// an ID and label are needed when creating a key, though when using a key either may be used
func (k *KeyConfig) checkNewKeyIntegrity() bool {
	return k.KeyBits > 0 && (len(k.Id) > 0 || len(k.Label) > 0)
}

func (k *KeyConfig) appendKeyIdentity(attribs []*pkcs11.Attribute) (fullAttribs []*pkcs11.Attribute, err error) {
	found := false

	var extraAttribs []*pkcs11.Attribute

	if len(k.Id) > 0 {
		extraAttribs = append(extraAttribs, pkcs11.NewAttribute(pkcs11.CKA_ID, k.Id))
		found = true
	}
	if len(k.Label) > 0 {
		extraAttribs = append(extraAttribs, pkcs11.NewAttribute(pkcs11.CKA_LABEL, k.Label))
		found = true
	}
	if !found {
		return nil, errors.New("Provide a key id or label")
	}
	fullAttribs = append(attribs, extraAttribs...)
	return
}

func (kp *KeyConfigKeyPairTemplate) appendKeyPairGenParams(attribs []*pkcs11.Attribute) (fullAttribs []*pkcs11.Attribute, err error) {
	found := false

	var extraAttribs []*pkcs11.Attribute

	if kp.keyConfig.Type == pkcs11.CKK_RSA {
		extraAttribs = append(extraAttribs, pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, kp.keyConfig.KeyBits),
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, kp.keyTemplatePubConfig.Exponent))
		found = true
	} else if kp.keyConfig.Type == pkcs11.CKK_EC || kp.keyConfig.Type == pkcs11.CKK_ECDSA {

		var curveName string

		var curve elliptic.Curve // secp224r1 .. secp521r, secp256k1

		if kp.keyConfig.CurveType == EC_UNSPECIFIED || kp.keyConfig.CurveType == EC_SECPRIME {
			switch kp.keyConfig.KeyBits {
			case 224:
				curve = elliptic.P224()
			case 256:
				curve = elliptic.P256()
			case 384:
				curve = elliptic.P384()
			case 521:
				curve = elliptic.P521()
			default:
				return nil, errors.New(ERR_UNSUPPORTEDCURVESIZE)
			}
			curveName = curve.Params().Name
		} else if kp.keyConfig.CurveType == EC_SECPK {
			curveName = CURVE_P256K1
		}

		if curveOID, err := asn1.Marshal(curveOIDs[curveName]); err != nil {
			return nil, errors.New(ERR_UNSUPPORTEDCURVESIZE)
		} else {
			extraAttribs = append(extraAttribs, pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, curveOID))
		}
		found = true
	}
	if !found {
		return nil, errors.New(ERR_UNSUPPORTEDKEYTYPE)
	}
	fullAttribs = append(attribs, extraAttribs...)
	return
}

func (kp *KeyConfigKeyPairTemplate) GenDefaultKeyPairPrivTemplateForSigning() {

	kp.keyTemplatePrivConfig = KeyTemplatePrivConfig{
		IsDecrypt: false,
		IsUnwrap:  false,
		IsSign:    true,
		IsDerive:  false,
	}

}

func (kp *KeyConfigKeyPairTemplate) GenDefaultKeyPairPubTemplateForSigning() {

	kp.keyTemplatePubConfig = KeyTemplatePubConfig{
		IsEncrypt: false,
		IsWrap:    false,
		IsVerify:  true,
		Exponent:  []byte{1, 0, 1},
	}
}

func GenKeyConfigKeyPairTemplate(keyConfig *KeyConfig) KeyConfigKeyPairTemplate {
	kp := KeyConfigKeyPairTemplate{}
	kp.keyConfig = *keyConfig
	return kp
}

func (kp *KeyConfigKeyPairTemplate) GenDefaultKeyPairTemplateForSigning() {

	kp.GenDefaultKeySecurityTemplate()
	kp.GenDefaultKeyPairPrivTemplateForSigning()
	kp.GenDefaultKeyPairPubTemplateForSigning()
}

func (kp *KeyConfigKeyPairTemplate) GenDefaultKeySecurityTemplate() {
	kp.keyTemplateSecurity = KeyTemplateSecurity{
		IsToken:            true,
		IsPrivate:          true,
		IsSensitive:        true,
		IsAlwaysSensitive:  true,
		IsModifiable:       false,
		IsExtractable:      false,
		IsNeverExtractable: true,
	}
}

func (kp *KeyConfigKeyPairTemplate) GenKeyPairTemplateAttribs() (privAttribs []*pkcs11.Attribute, pubAttribs []*pkcs11.Attribute, err error) {

	privAttribs = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, kp.keyTemplateSecurity.IsToken),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, kp.keyTemplateSecurity.IsPrivate),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, kp.keyTemplateSecurity.IsSensitive),
		//		pkcs11.NewAttribute(pkcs11.CKA_ALWAYS_SENSITIVE, kp.keyTemplateSecurity.IsAlwaysSensitive),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, kp.keyTemplatePrivConfig.IsDecrypt),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, kp.keyTemplatePrivConfig.IsUnwrap),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, kp.keyTemplatePrivConfig.IsSign),
		pkcs11.NewAttribute(pkcs11.CKA_DERIVE, kp.keyTemplatePrivConfig.IsDerive),
		pkcs11.NewAttribute(pkcs11.CKA_MODIFIABLE, kp.keyTemplateSecurity.IsModifiable),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, kp.keyTemplateSecurity.IsExtractable),
	}
	privAttribs, err = (kp.keyConfig).appendKeyIdentity(privAttribs)
	if err != nil {
		return
	}

	pubAttribs = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, kp.keyConfig.Type),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, kp.keyTemplateSecurity.IsToken),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, kp.keyTemplatePubConfig.IsEncrypt),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, kp.keyTemplatePubConfig.IsWrap),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, kp.keyTemplatePubConfig.IsVerify),
	}

	pubAttribs, err = (kp.keyConfig).appendKeyIdentity(pubAttribs)
	if err != nil {
		return
	}
	pubAttribs, err = kp.appendKeyPairGenParams(pubAttribs)
	if err != nil {
		return
	}

	return
}
