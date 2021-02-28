package pkcs11client

import (
	"errors"
	"github.com/miekg/pkcs11"
)

type KeyConfig struct {
	Label string

	// CKA_ID doesn't appear to work with SoftHSM
	Id string

	// for CKA_KEY_TYPE
	Type uint

	// The mechanism will be auto populated but it can be manually set
	Mechanism []*pkcs11.Mechanism
}

func (k *KeyConfig) appendKeyIdentity(attribs []*pkcs11.Attribute) (fullAttribs []*pkcs11.Attribute, err error) {
	if len(k.Id) > 0 {
		fullAttribs = append(attribs, pkcs11.NewAttribute(pkcs11.CKA_ID, k.Id))
	} else if len(k.Label) > 0 {
		fullAttribs = append(attribs, pkcs11.NewAttribute(pkcs11.CKA_LABEL, k.Label))
	} else {
		return nil, errors.New("Provide a key id or label")
	}
	return
}
