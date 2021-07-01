// Helpers for PKCS#11 including instructions for configuring:
// - SoftHSM
// - Thales SafeNet DPoD
// - Entrust nShield
package pkcs11client

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"github.com/miekg/pkcs11"
	"github.com/rs/zerolog/log"
	"math/big"
	"sync"
	"time"
)

type Pkcs11ErrorCode int

type Pkcs11ConnectionState int

const (
	PKCS11ERR_NONE Pkcs11ErrorCode = iota
	PKCS11ERR_GENERICERROR
	PKCS11ERR_CONNECTIONTIMEOUT
	PKCS11ERR_READTIMEOUT

	PKCS11CONNECTION_NONE = iota
	PKCS11CONNECTION_INPROGRESS
	PKCS11CONNECTION_FAILED
	PKCS11CONNECTION_SUCCEEDED
)

type Pkcs11Client struct {
	context     *pkcs11.Ctx
	session     pkcs11.SessionHandle
	HsmConfig   *HsmConfig
	Pkcs11Mutex sync.Mutex
	// the most recent error and code should only be used whilst holding the mutex lock
	ConnectionState Pkcs11ConnectionState
	LastErrCode     Pkcs11ErrorCode
	LastErr         error
}

func (p *Pkcs11Client) Init() (err error) {
	p.context = pkcs11.New(p.HsmConfig.Lib)
	err = p.context.Initialize()
	return
}

// this includes the PKCS#11 Initialize as part of the overall timeout
func (p *Pkcs11Client) InitAndLoginWithTimeout() (err error) {

	p.Pkcs11Mutex.Lock()
	defer p.Pkcs11Mutex.Unlock()

	p.ConnectionState = PKCS11CONNECTION_INPROGRESS

	chan1 := make(chan error, 1)
	go func() {

		if err = p.Init(); err != nil {
			chan1 <- err
		}
		if err = p.Login(); err != nil {
			chan1 <- err
		}
		chan1 <- nil
	}()

	select {
	case res := <-chan1:
		if res != nil {
			p.ConnectionState = PKCS11CONNECTION_FAILED
			return res
		}
	case <-time.After(time.Duration(p.HsmConfig.ConnectTimeoutS) * time.Second):
		p.ConnectionState = PKCS11CONNECTION_FAILED
		return errors.New("PKCS#11 connection timeout")
	}
	p.ConnectionState = PKCS11CONNECTION_SUCCEEDED
	return
}

func (p *Pkcs11Client) FlushSession() {
	if p.context != nil && p.session > 0 {
		p.context.CloseSession(p.session)
		p.Cleanup()
	}
}

// for module handling of connection timeout without the PKCS#11 Initialize as part of the timeout
// alternatively the Login function can be called directly so that timeouts can be handled externally
func (p *Pkcs11Client) LoginWithTimeout() error {

	chan1 := make(chan error, 1)
	go func() {

		if err := p.Login(); err != nil {
			chan1 <- err
		}
		chan1 <- nil
	}()

	select {
	case res := <-chan1:
		if res != nil {
			return errors.Unwrap(res)
		}
	case <-time.After(time.Duration(p.HsmConfig.ConnectTimeoutS) * time.Second):
		return errors.New("PKCS#11 connection timeout")
	}

	return nil
}

func (p *Pkcs11Client) Login() (err error) {
	p.session, err = p.context.OpenSession(p.HsmConfig.SlotId, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return
	}
	if len(p.HsmConfig.Pin) > 0 {
		err = p.context.Login(p.session, pkcs11.CKU_USER, p.HsmConfig.Pin)
	} else {
		err = errors.New("Please set the HSM slot PIN")
	}
	return
}

func (p *Pkcs11Client) Logout() (err error) {
	err = p.context.Logout(p.session)
	if err != nil {
		err = p.context.CloseSession(p.session)
	}
	return
}

func (p *Pkcs11Client) Cleanup() {
	p.context.Destroy()
	p.context.Finalize()
}

func (p *Pkcs11Client) SignCertRSA(csrData []byte, signer *HsmSigner) (cert []byte, err error) {
	cert, err = p.signCert(csrData, signer, pkcs11.CKK_RSA, pkcs11.CKM_RSA_PKCS)
	return
}

func (p *Pkcs11Client) SignCertRSAPSS(csrData []byte, signer *HsmSigner) (cert []byte, err error) {
	cert, err = p.signCert(csrData, signer, pkcs11.CKK_RSA, pkcs11.CKM_RSA_PKCS_PSS)
	return
}

func (p *Pkcs11Client) SignCertDSA(csrData []byte, signer *HsmSigner) (cert []byte, err error) {
	cert, err = p.signCert(csrData, signer, pkcs11.CKK_DSA, pkcs11.CKM_DSA)
	return
}

func (p *Pkcs11Client) SignCertECDSA(csrData []byte, signer *HsmSigner) (cert []byte, err error) {
	// CKK_ECDSA is deprecated in v2.11, use CKK_EC
	cert, err = p.signCert(csrData, signer, pkcs11.CKK_EC, pkcs11.CKM_ECDSA)
	if err == nil {
		// match RFC 5480 output
		cert, err = ecdsaPKCS11ToRFC5480(cert)
	}
	return
}

func (p *Pkcs11Client) SignDataECDSA(data []byte, signer *HsmSigner) (res []byte, err error) {
	res, err = p.signCert(data, signer, pkcs11.CKK_EC, pkcs11.CKM_ECDSA)
	return
}

// EDDSA uses the Edwards Ed25519 elliptic curve in FIPS 186-5
// https://csrc.nist.gov/publications/detail/fips/186/5/draft
func (p *Pkcs11Client) SignCertEDDSA(csrData []byte, signer *HsmSigner) (cert []byte, err error) {
	// CKK_ECDSA is deprecated in v2.11, use CKK_EC
	cert, err = p.signCert(csrData, signer, CKK_EC_EDWARDS, CKM_EDDSA)
	if err == nil {
		// match RFC 5480 output
		cert, err = ecdsaPKCS11ToRFC5480(cert)
	}
	return
}

func (p *Pkcs11Client) signCert(csrData []byte, signer *HsmSigner, privKeyType int, mechanismId uint) (signedCsr []byte, err error) {

	//err = SaveDataToFile("./data/outdigest.der", &csrData)

	attribs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, privKeyType),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
	}
	var fullAttribs []*pkcs11.Attribute
	if fullAttribs, err = (*signer).KeyConfig.appendKeyIdentity(attribs); err != nil {
		return nil, err
	}

	err = p.context.FindObjectsInit(p.session, fullAttribs)
	if err != nil {
		return nil, err
	}

	objHandles, _, err := p.context.FindObjects(p.session, 1)
	if err != nil {
		return nil, err
	}
	if objHandles == nil || len(objHandles) == 0 {
		return nil, errors.New("PKCS11 FindObjects empty")
	} else {
		if err = p.context.FindObjectsFinal(p.session); err != nil {
			return nil, err
		}
		var mechanism []*pkcs11.Mechanism
		if mechanism, err = GenSignerMechanismById(mechanismId, signer.SignerOpts); err != nil {
			return nil, err
		}

		if err = p.context.SignInit(p.session, mechanism, objHandles[0]); err != nil {
			return nil, err
		}
		signedCsr, err = p.context.Sign(p.session, csrData)
		if err != nil {
			return nil, err
		}

		/*		err = SaveDataToFile("./data/out.der", &signedCsr)
				if err != nil {
					return nil, err
				}*/
		return signedCsr, nil

	}
	return nil, nil
}

// PKCS v1_15 supports Encrypt/Decrypt, Sign/Verify, SR/VR, Wrap/Unwrap only
// insecure PKCSv1_15 not supported by FIPS enabled SafeNet HSM but works with SoftHSM
func (p *Pkcs11Client) EncryptRsaPkcs1v15(plainData *[]byte, encryptedData *[]byte, keyConfig KeyConfig) (err error) {
	keyConfig.Mechanism, err = GenMechanismById(pkcs11.CKM_RSA_PKCS)
	return p.encrypt(plainData, encryptedData, keyConfig)
}

func (p *Pkcs11Client) EncryptRsaPkcsX509(plainData *[]byte, encryptedData *[]byte, keyConfig KeyConfig) (err error) {
	keyConfig.Mechanism, err = GenMechanismById(pkcs11.CKM_RSA_X_509)
	return p.encrypt(plainData, encryptedData, keyConfig)
}

// RSA OAEP supports Encrypt/Decrypt and Wrap/Unwrap only
// requires additional params
// keyConfig.Mechanism will be auto populated based on the hashAlg unless already set, ie. it can be overridden
// hashAlg is eg. crypto.SHA256
// check RSA mechanisms vs functions: http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/os/pkcs11-curr-v2.40-os.html#_Toc416959967
func (p *Pkcs11Client) EncryptRsaPkcsOaep(plainData *[]byte, encryptedData *[]byte, keyConfig KeyConfig, hashAlg crypto.Hash) (err error) {
	if hashAlg == 0 {
		return errors.New("Must supply a hash algorithm, eg. crypto.SHA256")
	}
	if len(keyConfig.Mechanism) == 0 {
		keyConfig.Mechanism, err = genMechanismByIdWithOaepParams(pkcs11.CKM_RSA_PKCS_OAEP, hashAlg)
		if err != nil {
			return err
		}
	}
	return p.encrypt(plainData, encryptedData, keyConfig)
}

func (p *Pkcs11Client) encrypt(plainData *[]byte, encryptedData *[]byte, keyConfig KeyConfig) (err error) {
	attribs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, keyConfig.Type),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
	}
	var fullAttribs []*pkcs11.Attribute
	if fullAttribs, err = keyConfig.appendKeyIdentity(attribs); err != nil {
		return err
	}

	var objHandles []pkcs11.ObjectHandle
	if objHandles, err = p.FindObjects(fullAttribs, 1); err != nil {
		return err
	} else if len(objHandles) == 0 {
		return errors.New("No key found")
	} else {
		//mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, OAEPSha256Params)}
		err = p.EncryptWithHandle(plainData, encryptedData, keyConfig.Mechanism, objHandles[0])
		log.Info().Msgf("cipheredText addr=%p", encryptedData)
		return err
	}
}

// insecure PKCSv1_15 not supported by FIPS enabled SafeNet HSM but works with SoftHSM
func (p *Pkcs11Client) DecryptRsaPkcs1v15(encryptedData *[]byte, plainData *[]byte, keyConfig KeyConfig) (err error) {
	keyConfig.Mechanism, err = GenMechanismById(pkcs11.CKM_RSA_PKCS)
	return p.decrypt(encryptedData, plainData, keyConfig)
}

func (p *Pkcs11Client) DecryptRsaPkcsX509(encryptedData *[]byte, plainData *[]byte, keyConfig KeyConfig) (err error) {
	keyConfig.Mechanism, err = GenMechanismById(pkcs11.CKM_RSA_X_509)
	return p.decrypt(encryptedData, plainData, keyConfig)
}

// RSA OAEP requires additional params
// keyConfig.Mechanism will be auto populated based on the hashAlg unless already set, ie. it can be overridden
// hashAlg is eg. crypto.SHA256
func (p *Pkcs11Client) DecryptRsaPkcsOaep(encryptedData *[]byte, plainData *[]byte, keyConfig KeyConfig, hashAlg crypto.Hash) (err error) {
	if hashAlg == 0 {
		return errors.New("Must supply a hash algorithm, eg. crypto.SHA256")
	}
	if len(keyConfig.Mechanism) == 0 {
		keyConfig.Mechanism, err = genMechanismByIdWithOaepParams(pkcs11.CKM_RSA_PKCS_OAEP, hashAlg)
		if err != nil {
			return err
		}
	}
	return p.decrypt(encryptedData, plainData, keyConfig)
}

func (p *Pkcs11Client) decrypt(encryptedData *[]byte, plainData *[]byte, keyConfig KeyConfig) (err error) {

	attribs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, keyConfig.Type),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
	}
	var fullAttribs []*pkcs11.Attribute
	if fullAttribs, err = keyConfig.appendKeyIdentity(attribs); err != nil {
		return err
	}
	var objHandles []pkcs11.ObjectHandle
	if objHandles, err = p.FindObjects(fullAttribs, 1); err != nil {
		return err
	} else {
		//mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, OAEPSha256Params)}
		err = p.DecryptWithHandle(encryptedData, plainData, keyConfig.Mechanism, objHandles[0])
		return err
	}
}

func (p *Pkcs11Client) EncryptWithHandle(plainData *[]byte,
	encryptedData *[]byte,
	mechanism []*pkcs11.Mechanism,
	objHandle pkcs11.ObjectHandle) (err error) {

	if err = p.context.EncryptInit(p.session, mechanism, objHandle); err != nil {
		return err
	}

	// single part call - C_EncryptFinal is only needed if C_EncryptUpdate is used
	if *encryptedData, err = p.context.Encrypt(p.session, *plainData); err != nil {
		return err
	} else {
		return
	}
}

func (p *Pkcs11Client) DecryptWithHandle(encryptedData *[]byte,
	plainText *[]byte,
	mechanism []*pkcs11.Mechanism,
	objHandle pkcs11.ObjectHandle) (err error) {

	if err = p.context.DecryptInit(p.session, mechanism, objHandle); err != nil {
		return err
	}

	// single part call, C_DecryptFinal is only needed if C_DecryptUpdate is used
	if *plainText, err = p.context.Decrypt(p.session, *encryptedData); err != nil {
		return err
	} else {
		return
	}
}

func (p *Pkcs11Client) FindObjects(attribs []*pkcs11.Attribute, max int) (objHandles []pkcs11.ObjectHandle, err error) {

	if err = p.context.FindObjectsInit(p.session, attribs); err != nil {
		return
	}

	if objHandles, _, err = p.context.FindObjects(p.session, max); err != nil {
		return
	} else {
		if err = p.context.FindObjectsFinal(p.session); err != nil {
			return
		}
		if objHandles == nil || len(objHandles) == 0 {
			err = errors.New("PKCS11 FindObjects empty")
		}
		return
	}
}

// https://stackoverflow.com/a/25181584/2002211
func (p *Pkcs11Client) ReadRSAPublicKey(keyConfig *KeyConfig) (pubKey interface{}, err error) {
	return p.ReadPublicKey(keyConfig, pkcs11.CKK_RSA)
}

func (p *Pkcs11Client) ReadECPublicKey(keyConfig *KeyConfig) (pubKey interface{}, err error) {
	return p.ReadPublicKey(keyConfig, pkcs11.CKK_EC)
}

func (p *Pkcs11Client) ReadPublicKey(keyConfig *KeyConfig, pubKeyType uint) (pubKey interface{}, err error) {

	attribs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
	}

	var fullAttribs []*pkcs11.Attribute
	if fullAttribs, err = (keyConfig).appendKeyIdentity(attribs); err != nil {
		return
	}
	var objHandles []pkcs11.ObjectHandle
	if objHandles, err = p.FindObjects(fullAttribs, 1); err != nil {
		return
	}
	switch pubKeyType {
	case pkcs11.CKK_RSA:
		return p.GetRSAPublicKey(objHandles[0])
	case pkcs11.CKK_ECDSA:
		return p.GetECDSAPublicKey(objHandles[0])
	}
	return nil, nil
}

// https://github.com/letsencrypt/boulder/blob/release-2021-02-08/pkcs11helpers/helpers.go#L178
func (p *Pkcs11Client) GetRSAPublicKey(object pkcs11.ObjectHandle) (*rsa.PublicKey, error) {
	// Retrieve the public exponent and modulus for the public key
	attrs, err := p.context.GetAttributeValue(p.session, object, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("Failed to retrieve key attributes: %s", err)
	}

	// Attempt to build the public key from the retrieved attributes
	pubKey := &rsa.PublicKey{}
	gotMod, gotExp := false, false
	for _, a := range attrs {
		switch a.Type {
		case pkcs11.CKA_PUBLIC_EXPONENT:
			pubKey.E = int(big.NewInt(0).SetBytes(a.Value).Int64())
			gotExp = true
		case pkcs11.CKA_MODULUS:
			pubKey.N = big.NewInt(0).SetBytes(a.Value)
			gotMod = true
		}
	}
	// Fail if we are missing either the public exponent or modulus
	if !gotExp || !gotMod {
		return nil, errors.New("Couldn't retrieve modulus and exponent")
	}
	return pubKey, nil
}

// https://github.com/letsencrypt/boulder/blob/release-2021-02-08/pkcs11helpers/helpers.go#L208
func (p *Pkcs11Client) GetECDSAPublicKey(object pkcs11.ObjectHandle) (*ecdsa.PublicKey, error) {
	// Retrieve the curve and public point for the generated public key
	attrs, err := p.context.GetAttributeValue(p.session, object, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	})

	if err != nil {
		return nil, fmt.Errorf("Failed to retrieve key attributes: %s", err)
	}

	pubKey := &ecdsa.PublicKey{}
	var pointBytes []byte
	for _, a := range attrs {
		switch a.Type {
		case pkcs11.CKA_EC_PARAMS:
			rCurve, present := oidDERToCurve[fmt.Sprintf("%X", a.Value)]
			if !present {
				return nil, errors.New("Unknown curve OID value returned")
			}
			pubKey.Curve = rCurve
		case pkcs11.CKA_EC_POINT:
			pointBytes = a.Value
		}
	}
	if pointBytes == nil || pubKey.Curve == nil {
		return nil, errors.New("Couldn't retrieve EC point and EC parameters")
	}

	x, y := elliptic.Unmarshal(pubKey.Curve, pointBytes)
	if x == nil {
		// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/os/pkcs11-curr-v2.40-os.html#_ftn1
		// PKCS#11 v2.20 specified that the CKA_EC_POINT was to be stored in a DER-encoded
		// OCTET STRING.
		var point asn1.RawValue
		_, err = asn1.Unmarshal(pointBytes, &point)
		if err != nil {
			return nil, fmt.Errorf("Failed to unmarshal returned CKA_EC_POINT: %s", err)
		}
		if len(point.Bytes) == 0 {
			return nil, errors.New("Invalid CKA_EC_POINT value returned, OCTET string is empty")
		}
		x, y = elliptic.Unmarshal(pubKey.Curve, point.Bytes)
		if x == nil {
			return nil, errors.New("Invalid CKA_EC_POINT value returned, point is malformed")
		}
	}
	pubKey.X, pubKey.Y = x, y

	return pubKey, nil
}

// Check the public part of the key exists by label and/or ID
func (p *Pkcs11Client) ExistsPublicKey(keyConfig *KeyConfig) (exists bool, err error) {
	attribs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
	}

	var fullAttribs []*pkcs11.Attribute
	if fullAttribs, err = (*keyConfig).appendKeyIdentity(attribs); err != nil {
		return
	}
	var objHandles []pkcs11.ObjectHandle
	if objHandles, err = p.FindObjects(fullAttribs, 1); err != nil {
		return false, nil
	}
	if len(objHandles) > 0 {
		exists = true
	} else {
		exists = false
	}
	return
}

func (p *Pkcs11Client) ReadExistsPublicKey(keyConfig *KeyConfig) (publicKey []byte, err error) {

	attribs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
	}

	var fullAttribs []*pkcs11.Attribute
	if fullAttribs, err = (*keyConfig).appendKeyIdentity(attribs); err != nil {
		return
	}
	var objHandles []pkcs11.ObjectHandle
	if objHandles, err = p.FindObjects(fullAttribs, 1); err != nil {
		return
	}

	attrs, err := p.context.GetAttributeValue(p.session, objHandles[0], []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
	})
	if err != nil {
		return
	}
	if len(attrs) == 1 && attrs[0].Type == pkcs11.CKA_VALUE {
		return attrs[0].Value, nil
	}
	return nil, errors.New("GetAttributeValue error")

}

// Fetch the key handles if exist
func (p *Pkcs11Client) FetchKeyPairHandles(keyConfig *KeyConfig) (privKeyHandle *[]pkcs11.ObjectHandle, pubKeyHandle *[]pkcs11.ObjectHandle, err error) {

	pubAttribs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
	}

	var fullPubAttribs []*pkcs11.Attribute
	if fullPubAttribs, err = (*keyConfig).appendKeyIdentity(pubAttribs); err != nil {
		return
	}

	var pubObjHandles []pkcs11.ObjectHandle
	if pubObjHandles, err = p.FindObjects(fullPubAttribs, 1); err != nil {
		return
	}
	pubKeyHandle = &pubObjHandles

	privAttribs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
	}

	var fullPrivAttribs []*pkcs11.Attribute
	if fullPrivAttribs, err = (*keyConfig).appendKeyIdentity(privAttribs); err != nil {
		return
	}

	var privObjHandles []pkcs11.ObjectHandle
	if privObjHandles, err = p.FindObjects(fullPrivAttribs, 1); err != nil {
		return
	}
	privKeyHandle = &privObjHandles
	return
}

// first see if the key already exists, whether identified by ID or by LABEL
func (p *Pkcs11Client) CheckExistsCreateKeyPair(keyConfig *KeyConfig) error {
	return p.checkExistsCreateKeyPair(keyConfig, false)
}

func (p *Pkcs11Client) CheckExistsOkCreateKeyPair(keyConfig *KeyConfig) error {
	return p.checkExistsCreateKeyPair(keyConfig, true)
}

func (p *Pkcs11Client) checkExistsCreateKeyPair(keyConfig *KeyConfig, okExists bool) error {

	if !keyConfig.checkNewKeyIntegrity() {
		return errors.New(ERR_NEWKEYINTEGRITY)
	}

	if exists, err := p.ExistsPublicKey(keyConfig); err != nil || exists {
		if exists {
			if okExists {
				return nil
			} else {
				return errors.New(ERR_NEWKEYALREADYEXISTS)
			}
		} else {
			return err
		}
	}
	return p.createKeyPair(keyConfig)
}

// No existence check here, which means a new key can be created with the same label but a different ID
func (p *Pkcs11Client) CreateKeyPair(keyConfig *KeyConfig) error {

	if !keyConfig.checkNewKeyIntegrity() {
		return errors.New(ERR_NEWKEYALREADYEXISTS)
	}
	return p.createKeyPair(keyConfig)
}

// https://github.com/ThalesIgnite/crypto11/blob/cloudhsm/rsa.go#L83
func (p *Pkcs11Client) createKeyPair(keyConfig *KeyConfig) error {

	keyTemplates := GenKeyConfigKeyPairTemplate(keyConfig)
	keyTemplates.GenDefaultKeyPairTemplateForSigning()
	privAttribs, pubAttribs, err := keyTemplates.GenKeyPairTemplateAttribs()
	if err != nil {
		return err
	}

	mech, err := genKeyGenMechanismById(keyConfig.Type)

	if err != nil {
		return err
	}
	if _, _, err = p.context.GenerateKeyPair(p.session, mech, pubAttribs, privAttribs); err != nil {
		return err
	}
	return nil
}

func (p *Pkcs11Client) DeleteKeyPair(keyConfig *KeyConfig) (err error) {

	privKeyHandle, pubKeyHandle, err := p.FetchKeyPairHandles(keyConfig)

	if pubKeyHandle != nil && len(*pubKeyHandle) > 0 {
		err = p.context.DestroyObject(p.session, (*pubKeyHandle)[0])
	}
	if privKeyHandle != nil && len(*privKeyHandle) > 0 {
		err = p.context.DestroyObject(p.session, (*privKeyHandle)[0])
	}

	return
}

// get the public key from the HSM and generate the subjectKeyID from it for CA cert gen
func (p *Pkcs11Client) GetGenSubjectKeyId(keyConfig *KeyConfig, keyType uint) (subjectKeyId []byte, publicKey crypto.PublicKey, err error) {

	switch keyType {
	case pkcs11.CKK_ECDSA:
		publicKey, err = p.ReadECPublicKey(keyConfig)
	case pkcs11.CKK_RSA:
		publicKey, err = p.ReadRSAPublicKey(keyConfig)
	default:
		return nil, nil, errors.New("Only EC or RSA keys are supported")
	}

	if err != nil {
		return
	}
	subjectKeyId, err = GenSubjectKeyID(publicKey)
	return
}
