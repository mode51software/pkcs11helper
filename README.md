# pkcs11helper

Go [PKCS#11](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html) helper module for certificate signing using HSMs.


## Setup

The [Setup](SETUP.md) instructions help get an HSM up and running with a usable signed Intermediate CA.

SoftHSM2, Thales SafeNet DPoD and Entrust nShield HSMs are currently documented, though any PKCS#11 compliant HSM should work.

## Test

The casigner11 command line client is work in progress, as is this documentation.

Once the signed Intermediate issuing CA cert has been produced, use [TestCASigner](./pkg/pkcs11client/pkcs11_client_test.go) to try out the HSM signer.

Check [TESTING](TESTING.md) for more instructions. 

A [Vault plugin](https://github.com/mode51software/vaultplugin-hsmpki) is also available which uses this pkcs11helper 
module to add support for HSM backed PKI.

## License

HSM PKI for Vault was sponsored by [BT UK](https://www.globalservices.bt.com/en/aboutus/our-services/security) and developed by [mode51 Software](https://mode51.software) under the Mozilla Public License v2.

By [Chris Newman](https://mode51.software)