# pkcs11helper Setup HSMs

Go [PKCS#11](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html) helper module for certificate signing using HSMs

## Dependencies

### OpenSSL

[OpenSSL](https://www.openssl.org/) includes a conf file commonly found under Linux in /etc/ssl/openssl.cnf that is used to configure the HSM engines

On Ubuntu install the follwing packages:

[OpenSSL](https://packages.ubuntu.com/focal/openssl)

[OpenSSL PKCS#11 engine](https://packages.ubuntu.com/focal/libengine-pkcs11-openssl)

### pkcs11-tool

Part of the [OpenSC](https://github.com/OpenSC/OpenSC) project. 

Install on [Ubuntu](http://manpages.ubuntu.com/manpages/focal/man1/pkcs11-tool.1.html).

## End Entity

The End Entity may be eg. a web server.

### Create Private Key for End Entity

`openssl genrsa -out localhost.key 2048`


### Generate CSR for End Entity Certificate

`openssl req -sha512 -key ./localhost.key -new -out localhost512.csr.pem`

## HSMs

### SoftHSM

[SoftHSM](https://github.com/opendnssec/SoftHSMv2) is a software based HSM developed as part of the [OpenDNSSec](https://www.opendnssec.org/) project.

#### Dependencies

On Ubuntu, install the following packages:

[softhsm2](https://packages.ubuntu.com/focal/softhsm2)

[softhsm2-common](https://packages.ubuntu.com/focal/softhsm2-common)

[libsofthsm2](https://packages.ubuntu.com/focal/libsofthsm2)


#### Configuration

##### SoftHSM2 Conf

On installation the default token can be seen, though may need to be run as root:

`softhsm2-util --show-slots`

```Available slots:
Slot 0
Slot info:
Description:      SoftHSM slot ID 0x0                                             
Manufacturer ID:  SoftHSM project                 
Hardware version: 2.6
Firmware version: 2.6
Token present:    yes
Token info:
Manufacturer ID:  SoftHSM project                 
Model:            SoftHSM v2      
Hardware version: 2.6
Firmware version: 2.6
Serial number:                    
Initialized:      no
User PIN init.:   no
Label:                   
```

Initialise the token:

`softhsm2-util --init-token --slot 0 --label "token0" --pin 1234 --so-pin 1234`

A slot number will be generated:

`The token has been initialized and is reassigned to slot 1601805484`

show-slots will now provide the new slot's details:

`softhsm2-util --show-slots`

```
Available slots:
Slot 1601805484
Slot info:
Description:      SoftHSM slot ID 0x5f799cac                                      
Manufacturer ID:  SoftHSM project                 
Hardware version: 2.6
Firmware version: 2.6
Token present:    yes
Token info:
Manufacturer ID:  SoftHSM project                 
Model:            SoftHSM v2      
Hardware version: 2.6
Firmware version: 2.6
Serial number:    58bc41dc5f799cac
Initialized:      yes
User PIN init.:   yes
Label:            token0
```


##### OpenSSL Engine Configuration

/etc/ssl/openssl.cnf needs this section at the top:

```
openssl_conf = openssl_init

[openssl_init]
engines=engine_section

[engine_section]
pkcs11 = pkcs11_section

[pkcs11_section]
engine_id = pkcs11
dynamic_path = /usr/lib/x86_64-linux-gnu/engines-1.1/libpkcs11.so
MODULE_PATH = /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
init = 1601805484    # this is the SoftHSM slot ID
```


#### Commands

##### Show Slots

`softhsm2-util --show-slots`

or

`pkcs11-tool --module=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so -L`

##### List Keys

`pkcs11-tool --module=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --slot 1601805484 --login -O`

##### Signing

###### Gen Root and Intermediate CA RSA Keys

`pkcs11-tool --module=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --slot 1601805484 --login --keypairgen --key-type rsa:4096 --label "RSATestCARootKey0001" --id "0001"`

`pkcs11-tool --module=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --slot 1601805484 --login --keypairgen --key-type rsa:2048 --label "RSATestCAInterKey0002" --id "0002"`

###### Gen Root CA Cert

`openssl req -new -x509 -days 3560 -sha512 -extensions v3_ca  -engine pkcs11 -keyform engine -key 1601805484:0001 -out softhsm-root-0001.ca.cert.pem -set_serial 5000`

###### Gen Intermediate CA CSR

`openssl req -new -sha512 -engine pkcs11 -keyform engine -key "1601805484:0002" -out softhsm-inter-0002.ca.csr.pem`

###### Create OpenSSL demoCA directory

```
mkdir -p /etc/ssl/private/demoCA/newcerts
touch demaCA/index.txt
echo "1000" > demoCA/serial
```

###### Sign Intermediate CA CSR

`openssl ca -days 3650 -md sha512 -notext -extensions v3_intermediate_ca -engine pkcs11 -keyform engine -keyfile 1601805484:0001 -in softhsm-inter-0002.ca.csr.pem -out softhsm-inter-0002.ca.cert.pem -cert softhsm-root-0001.ca.cert.pem -noemailDN`

###### Extract the CA's public key

`pkcs11-tool --module=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --slot 1601805484 --login -r -y pubkey -a "RSATestCAInterKey0002" -o softhsm-inter-0002.ca.pub.der`

The signed Intermediate CA is now ready for use with [TESTING](TESTING.md)


##### Encryption

###### Create RSA Key

`pkcs11-tool --module=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --slot 1601805484 --login --keypairgen --key-type rsa:4096 --label "RSATestKey0020" --id "0020"`

###### Create EC Key

`pkcs11-tool --module=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --slot 1601805484 --login --keypairgen --key-type EC:prime384v1 --label "ECDSATestKey0021" --id "0021"`

###### Encryption test

`openssl pkeyutl -encrypt -engine pkcs11 -keyform engine -inkey 1601805484:0020 -in ./test.txt -out ./test.enc`

###### Decryption test

`openssl pkeyutl -decrypt -engine pkcs11 -keyform engine -inkey 1601805484:0020 -in ./test.enc -out ./testdec.txt`


### SafeNet DPoD

#### Configuration

##### SafeNet Configuration

Using a SafeNet DPoD account, download the installation files.

All of the following commands need a shell where the DPoD environment has been included using the source command:

```
cd /yoursafenetdpodpath
. ./setenv
```

If you are using an IDE then source this script in a terminal and then start the IDE from the terminal.
The unit tests should then work with debug enabled within the IDE.

##### OpenSSL Engine Configuration

```
openssl_conf = openssl_init

[openssl_init]
engines=engine_section

[engine_section]
pkcs11 = pkcs11_section

[pkcs11_section]
engine_id = pkcs11
dynamic_path = /usr/lib/x86_64-linux-gnu/engines-1.1/libpkcs11.so
MODULE_PATH = /yoursafenetpath/libs/64/libCryptoki2.so
```

#### Commands

##### List Keys
`pkcs11-tool --module=/opt/apps/safenet/dpod/current/libs/64/libCryptoki2.so --login --login-type user --slot 3 -O`

##### Signing

```
...the value of the "id" attribute can contain non-textual data.  
This is because the corresponding PKCS#11 "CKA_ID" object attribute can contain arbitrary binary data.
```

###### Gen Root and Intermediate CA RSA Keys

`pkcs11-tool --module=/opt/apps/safenet/dpod/current/libs/64/libCryptoki2.so --login --login-type user --slot 3 --keypairgen --key-type rsa:4096 --label RSATestCARootKey0001 --id 1`

`pkcs11-tool --module=/opt/apps/safenet/dpod/current/libs/64/libCryptoki2.so --login --login-type user --slot 3 --keypairgen --key-type rsa:2048 --label RSATestCAInterKey0002 --id 2`

###### Extract the Root and Intermediate CAs' public keys

`pkcs11-tool --module=/opt/apps/safenet/dpod/current/libs/64/libCryptoki2.so --login --login-type user --slot 3 --id 1 --type pubkey -r -o safenet-root-01.ca.pub.der`

`pkcs11-tool --module=/opt/apps/safenet/dpod/current/libs/64/libCryptoki2.so --login --login-type user --slot 3 --id 2 --type pubkey -r -o safenet-inter-02.ca.pub.der`

###### Convert the Root and Intermediate CAs' public keys to PEM format

`openssl rsa -pubin -inform DER -in ./safenet-root-01.ca.pub.der -out ./safenet-root-01.ca.pub.pem`

`openssl rsa -pubin -inform DER -in ./safenet-inter-02.ca.pub.der -out ./safenet-inter-02.ca.pub.pem`

###### Gen Root CA Cert

`openssl req -new -x509 -days 7300 -sha512 -extensions v3_ca -engine pkcs11 -keyform engine -key "pkcs11:id=%01" -out safenet-root-01.ca.cert.pem -set_serial 5000`

###### Gen Intermediate CA CSR

`openssl req -new -sha512 -engine pkcs11 -keyform engine -key "pkcs11:id=%02" -out safenet-inter-02.ca.csr.pem`

###### Sign Intermediate CA CSR

`openssl ca -days 3650 -md sha512 -notext -extensions v3_intermediate_ca -engine pkcs11 -keyform engine -keyfile "pkcs11:id=%01" -in safenet-inter-02.ca.csr.pem -out safenet-inter-02.ca.cert.pem -cert safenet-root-01.ca.cert.pem -noemailDN`


###### Gen Root and Intermediate CA ECDSA Keys

`pkcs11-tool --module=/opt/apps/safenet/dpod/current/libs/64/libCryptoki2.so --login --login-type user --slot 3 --keypairgen --key-type EC:secp521r1 --label ECTestCARootKey03 --id 3`

`pkcs11-tool --module=/opt/apps/safenet/dpod/current/libs/64/libCryptoki2.so --login --login-type user --slot 3 --keypairgen --key-type EC:secp384r1 --label ECTestCAInterKey04 --id 4`

###### Extract the Root and Intermediate CAs' public keys

`pkcs11-tool --module=/opt/apps/safenet/dpod/current/libs/64/libCryptoki2.so --login --login-type user --slot 3 --id 3 --type pubkey -r -o safenet-root-03.ca.pub.der`

`pkcs11-tool --module=/opt/apps/safenet/dpod/current/libs/64/libCryptoki2.so --login --login-type user --slot 3 --id 4 --type pubkey -r -o safenet-inter-04.ca.pub.der`

###### Convert the Root and Intermediate CAs' public keys to PEM format

`openssl ec -pubin -inform DER -in ./safenet-root-03.ca.pub.der -out ./safenet-root-03.ca.pub.pem`

`openssl ec -pubin -inform DER -in ./safenet-inter-04.ca.pub.der -out ./safenet-inter-04.ca.pub.pem`

###### Gen Root CA Cert

`openssl req -new -x509 -days 7300 -sha512 -extensions v3_ca -engine pkcs11 -keyform engine -key "pkcs11:id=%03" -out safenet-root-03.ca.cert.pem -set_serial 5010`

###### Gen Intermediate CA CSR

`openssl req -new -sha512 -engine pkcs11 -keyform engine -key "pkcs11:id=%04" -out safenet-inter-04.ca.csr.pem`

###### Sign Intermediate CA CSR

`openssl ca -days 3650 -md sha512 -notext -extensions v3_intermediate_ca -engine pkcs11 -keyform engine -keyfile "pkcs11:id=%03" -in safenet-inter-04.ca.csr.pem -out safenet-inter-04.ca.cert.pem -cert safenet-root-03.ca.cert.pem -noemailDN`


##### Encryption

###### Create RSA key
`pkcs11-tool --module=/opt/apps/safenet/dpod/current/libs/64/libCryptoki2.so --login --login-type user --slot 3 --keypairgen --key-type rsa:2048 --label RSATestKey0020 --id "0020"`

###### Create EC key
`pkcs11-tool --module=/opt/apps/safenet/dpod/current/libs/64/libCryptoki2.so --login --login-type user --slot 3 --keypairgen --key-type EC:secp384r1 --label ECTestKey0014 --id 30303134`

###### Encryption test
`openssl pkeyutl -encrypt -engine pkcs11 -keyform engine -inkey "pkcs11:id=0007;type=public;" -in ./test.txt -out ./testsafe.enc`

###### Decryption test
`openssl pkeyutl -decrypt -engine pkcs11 -keyform engine -inkey "pkcs11:id=0007;type=private;" -in ./testsafe.enc -out ./testsafe.dec`


### Entrust nShield

```
openssl_conf = openssl_init

[openssl_init]
engines=engine_section

[engine_section]
pkcs11 = pkcs11_section

[pkcs11_section]
engine_id = pkcs11
dynamic_path = /usr/lib/x86_64-linux-gnu/engines-1.1/libpkcs11.so
MODULE_PATH = /opt/apps/nfast/20201219/bin/libcknfast.so
```

#### Commands

##### nCipher Encryption Test
`openssl pkeyutl -encrypt -engine pkcs11 -keyform engine -inkey "pkcs11:id=%61%02%1f%1f%ed%1e%fc%39%f9%d6%0f%28%9b%d5%5f%e9%78%91%6c%e9;type=public;" -in ./test.txt -out ./testncipher.enc`

##### nCipher Decryption Test
`openssl pkeyutl -decrypt -engine pkcs11 -keyform engine -inkey "pkcs11:id=%61%02%1f%1f%ed%1e%fc%39%f9%d6%0f%28%9b%d5%5f%e9%78%91%6c%e9;type=public;" -in ./testncipher.enc -out ./testncipher.dec`

##### OpenSSL Gen Root CA Cert
`openssl req -new -x509 -days 7300 -sha512 -extensions v3_ca -engine pkcs11 -keyform engine -key "pkcs11:id=%61%02%1f%1f%ed%1e%fc%39%f9%d6%0f%28%9b%d5%5f%e9%78%91%6c%e9;type=public;" -out ncipher-root-0005.ca.cert.pem -set_serial 5001`

##### OpenSSL Gen Intermediate CA CSR
`openssl req -new -sha512 -engine pkcs11 -keyform engine -key "pkcs11:id=%88%d8%42%c8%6f%7a%49%ae%92%be%d6%0f%3b%e7%41%51%94%27%69%86" -out ncipher-inter-0006.ca.csr.pem`

##### OpenSSL Sign Intermediate CA CSR
`openssl ca -days 3650 -md sha512 -notext -extensions v3_intermediate_ca -engine pkcs11 -keyform engine -keyfile "pkcs11:id=%61%02%1f%1f%ed%1e%fc%39%f9%d6%0f%28%9b%d5%5f%e9%78%91%6c%e9" -in ncipher-inter-0006.ca.csr.pem -out ncipher-inter-0006.ca.cert.pem -cert ncipher-root-0005.ca.cert.pem -noemailDN`

##### Extract the Intermediate CA's public key
`pkcs11-tool --module=/opt/apps/nfast/20201219/bin/libcknfast.so --id "61021f1fed1efc39f9d60f289bd55fe978916ce9" --type pubkey -r -o /tmp/ncipher-inter.ca.pub.der`
