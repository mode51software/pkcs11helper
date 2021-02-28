# Tests

## Signing

### TestCASigner

TODO: conf file

Configure the HSM in pkg/pkcs11client/pkcs11client_test.go

```
	pkcs11Client.HsmConfig = &HsmConfig{
		Lib:      			"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2",
		SlotId:   			1,
		Pin:      			"1234",
		ConnectTimeoutS: 	10,
		ReadTimeoutS: 		30,
	}
```

Convert the signed Intermediate CA to DER format and place in data/

`openssl x509 -in softhsm-inter-0002.ca.cert.pem -outform DER -out softhsm-inter-0002.ca.cert.der`

Also convert the CSR to DER format and place in data/

`openssl req -in localhost512.csr.pem` -outform DER -out localhost512.csr.der`

Copy the signed Intermediate CA's DER public key into data/ and convert to PEM:

`openssl rsa -pubin -inform DER -in softhsm-inter-0002.ca.pub.der -out softhsm-inter-0002.ca.pub.pem`


```
var caFiles = CASigningRequest {
    csrFile:      "../../data/localhost512.csr.der",
    caPubkeyFile: "../../data/softhsm-inter-0002.ca.pub.der",
    caCertFile:   "../../data/softhsm-inter-0002.ca.cert.der",
}
```


go test -v -run TestCASigner ./pkg/pkcs11client
