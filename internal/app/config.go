package app

import "errors"

type CASignerConfig struct {

	// JSON config file containing HSM access details
	HSMConfigFile string

	// Certificate Signing Request (CSR) file DER encoded
	CSRFile string

	// Signed Certificate validity period
	Days uint

	// CA cert
	CAFile string
}

func (c *CASignerConfig) ValidateCASignerConfig() error {
	if len(c.HSMConfigFile) > 0 &&
		len(c.CSRFile) > 0 &&
		len(c.CAFile) > 0 {
		return nil
	}
	return errors.New("Please set HSM Config file, CSR file and CA Cert file")
}

//	confFile, err := os.Open(filename)
//	if err != nil { return err }
//	bufConfFile := bufio.NewReader(confFile)
//	hsmPkiConfig := HsmPkiConfig{}
//	if err = jsonutil.DecodeJSONFromReader(bufConfFile, hsmPkiConfig); err != nil { return err }
