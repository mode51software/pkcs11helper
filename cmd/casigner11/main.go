package main

import (
	"flag"
	"fmt"
	"github.com/mode51software/pkcs11helper/internal/app"
	"github.com/mode51software/pkcs11helper/pkg/pkcs11client"
	"github.com/rs/zerolog/log"
	"math/rand"
	"os"
)

func init() {
	app.InitLogger()
}

const (
	// the JSON config file
	FLAG_HSMCONFIG = "hsmconfig"

	// the Certificate Signing Request
	FLAG_CSRFILE = "csr"

	// the validity period for the signed certificate
	FLAG_DAYS = "days"

	// the CA cert
	FLAG_CAFILE = "ca"

	// help
	FLAG_HELP = "help"

	USAGE string = "casigner\n" +
		"\t-" + FLAG_CAFILE + "=<cert authority file DER format>\n" +
		"\t-" + FLAG_CSRFILE + "=<cert signing request file DER format>\n" +
		"\t-" + FLAG_DAYS + "=<signed cert validity period>\n" +
		"\t-" + FLAG_HELP + "=help\n" +
		"\t-" + FLAG_HSMCONFIG + "=<conf file>\n"
)

// Supports either a conf file or args
func main() {

	// TODO: this is incomplete, use the test cases for now
	caSignerConfig, err := parseFlags()
	if err != nil {
		log.Error().Err(err).Msg("Error parsing command line args")
		exitUsage()
	} else {
		//	csr, err := pkcs11client.LoadCertRequestFromFile("./data/localhost.csr.der")
		csr, err := pkcs11client.LoadCertRequestFromFile(caSignerConfig.CSRFile)
		if err != nil {
			log.Error().Err(err)
			exitUsage()
		} else {
			log.Info().Msg("Loaded CSR with CN=" + csr.Subject.CommonName)

			// "./data/cacert.der"
			if caCert, err := pkcs11client.LoadCertFromFile(caSignerConfig.CAFile); err != nil {
				log.Error().Msg(err.Error())
			} else {
				log.Info().Msg("Loaded CA cert with CN=" + caCert.Subject.CommonName)

				if caPubKey, err := pkcs11client.LoadPubkeyFromFile("./data/capubkey.pem"); err != nil {
					log.Error().Msg(err.Error() + " check RSA in -----BEGIN RSA PUBLIC KEY-----")
				} else {
					log.Info().Msgf("Loaded CA pubkey with E=%d", caPubKey.E)

					_, err := pkcs11client.ParseHSMConfig(caSignerConfig.HSMConfigFile)
					if err != nil {
						panic(err)
					}

					hsmSigner := pkcs11client.HsmSigner{
						Pkcs11Client: pkcs11client.Pkcs11Client{},
						PublicKey:    caPubKey,
						KeyConfig: pkcs11client.KeyConfig{
							Label: "SSL Root CA 02",
						},
						Serial: rand.Int(),
					}

					if signedCsr, err := pkcs11client.GenSignedCert(csr, caCert, &hsmSigner); err != nil {
						log.Error().Msg(err.Error())
					} else {
						log.Info().Msg("Signed CSR with CN=" + signedCsr.Subject.CommonName)
						if err = pkcs11client.SaveCertToFile("./data/signedcert.der", signedCsr); err != nil {
							log.Error().Msg(err.Error())
						} else {
							log.Info().Msg("Saved signed cert")

						}
					}
				}
			}
		}
	}
}

func parseFlags() (caSignerConfig app.CASignerConfig, err error) {

	flag.StringVar(&(caSignerConfig.HSMConfigFile), FLAG_HSMCONFIG, "", "JSON HSM config file")
	flag.StringVar(&(caSignerConfig.CAFile), FLAG_CAFILE, "", "CA file")
	flag.StringVar(&(caSignerConfig.CSRFile), FLAG_CSRFILE, "", "Certificate Signing Request file DER encoded")
	flag.UintVar(&(caSignerConfig.Days), FLAG_DAYS, 365, "Validity period for signed certificate, defaults to 365 days")

	flag.Parse()

	// validate flags
	err = caSignerConfig.ValidateCASignerConfig()
	return
}

func exitUsage() {
	fmt.Println(USAGE)
	os.Exit(1)
}
