package pkcs11client

import (
	"encoding/json"
	"errors"
	"os"
)

type HsmConfig struct {
	// the HSM's client PKCS#11 library
	Lib string

	// the HSM slot ID
	SlotId uint `json:"slot_id"`

	// the slot pin
	Pin string

	// a key label
	KeyLabel string `json:"key_label"`

	// connection timeout seconds
	ConnectTimeoutS uint `json:"connect_timeout_s"`

	// function timeout seconds
	ReadTimeoutS uint `json:"read_timeout_s"`
}

const (
	DEFAULT_CONNECTTIMEOUTS = 30
	DEFAULT_READTIMEOUTS    = 30
)

func ParseHsmConfig(filename string) (*HsmConfig, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, errors.New("Unable to open conf file ")
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	config := HsmConfig{}
	err = decoder.Decode(&config)
	if err != nil {
		return nil, errors.New("Unable to decode conf file: " + err.Error())
	}
	err = config.ValidateConfig()
	if err != nil {
		return nil, err
	}
	return &config, nil
}

// Only check the presence of the client lib
// the slot could be 0, the pin could be blank and the key label could be set dynamically
func (h *HsmConfig) ValidateConfig() error {
	if len((*h).Lib) == 0 {
		return errors.New("Please specify the path of the PKCS#11 client library")
	} else {
		return nil
	}
}

func (h *HsmConfig) CheckSetDefaultTimeouts() {
	if h.ConnectTimeoutS == 0 {
		h.ConnectTimeoutS = DEFAULT_CONNECTTIMEOUTS
	}
	if h.ReadTimeoutS == 0 {
		h.ReadTimeoutS = DEFAULT_READTIMEOUTS
	}
	return
}
