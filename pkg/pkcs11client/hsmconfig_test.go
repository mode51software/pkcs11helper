package pkcs11client

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestParseConfig(t *testing.T) {
	_, err := ParseHsmConfig("../../conf/pkcs11-softhsm.cnf")
	assert.NoError(t, err)
}
