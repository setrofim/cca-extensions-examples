package cert

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func readCert(path string) (*x509.Certificate, error) {
	rawCert, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(rawCert)
	return x509.ParseCertificate(block.Bytes)
}

func readToken(path string) (*Evidence, error) {
	rawToken, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var token Evidence
	if err := token.FromCBOR(rawToken); err != nil {
		return nil, err
	}

	return &token, nil
}

func Test_VerifyWithCert(t *testing.T) {
	token, err := readToken("data/token.cbor")
	require.NoError(t, err)

	cert, err := readCert("data/cert.crt")
	require.NoError(t, err)

	spew.Dump(token)

	err = token.VerifyWithCert(cert)
	assert.NoError(t, err)
}
