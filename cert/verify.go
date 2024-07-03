package cert

import (
	"crypto/x509"

	"github.com/veraison/ccatoken"
)

type Evidence struct {
	ccatoken.Evidence
}

func (o *Evidence) VerifyWithCert(cert *x509.Certificate) error {
	return o.Verify(cert.PublicKey)
}

