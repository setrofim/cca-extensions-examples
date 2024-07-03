package claims11

import (
	"fmt"

	"github.com/veraison/ccatoken/platform"
	"github.com/veraison/eat"
	"github.com/veraison/psatoken"
)

const ProfileName = "http://arm.com/CCA-SSD/1.1.0"

func NewClaims() platform.IClaims {
	p := eat.Profile{}
	if err := p.Set(ProfileName); err != nil {
		// should never get here as using known good constant as input
		panic(err)
	}

	return &platform.Claims{
		Profile:      &p,
		SwComponents: &psatoken.SwComponents[*SwComponentV11]{},
		CanonicalProfile: ProfileName,
	}
}

type SwComponentV11 struct {
	psatoken.SwComponent

	LFASupported *bool `cbor:"7,keyasint,omitempty" json:"live-fw-activation-supported,omitempty"`
	CountersignerIDs *[][]byte `cbor:"8,keyasint,omitempty" json:"countersigner-ids,omitempty"`
}

func (o *SwComponentV11) Validate() error {
	if err := psatoken.ValidateSwComponent(o); err != nil {
		return err
	}

	if o.CountersignerIDs != nil {
		for i, csID := range *o.CountersignerIDs {
			if err := psatoken.ValidatePSAHashType(csID); err != nil {
				return fmt.Errorf("bad countersigner id at index %d: %w", i, err)
			}
		}
	}

	return nil
}

