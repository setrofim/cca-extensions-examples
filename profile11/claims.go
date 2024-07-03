package profile11

import (
	"fmt"

	"github.com/veraison/ccatoken/platform"
	"github.com/veraison/eat"
	"github.com/veraison/psatoken"
)

const ProfileName = "http://arm.com/CCA-SSD/1.1.0"

type Profile struct{}

func (o Profile) GetName() string {
	return ProfileName
}

func (o Profile) GetClaims() psatoken.IClaims {
	return NewClaims()
}

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

	if err := psatoken.FilterError(o.GetCountersignerIDs()); err != nil {
		return err
	}

	if err := psatoken.FilterError(o.GetLFASupported()); err != nil {
		return err
	}

	return nil
}

func (o *SwComponentV11) SetCountersignerIDs(v [][]byte) error {
	for i, csID := range v {
		if err := psatoken.ValidatePSAHashType(csID); err != nil {
			return fmt.Errorf("bad countersigner id at index %d: %w", i, err)
		}
	}

	o.CountersignerIDs = &v

	return nil
}

func (o *SwComponentV11) SetLFASupported(v bool) error {
	o.LFASupported = &v

	return nil
}

func (o *SwComponentV11) GetCountersignerIDs() ([][]byte, error){
	if o.CountersignerIDs == nil {
		return nil, psatoken.ErrOptionalClaimMissing
	}

	for i, csID := range *o.CountersignerIDs {
		if err := psatoken.ValidatePSAHashType(csID); err != nil {
			return nil, fmt.Errorf("bad countersigner id at index %d: %w", i, err)
		}
	}

	return *o.CountersignerIDs, nil
}

func (o *SwComponentV11) GetLFASupported() (bool, error) {
	if o.LFASupported == nil {
		return false, psatoken.ErrOptionalClaimMissing
	}

	return *o.LFASupported, nil
}

func init() {
	if err := psatoken.RegisterProfile(Profile{}); err != nil {
		panic(err)
	}
}
