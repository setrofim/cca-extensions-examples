package profile11

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_CCAPlatform_FromJSON_ok(t *testing.T) {
	tv := `{
		"cca-platform-profile": "http://arm.com/CCA-SSD/1.1.0",
		"cca-platform-challenge":  "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
		"cca-platform-implementation-id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"cca-platform-instance-id": "AQICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC",
		"cca-platform-config": "AQID",
		"cca-platform-lifecycle": 12288,
		"cca-platform-sw-components": [
			  {
				"measurement-value": "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=",
				"signer-id": "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=",
				"countersigner-ids": [
					"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=",
					"BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ="
				],
				"live-fw-activation-supported": true
			  }
			],
		"cca-platform-service-indicator" : "https://veraison.example/v1/challenge-response",
		"cca-platform-hash-algo-id": "sha-256"
		}`

	c := NewClaims()

	err := c.FromJSON([]byte(tv))
	require.NoError(t, err)

	swComps, err := c.GetSoftwareComponents()
	require.NoError(t, err)

	swComp11, ok := swComps[0].(*SwComponentV11)
	require.True(t, ok)
	assert.True(t, *swComp11.LFASupported)
}

func Test_CCAPlatform_FromJSON_bad_countersigner(t *testing.T) {
	tv := `{
		"cca-platform-profile": "http://arm.com/CCA-SSD/1.1.0",
		"cca-platform-challenge":  "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
		"cca-platform-implementation-id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"cca-platform-lifecycle": 12288,
		"cca-platform-sw-components": [
			  {
				"measurement-value": "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=",
				"signer-id": "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=",
				"countersigner-ids": [
					"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=",
					"BAQE"
				],
				"live-fw-activation-supported": true
			  }
			]
		}`

	c := NewClaims()

	err := c.FromJSON([]byte(tv))
	assert.EqualError(t, err, "validation of CCA platform claims failed: validating software components: failed at index 0: bad countersigner id at index 1: wrong syntax: length 3 (hash MUST be 32, 48 or 64 bytes)")
}

