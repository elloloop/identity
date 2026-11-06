package config

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidatePasskeyRelyingParties_Unset(t *testing.T) {
	t.Parallel()
	c := &Config{}
	require.NoError(t, c.ValidatePasskeyRelyingParties())
	assert.False(t, c.PasskeyRelyingPartiesConfigured())
}

func TestValidatePasskeyRelyingParties_ParsesEntries(t *testing.T) {
	t.Parallel()
	c := &Config{PasskeyRelyingPartiesJSON: `[
		{"host": "auth.acme.example", "rp_id": "acme.example", "rp_name": "Acme", "origins": ["https://acme.example", "https://accounts.acme.example"]},
		{"host": "acme.example", "rp_id": "acme.example", "origins": ["https://acme.example:8443"]},
		{"host": "localhost", "rp_id": "localhost", "origins": ["http://localhost:3000"]}
	]`}
	require.NoError(t, c.ValidatePasskeyRelyingParties())
	assert.True(t, c.PasskeyRelyingPartiesConfigured())

	party, ok := c.PasskeyRelyingPartyForHost("auth.acme.example")
	require.True(t, ok)
	assert.Equal(t, "acme.example", party.RPID)
	assert.Equal(t, "Acme", party.RPName)
	assert.Equal(t, []string{"https://acme.example", "https://accounts.acme.example"}, party.Origins)

	_, ok = c.PasskeyRelyingPartyForHost("auth.other.example")
	assert.False(t, ok)
}

func TestValidatePasskeyRelyingParties_Refuses(t *testing.T) {
	t.Parallel()
	tests := map[string]struct{ raw, want string }{
		"not json":             {`nope`, "JSON array"},
		"an object":            {`{"host":"auth.acme.example"}`, "JSON array"},
		"unknown field":        {`[{"host":"auth.acme.example","rp_id":"acme.example","origins":["https://acme.example"],"rpid":"x"}]`, "JSON array"},
		"data after the array": {`[{"host":"auth.acme.example","rp_id":"acme.example","origins":["https://acme.example"]}] []`, "nothing after"},
		"empty list":           {`[]`, "at least one host"},
		"no host":              {`[{"rp_id":"acme.example","origins":["https://acme.example"]}]`, "DNS name"},
		"upper-case host":      {`[{"host":"Auth.acme.example","rp_id":"acme.example","origins":["https://acme.example"]}]`, "lower-case DNS"},
		"host with a port":     {`[{"host":"auth.acme.example:443","rp_id":"acme.example","origins":["https://acme.example"]}]`, "DNS name"},
		"host with a scheme":   {`[{"host":"https://auth.acme.example","rp_id":"acme.example","origins":["https://acme.example"]}]`, "DNS name"},
		"duplicate host":       {`[{"host":"auth.acme.example","rp_id":"acme.example","origins":["https://acme.example"]},{"host":"auth.acme.example","rp_id":"auth.acme.example","origins":["https://auth.acme.example"]}]`, "listed twice"},
		"no rp id":             {`[{"host":"auth.acme.example","origins":["https://acme.example"]}]`, "registrable suffix of host"},
		"rp id of another":     {`[{"host":"auth.acme.example","rp_id":"widgets.example","origins":["https://widgets.example"]}]`, "registrable suffix of host"},
		"rp id look-alike":     {`[{"host":"auth.notacme.example","rp_id":"acme.example","origins":["https://acme.example"]}]`, "registrable suffix of host"},
		"rp id public suffix":  {`[{"host":"auth.acme.co.uk","rp_id":"co.uk","origins":["https://acme.co.uk"]}]`, "registrable suffix of host"},
		"rp id below the host": {`[{"host":"acme.example","rp_id":"auth.acme.example","origins":["https://auth.acme.example"]}]`, "registrable suffix of host"},
		"rp id an ip":          {`[{"host":"127.0.0.1","rp_id":"127.0.0.1","origins":["http://127.0.0.1"]}]`, "registrable suffix of host"},
		"no origins":           {`[{"host":"auth.acme.example","rp_id":"acme.example"}]`, "at least one origin"},
		"origin elsewhere":     {`[{"host":"auth.acme.example","rp_id":"acme.example","origins":["https://widgets.example"]}]`, "registrable suffix of origin"},
		"http origin":          {`[{"host":"auth.acme.example","rp_id":"acme.example","origins":["http://acme.example"]}]`, "must be https"},
		"origin with a path":   {`[{"host":"auth.acme.example","rp_id":"acme.example","origins":["https://acme.example/"]}]`, "nothing after"},
		"upper-case origin":    {`[{"host":"auth.acme.example","rp_id":"acme.example","origins":["https://ACME.example"]}]`, "lower-case"},
		"origin with userinfo": {`[{"host":"auth.acme.example","rp_id":"acme.example","origins":["https://u@acme.example"]}]`, "nothing after"},
		"wildcard host":        {`[{"host":"auth.acme.example","rp_id":"acme.example","origins":["https://*.acme.example"]}]`, "wildcard"},
		"unicode host":         {`[{"host":"auth.acme.example","rp_id":"acme.example","origins":["https://bücher.acme.example"]}]`, "punycode"},
		"empty label":          {`[{"host":"auth.acme.example","rp_id":"acme.example","origins":["https://..acme.example"]}]`, "DNS name"},
		"unparsable origin":    {`[{"host":"auth.acme.example","rp_id":"acme.example","origins":["https://acme.example/%zz"]}]`, "origin"},
		"default https port":   {`[{"host":"auth.acme.example","rp_id":"acme.example","origins":["https://acme.example:443"]}]`, "port"},
		"default http port":    {`[{"host":"localhost","rp_id":"localhost","origins":["http://localhost:80"]}]`, "port"},
		"empty port":           {`[{"host":"auth.acme.example","rp_id":"acme.example","origins":["https://acme.example:"]}]`, "port"},
		"padded port":          {`[{"host":"auth.acme.example","rp_id":"acme.example","origins":["https://acme.example:0443"]}]`, "port"},
		"port out of range":    {`[{"host":"auth.acme.example","rp_id":"acme.example","origins":["https://acme.example:99999"]}]`, "port"},
		"android origin":       {`[{"host":"auth.acme.example","rp_id":"acme.example","origins":["android:apk-key-hash:abc"]}]`, "must be https"},
		"bare origin":          {`[{"host":"auth.acme.example","rp_id":"acme.example","origins":["acme.example"]}]`, "must be https"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c := &Config{PasskeyRelyingPartiesJSON: tc.raw}
			err := c.ValidatePasskeyRelyingParties()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "GATEWAY_PASSKEY_RELYING_PARTIES")
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestValidate_RefusesABadPasskeyRelyingParty(t *testing.T) {
	t.Parallel()
	c := &Config{PasskeyRelyingPartiesJSON: `[{"host":"auth.acme.example","rp_id":"widgets.example","origins":["https://widgets.example"]}]`}
	require.ErrorContains(t, c.Validate(), "GATEWAY_PASSKEY_RELYING_PARTIES")
}

func TestPasskeyRelyingPartyHosts_Sorted(t *testing.T) {
	t.Parallel()
	c := &Config{PasskeyRelyingPartiesJSON: `[
		{"host":"auth.widgets.example","rp_id":"widgets.example","origins":["https://widgets.example"]},
		{"host":"auth.acme.example","rp_id":"acme.example","origins":["https://acme.example"]}
	]`}
	if err := c.ValidatePasskeyRelyingParties(); err != nil {
		t.Fatal(err)
	}
	got := c.PasskeyRelyingPartyHosts()
	want := []string{"auth.acme.example", "auth.widgets.example"}
	if !slices.Equal(got, want) {
		t.Errorf("hosts = %v, want %v", got, want)
	}
}
