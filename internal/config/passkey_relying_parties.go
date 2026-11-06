package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"

	"github.com/elloloop/identity/internal/origin"
)

// PasskeyRelyingParty is the WebAuthn relying party of one public auth host.
type PasskeyRelyingParty struct {
	// Host is the public auth host a request arrives on: a lower-case DNS name
	// with no scheme, port or path.
	Host string `json:"host"`
	// RPID is the relying-party id, a registrable suffix of Host and of every
	// entry in Origins.
	RPID string `json:"rp_id"`
	// RPName is shown in the platform's passkey dialog. Empty means
	// GATEWAY_PASSKEY_RP_NAME.
	RPName string `json:"rp_name"`
	// Origins are the origins a ceremony may run on: the pages that run it in a
	// browser, and https://<rp_id> for an Apple native app, whose platform
	// reports that origin for itself. An Android native app reports an
	// android:apk-key-hash: origin, which this setting does not accept.
	Origins []string `json:"origins"`
}

// ValidatePasskeyRelyingParties parses GATEWAY_PASSKEY_RELYING_PARTIES and holds
// each entry to the rule a browser and a platform authenticator enforce during
// a ceremony, so a mistake stops the server at boot rather than failing every
// sign-in on one host. Validate runs it.
func (c *Config) ValidatePasskeyRelyingParties() error {
	c.passkeyRelyingParties = nil
	if c.PasskeyRelyingPartiesJSON == "" {
		return nil
	}
	parties, err := parsePasskeyRelyingParties(c.PasskeyRelyingPartiesJSON)
	if err != nil {
		return fmt.Errorf("config: GATEWAY_PASSKEY_RELYING_PARTIES: %w", err)
	}
	c.passkeyRelyingParties = parties
	return nil
}

// PasskeyRelyingPartiesConfigured reports whether the operator chose relying
// parties per host, in which case a host with no entry has no relying party:
// it never falls back to GATEWAY_PASSKEY_RP_ID. It reads the raw setting, so a
// Config that skipped validation fails closed rather than falling back.
func (c *Config) PasskeyRelyingPartiesConfigured() bool {
	return c.PasskeyRelyingPartiesJSON != ""
}

// PasskeyRelyingPartyForHost returns the entry for a request's host.
func (c *Config) PasskeyRelyingPartyForHost(host string) (PasskeyRelyingParty, bool) {
	party, ok := c.passkeyRelyingParties[host]
	return party, ok
}

// PasskeyRelyingPartyHosts returns the configured hosts in a stable order.
func (c *Config) PasskeyRelyingPartyHosts() []string {
	hosts := make([]string, 0, len(c.passkeyRelyingParties))
	for host := range c.passkeyRelyingParties {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	return hosts
}

func parsePasskeyRelyingParties(raw string) (map[string]PasskeyRelyingParty, error) {
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	var entries []PasskeyRelyingParty
	if err := dec.Decode(&entries); err != nil {
		return nil, fmt.Errorf("must be a JSON array of {host, rp_id, rp_name, origins}: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("must hold one JSON array and nothing after it")
	}
	if len(entries) == 0 {
		return nil, errors.New("must name at least one host; unset it to use GATEWAY_PASSKEY_RP_ID for every host")
	}
	parties := make(map[string]PasskeyRelyingParty, len(entries))
	for i, entry := range entries {
		if err := entry.validate(); err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
		if _, dup := parties[entry.Host]; dup {
			return nil, fmt.Errorf("entry %d: host %q is listed twice", i, entry.Host)
		}
		parties[entry.Host] = entry
	}
	return parties, nil
}

func (p PasskeyRelyingParty) validate() error {
	if !origin.IsDNSName(p.Host) {
		return fmt.Errorf("host %q must be a lower-case DNS name with no scheme, port or path", p.Host)
	}
	if !origin.IsRegistrableSuffix(p.RPID, p.Host) {
		return fmt.Errorf("rp_id %q must be a registrable suffix of host %q", p.RPID, p.Host)
	}
	if len(p.Origins) == 0 {
		return fmt.Errorf("host %q must list at least one origin", p.Host)
	}
	for _, raw := range p.Origins {
		hostname, err := ceremonyOriginHost(raw)
		if err != nil {
			return fmt.Errorf("host %q: origin %q %w", p.Host, raw, err)
		}
		if !origin.IsRegistrableSuffix(p.RPID, hostname) {
			return fmt.Errorf("host %q: rp_id %q must be a registrable suffix of origin %q", p.Host, p.RPID, raw)
		}
	}
	return nil
}

// ceremonyOriginHost returns the hostname of an origin written exactly as a
// browser reports it, since WebAuthn compares the two as strings.
func ceremonyOriginHost(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("is not a URL")
	}
	if u.Scheme != "https" && (u.Scheme != "http" || !isLoopbackHost(u.Hostname())) {
		return "", errors.New("must be https (http only on a loopback host)")
	}
	if u.Hostname() == "" || u.Scheme+"://"+strings.ToLower(u.Host) != raw {
		return "", errors.New("must be a lower-case scheme://host[:port] with nothing after it")
	}
	if !origin.IsSerializedPort(u) {
		return "", errors.New("must carry its port as a browser does: none when it is the scheme's default, and no leading zeros")
	}
	return u.Hostname(), nil
}
