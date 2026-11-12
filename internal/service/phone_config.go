package service

import (
	"fmt"
	"strings"
)

// Delivery channels of a phone verification code, as named in a project's
// phone.channels.
const (
	// PhoneChannelSMS texts the code through the deployment's SMS provider
	// (GATEWAY_SMS_*).
	PhoneChannelSMS = "sms"
	// PhoneChannelMessage sends the code as a messaging-app template
	// message through the template sender the embedder wired.
	PhoneChannelMessage = "message"
)

// maxPhoneMessageTemplateLen bounds a template's name and language code.
const maxPhoneMessageTemplateLen = 128

// ProjectPhoneConfig is a project's policy for phone verification. The zero
// value is today's behaviour: verification is on wherever the deployment
// has an SMS provider (GATEWAY_SMS_ENABLED), codes go by SMS, a number may
// sit on any number of accounts, and every country is accepted. A project
// can only narrow that: it cannot turn on a channel the deployment has no
// sender for.
type ProjectPhoneConfig struct {
	// Enabled, when false, turns phone verification off for this project in
	// a deployment that has it on. Unset follows the deployment. True
	// changes nothing: a project cannot verify phones without a sender.
	Enabled *bool `json:"enabled,omitempty"`
	// Unique keeps a verified number on one account of the project: a
	// number another account holds is refused (ErrPhoneNumberTaken) until
	// that account removes it, or until ReassignAfterSeconds has passed.
	Unique bool `json:"unique"`
	// ReassignAfterSeconds lets a number move to another account that
	// proves it, this long after its holder verified it: carriers hand a
	// number its owner gave up to someone else. 0 (the default) means a
	// number moves only once released. Only valid with Unique.
	ReassignAfterSeconds int64 `json:"reassign_after_seconds"`
	// AllowedCallingCodes limits the numbers a code is sent to and stored
	// for to these country calling codes, as digits without the '+' ("91").
	// Empty accepts every country.
	AllowedCallingCodes []string `json:"allowed_calling_codes"`
	// Channels is the order in which the delivery channels are tried:
	// PhoneChannelSMS and PhoneChannelMessage. The first one the deployment
	// has a sender for and that accepts the message wins. Empty means SMS
	// only; a channel left out is never used.
	Channels []string `json:"channels"`
	// MessageTemplate and MessageLanguage name the template the message
	// channel sends, as registered with the provider; its one placeholder is
	// the code. MessageTemplate is required when Channels lists the message
	// channel.
	MessageTemplate string `json:"message_template"`
	MessageLanguage string `json:"message_language"`
}

func (c ProjectPhoneConfig) validate() error {
	if c.ReassignAfterSeconds < 0 {
		return fmt.Errorf("%w: phone.reassign_after_seconds must not be negative", ErrInvalidArgument)
	}
	if c.ReassignAfterSeconds > 0 && !c.Unique {
		return fmt.Errorf("%w: phone.reassign_after_seconds needs phone.unique", ErrInvalidArgument)
	}
	if err := validateCallingCodes("phone.allowed_calling_codes", c.AllowedCallingCodes); err != nil {
		return err
	}
	seen := map[string]struct{}{}
	for _, ch := range c.Channels {
		if ch != PhoneChannelSMS && ch != PhoneChannelMessage {
			return fmt.Errorf("%w: phone.channels: unknown channel %q (want %q or %q)",
				ErrInvalidArgument, ch, PhoneChannelSMS, PhoneChannelMessage)
		}
		if _, dup := seen[ch]; dup {
			return fmt.Errorf("%w: phone.channels lists %q twice", ErrInvalidArgument, ch)
		}
		seen[ch] = struct{}{}
	}
	for field, v := range map[string]string{"phone.message_template": c.MessageTemplate, "phone.message_language": c.MessageLanguage} {
		if v != strings.TrimSpace(v) || len(v) > maxPhoneMessageTemplateLen {
			return fmt.Errorf("%w: %s must have no surrounding space and be at most %d bytes",
				ErrInvalidArgument, field, maxPhoneMessageTemplateLen)
		}
	}
	if _, message := seen[PhoneChannelMessage]; message && c.MessageTemplate == "" {
		return fmt.Errorf("%w: phone.channels lists %q, which needs phone.message_template", ErrInvalidArgument, PhoneChannelMessage)
	}
	return nil
}

// validateCallingCodes checks each entry is a country calling code: one to
// three digits, not starting with 0, with no '+' and no repeats.
func validateCallingCodes(field string, codes []string) error {
	seen := map[string]struct{}{}
	for _, code := range codes {
		if len(code) < 1 || len(code) > 3 || code[0] == '0' || strings.Trim(code, "0123456789") != "" {
			return fmt.Errorf("%w: %s: %q is not a country calling code (1 to 3 digits, no '+')", ErrInvalidArgument, field, code)
		}
		if _, dup := seen[code]; dup {
			return fmt.Errorf("%w: %s lists %q twice", ErrInvalidArgument, field, code)
		}
		seen[code] = struct{}{}
	}
	return nil
}

// hasCallingCode reports whether the E.164 number phone starts with one of
// codes. Calling codes are prefix-free, so a prefix match is the country
// match. An empty list matches every number.
func hasCallingCode(phone string, codes []string) bool {
	if len(codes) == 0 {
		return true
	}
	for _, code := range codes {
		if strings.HasPrefix(phone, "+"+code) {
			return true
		}
	}
	return false
}

// off reports whether the project switched phone verification off.
func (c ProjectPhoneConfig) off() bool { return c.Enabled != nil && !*c.Enabled }

// channels is the delivery order, SMS alone when the project names none.
func (c ProjectPhoneConfig) channels() []string {
	if len(c.Channels) == 0 {
		return []string{PhoneChannelSMS}
	}
	return c.Channels
}

// takeOverBefore is the claim time before which another account's claim on
// a number is old enough to move at nowMs; 0 when no claim ever is.
func (c ProjectPhoneConfig) takeOverBefore(nowMs int64) int64 {
	if c.ReassignAfterSeconds <= 0 {
		return 0
	}
	return nowMs - c.ReassignAfterSeconds*1000 + 1
}

// phoneConfig is the request's project's phone policy; the zero policy when
// the request carries no project scope.
func phoneConfig(scope *ProjectScope) ProjectPhoneConfig {
	if scope == nil {
		return ProjectPhoneConfig{}
	}
	return scope.Phone
}

// normalizePhoneCallingCodes validates a login policy's comma-separated
// calling codes and returns them trimmed, in the order given.
func normalizePhoneCallingCodes(raw string) (string, error) {
	var codes []string
	for _, part := range strings.Split(raw, ",") {
		if code := strings.TrimSpace(part); code != "" {
			codes = append(codes, code)
		}
	}
	if err := validateCallingCodes("phone_calling_codes", codes); err != nil {
		return "", err
	}
	return strings.Join(codes, ","), nil
}

// phoneSatisfies reports whether user's verified phone meets a login
// policy's phone rule.
func phoneSatisfies(user *User, p *LoginPolicy) bool {
	if !user.PhoneVerified || user.PhoneNumber == "" {
		return false
	}
	if p.PhoneCallingCodes == "" {
		return true
	}
	return hasCallingCode(user.PhoneNumber, strings.Split(p.PhoneCallingCodes, ","))
}
