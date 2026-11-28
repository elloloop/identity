package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
)

// memberEditableSettings is the part of a project's config_json its own
// members may read and change through the console (ADR-0022). A section
// mapped to nil is editable whole; a section mapped to field names is
// editable in those fields only, and its other fields stay the operator's.
//
// Everything absent from this table is the operator's alone. It is an allow
// list on purpose: a config section added later is closed to members until
// someone decides it is theirs. What is left out today, and why:
//
//   - oauth carries provider secrets and the hub-sharing switch, which lends a
//     project the deployment's own OAuth clients (ADR-0011).
//   - accounts.domain makes the server issue, and mail, addresses on a domain
//     nobody has proven the project controls.
//   - branding, email_delivery and phone decide what the deployment's mail and
//     message senders put their name to.
//   - passkey, assurance and products bind the project to app and relying-party
//     identities an operator vouches for.
var memberEditableSettings = map[string][]string{
	"access":          nil,
	"accounts":        {"email_signup", "username_signup"},
	"age_gate":        nil,
	"anonymous":       nil,
	"cors":            nil,
	"guardian":        nil,
	"jurisdictions":   nil,
	"login":           nil,
	"recovery_emails": nil,
	"tenants":         nil,
}

// sectionsUnderProductGuardrails are the member-editable sections a
// project's product guardrails are built on. A guardrail (config_json
// products, the operator's) refuses a product to accounts below an age band;
// which band an account falls in is jurisdictions, and whether its age is
// known at all is age_gate. A member who lowered a threshold, or stopped
// asking for a date of birth, would let every account through a guardrail
// the operator set, so while a project has one these sections are the
// operator's too.
var sectionsUnderProductGuardrails = []string{"age_gate", "jurisdictions"}

// jsonNull is the JSON literal that clears a section to its default.
const jsonNull = "null"

// emptyJSONObject is the config of a project that has set nothing.
const emptyJSONObject = "{}"

// jsonZeroValues are the JSON encodings of the zero value of a config
// field's type: what the field holds when its key is absent.
var jsonZeroValues = []string{jsonNull, "false", "0", `""`, "[]", emptyJSONObject}

// ErrProjectConfigAmbiguous is returned when a member's write would have to
// merge into a section the stored config spells more than one way. The
// parser reads every spelling, in an order the merge cannot reproduce, so
// the write is refused rather than guessed at; the project's operator
// rewrites the config with one spelling. Mapped to CodeFailedPrecondition.
var ErrProjectConfigAmbiguous = errors.New("the project's stored config spells a section more than one way; its operator must correct it")

// MemberSettings returns the member-editable part of a project's config_json
// as a JSON object, read through the config parser: each editable section,
// and of a field-restricted section only its editable fields, under the
// names and with the values ParseProjectConfig gives them. A field at its
// default is absent, and so is a section with none set, since to the parser
// an absent key and a zero value are the same thing.
//
// It is the parsed config, not the stored text, on purpose. encoding/json
// reads keys without regard to case, so a stored "Access", or an
// "access"."Mode", governs sign-in as surely as the canonical spelling does;
// a view cut from the text could show a member one value while the server
// enforced another. Reading through the parser makes what a member sees
// exactly what is in force.
func MemberSettings(configJSON string) (string, error) {
	parsed, err := parseStoredConfig(configJSON)
	if err != nil {
		return "", err
	}
	sections, err := configSections(parsed)
	if err != nil {
		return "", fmt.Errorf("stored project config: %w", err)
	}

	out := make(map[string]json.RawMessage, len(memberEditableSettings))
	for section, fields := range memberEditableSettings {
		values, err := nonZeroFields(sections[section])
		if err != nil {
			return "", fmt.Errorf("stored project config: section %s: %w", section, err)
		}
		if fields != nil {
			for field := range values {
				if !slices.Contains(fields, field) {
					delete(values, field)
				}
			}
		}
		if len(values) == 0 {
			continue
		}
		encoded, err := json.Marshal(values)
		if err != nil {
			return "", fmt.Errorf("stored project config: section %s: %w", section, err)
		}
		out[section] = encoded
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		return "", fmt.Errorf("stored project config: %w", err)
	}
	return string(encoded), nil
}

// ApplyMemberSettings writes settingsJSON's sections over configJSON and
// returns the resulting config with the sorted names of the sections whose
// stored value changed. A section present replaces that section, or its
// editable fields where the section is field-restricted; a section set to
// null is cleared; a section absent is untouched, as is everything that is
// not member-editable.
//
// Section and restricted-field names are matched exactly, so "OAuth" or
// "accounts.Domain" is refused, not folded onto a name the config parser
// would read it as: encoding/json matches keys without regard to case, and
// an allow list that did the same would let a member reach a field by
// spelling it differently. For the same reason a write removes every other
// spelling of the section or field it sets, and a whole section is stored as
// the parser read it (canonicalSection), so the value written is the one the
// parser reads.
//
// It returns ErrInvalidArgument for settings that are not a JSON object,
// that name something not editable, or that hold a key the config does not
// have, and ErrProjectConfigAmbiguous for a field-restricted section the
// stored config spells more than one way, whose operator fields it could not
// carry over faithfully. It does not judge the result: the caller validates
// the returned config as any other config write.
func ApplyMemberSettings(configJSON, settingsJSON string) (next string, changed []string, err error) {
	stored, err := parseStoredConfig(configJSON)
	if err != nil {
		return "", nil, err
	}
	config, err := decodeJSONObject(configJSON)
	if err != nil {
		return "", nil, fmt.Errorf("stored project config: %w", err)
	}
	if strings.TrimSpace(settingsJSON) == "" {
		return "", nil, fmt.Errorf("%w: settings_json is required", ErrInvalidArgument)
	}
	settings, err := decodeJSONObject(settingsJSON)
	if err != nil {
		return "", nil, fmt.Errorf("%w: settings_json: %s", ErrInvalidArgument, err.Error())
	}

	sections := make([]string, 0, len(settings))
	for section := range settings {
		sections = append(sections, section)
	}
	sort.Strings(sections)

	guarded := hasProductGuardrails(stored)
	for _, section := range sections {
		fields, editable := memberEditableSettings[section]
		if !editable {
			return "", nil, fmt.Errorf("%w: %q is not a setting a project's members can change", ErrInvalidArgument, section)
		}
		if guarded && slices.Contains(sectionsUnderProductGuardrails, section) {
			return "", nil, fmt.Errorf("%w: %q is the operator's to change while the project has product age guardrails", ErrInvalidArgument, section)
		}
		spellings := foldedKeys(config, section)
		if fields != nil && len(spellings) > 1 {
			return "", nil, fmt.Errorf("%w: %s", ErrProjectConfigAmbiguous, section)
		}
		var before json.RawMessage
		if len(spellings) > 0 {
			before = config[spellings[0]]
		}
		after, err := mergeSection(section, fields, before, settings[section])
		if err != nil {
			return "", nil, err
		}
		for _, spelled := range spellings {
			delete(config, spelled)
		}
		if after != nil {
			config[section] = after
		}
		// Collapsing several spellings into one changes what the parser reads
		// even when the value written equals one of them.
		if len(spellings) > 1 || !sameJSON(before, after) {
			changed = append(changed, section)
		}
	}

	encoded, err := json.Marshal(config)
	if err != nil {
		return "", nil, fmt.Errorf("project config: %w", err)
	}
	return string(encoded), changed, nil
}

// parseStoredConfig parses a project's stored config, which is blank for a
// project that has set nothing.
func parseStoredConfig(configJSON string) (ProjectConfig, error) {
	if strings.TrimSpace(configJSON) == "" {
		configJSON = emptyJSONObject
	}
	parsed, err := ParseProjectConfig(configJSON)
	if err != nil {
		return ProjectConfig{}, fmt.Errorf("stored project config: %w", err)
	}
	return parsed, nil
}

// hasProductGuardrails reports whether any of the project's products refuses
// accounts below an age band. A product configured for its branding alone
// imposes no guardrail.
func hasProductGuardrails(cfg ProjectConfig) bool {
	for _, product := range cfg.Products {
		if product.MinimumAgeBand != "" {
			return true
		}
	}
	return false
}

// mergeSection returns what section holds after a member writes value to it:
// nil when the section ends up unset. fields is the section's editable field
// list, nil when the whole section is editable.
func mergeSection(section string, fields []string, stored, value json.RawMessage) (json.RawMessage, error) {
	if fields == nil {
		return canonicalSection(section, value)
	}

	kept := map[string]json.RawMessage{}
	if len(stored) > 0 && !isJSONNull(stored) {
		var err error
		if kept, err = decodeJSONObject(string(stored)); err != nil {
			return nil, fmt.Errorf("stored project config: section %s: %w", section, err)
		}
	}
	// The write replaces the editable fields, so each is dropped first: one
	// the member left out is cleared, as a whole section's absent field is.
	for _, field := range fields {
		deleteFold(kept, field)
	}
	if !isJSONNull(value) {
		written, err := decodeJSONObject(string(value))
		if err != nil {
			return nil, fmt.Errorf("%w: settings_json: section %s: %s", ErrInvalidArgument, section, err.Error())
		}
		for field, v := range written {
			if !slices.Contains(fields, field) {
				return nil, fmt.Errorf("%w: %q is not a setting a project's members can change", ErrInvalidArgument, section+"."+field)
			}
			if !isJSONNull(v) {
				kept[field] = v
			}
		}
	}
	if len(kept) == 0 {
		return nil, nil
	}
	encoded, err := json.Marshal(kept)
	if err != nil {
		return nil, fmt.Errorf("project config: section %s: %w", section, err)
	}
	return encoded, nil
}

// canonicalSection returns a member's value for a whole section as the
// config parser reads it: decoded into the config's own type and written
// back under its canonical field names, with fields at their default left
// out. nil when nothing is set.
//
// A member's JSON is not stored as sent. Two keys that differ only in case
// name one field, and which of them wins depends on their order, which the
// store does not keep (a jsonb column reorders an object's keys). Stored as
// sent, a section could be validated under one reading and enforced under
// another. Stored as parsed, it has one reading. A key the config does not
// have is refused rather than dropped, so a member is never told a setting
// was saved that this server does not read.
func canonicalSection(section string, value json.RawMessage) (json.RawMessage, error) {
	if isJSONNull(value) {
		return nil, nil
	}
	wrapped, err := json.Marshal(map[string]json.RawMessage{section: value})
	if err != nil {
		return nil, fmt.Errorf("%w: settings_json: section %s: %s", ErrInvalidArgument, section, err.Error())
	}
	var cfg ProjectConfig
	dec := json.NewDecoder(bytes.NewReader(wrapped))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("%w: settings_json: section %s: %s", ErrInvalidArgument, section, err.Error())
	}
	sections, err := configSections(cfg)
	if err != nil {
		return nil, fmt.Errorf("project config: section %s: %w", section, err)
	}
	values, err := nonZeroFields(sections[section])
	if err != nil {
		return nil, fmt.Errorf("project config: section %s: %w", section, err)
	}
	if len(values) == 0 {
		return nil, nil
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		return nil, fmt.Errorf("project config: section %s: %w", section, err)
	}
	return encoded, nil
}

// configSections returns cfg's sections keyed by their canonical names, each
// as the JSON its own type encodes to.
func configSections(cfg ProjectConfig) (map[string]json.RawMessage, error) {
	encoded, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	return decodeJSONObject(string(encoded))
}

// nonZeroFields decodes a section and drops each field whose value is the
// zero value of its type. It looks at the section's own fields only: a
// nested object is kept or dropped whole, never pruned.
func nonZeroFields(section json.RawMessage) (map[string]json.RawMessage, error) {
	fields, err := decodeJSONObject(string(section))
	if err != nil {
		return nil, err
	}
	for field, value := range fields {
		if isJSONZero(value) {
			delete(fields, field)
		}
	}
	return fields, nil
}

// decodeJSONObject decodes text as exactly one JSON object. Blank text is the
// empty object, as a project with no config stores "{}".
func decodeJSONObject(text string) (map[string]json.RawMessage, error) {
	if strings.TrimSpace(text) == "" {
		return map[string]json.RawMessage{}, nil
	}
	dec := json.NewDecoder(strings.NewReader(text))
	var object map[string]json.RawMessage
	if err := dec.Decode(&object); err != nil {
		return nil, errors.New("must be a JSON object")
	}
	if object == nil {
		return nil, errors.New("must be a JSON object")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("must be a single JSON object")
	}
	return object, nil
}

// deleteFold removes every spelling of key from object.
func deleteFold(object map[string]json.RawMessage, key string) {
	for _, spelled := range foldedKeys(object, key) {
		delete(object, spelled)
	}
}

// foldedKeys lists, in a stable order, object's keys that encoding/json would
// decode into a field tagged key.
func foldedKeys(object map[string]json.RawMessage, key string) []string {
	var spelled []string
	for k := range object {
		if strings.EqualFold(k, key) {
			spelled = append(spelled, k)
		}
	}
	sort.Strings(spelled)
	return spelled
}

func isJSONNull(raw json.RawMessage) bool {
	return string(bytes.TrimSpace(raw)) == jsonNull
}

// isJSONZero reports whether raw is one of jsonZeroValues.
func isJSONZero(raw json.RawMessage) bool {
	return slices.Contains(jsonZeroValues, string(bytes.TrimSpace(raw)))
}

// sameJSON reports whether two raw values are the same JSON, ignoring
// insignificant whitespace. Unset and null are the same: both leave the
// section at its default.
func sameJSON(a, b json.RawMessage) bool {
	return compactJSON(a) == compactJSON(b)
}

func compactJSON(raw json.RawMessage) string {
	if len(raw) == 0 || isJSONNull(raw) {
		return ""
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return string(raw)
	}
	return buf.String()
}
