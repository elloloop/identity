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

// jsonNull is the JSON literal that clears a section to its default.
const jsonNull = "null"

// MemberSettings returns the member-editable part of a project's config_json
// as a JSON object: each editable section the config sets, and of a
// field-restricted section only its editable fields. A section the config
// does not set is absent.
func MemberSettings(configJSON string) (string, error) {
	config, err := decodeJSONObject(configJSON)
	if err != nil {
		return "", fmt.Errorf("stored project config: %w", err)
	}
	out := make(map[string]json.RawMessage, len(memberEditableSettings))
	for section, fields := range memberEditableSettings {
		raw, ok := lookupFold(config, section)
		if !ok || isJSONNull(raw) {
			continue
		}
		if fields == nil {
			out[section] = raw
			continue
		}
		stored, err := decodeJSONObject(string(raw))
		if err != nil {
			return "", fmt.Errorf("stored project config: section %s: %w", section, err)
		}
		visible := make(map[string]json.RawMessage, len(fields))
		for _, field := range fields {
			if v, ok := lookupFold(stored, field); ok {
				visible[field] = v
			}
		}
		if len(visible) == 0 {
			continue
		}
		encoded, err := json.Marshal(visible)
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
// Keys are matched exactly, so "OAuth" or "accounts.Domain" is refused, not
// folded onto a name the config parser would read it as: encoding/json
// matches keys without regard to case, and an allow list that did the same
// would let a member reach a field by spelling it differently. For the same
// reason a write removes every other spelling of the section or field it
// sets, so the value written is the one the parser reads.
//
// It returns ErrInvalidArgument for settings that are not a JSON object or
// that name something not editable. It does not judge the result: the caller
// validates the returned config as any other config write.
func ApplyMemberSettings(configJSON, settingsJSON string) (next string, changed []string, err error) {
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

	for _, section := range sections {
		fields, editable := memberEditableSettings[section]
		if !editable {
			return "", nil, fmt.Errorf("%w: %q is not a setting a project's members can change", ErrInvalidArgument, section)
		}
		before, _ := lookupFold(config, section)
		after, err := mergeSection(section, fields, before, settings[section])
		if err != nil {
			return "", nil, err
		}
		deleteFold(config, section)
		if after != nil {
			config[section] = after
		}
		if !sameJSON(before, after) {
			changed = append(changed, section)
		}
	}

	encoded, err := json.Marshal(config)
	if err != nil {
		return "", nil, fmt.Errorf("project config: %w", err)
	}
	return string(encoded), changed, nil
}

// mergeSection returns what section holds after a member writes value to it:
// nil when the section ends up unset. fields is the section's editable field
// list, nil when the whole section is editable.
func mergeSection(section string, fields []string, stored, value json.RawMessage) (json.RawMessage, error) {
	if fields == nil {
		if isJSONNull(value) {
			return nil, nil
		}
		return value, nil
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

// lookupFold returns object's value for key, preferring the exact spelling
// and otherwise the spelling encoding/json would read as key.
func lookupFold(object map[string]json.RawMessage, key string) (json.RawMessage, bool) {
	if v, ok := object[key]; ok {
		return v, true
	}
	for _, spelled := range foldedKeys(object, key) {
		return object[spelled], true
	}
	return nil, false
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
