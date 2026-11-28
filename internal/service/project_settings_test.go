package service

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// decodeForTest decodes a JSON object into a comparable value.
func decodeForTest(t *testing.T, text string) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("decode %q: %v", text, err)
	}
	return out
}

func TestMemberSettings_ReturnsOnlyEditableSections(t *testing.T) {
	config := `{
		"access": {"mode": "open"},
		"tenants": {"self_service": true},
		"accounts": {"domain": "accounts.example.com", "email_signup": "self"},
		"oauth": {"google": {"client_id": "id", "client_secret_enc": "ciphertext"}},
		"branding": {"from": "team@example.com"},
		"passkey": {"rp_id": "example.com"}
	}`
	got, err := MemberSettings(config)
	if err != nil {
		t.Fatalf("MemberSettings: %v", err)
	}
	want := map[string]any{
		"access":   map[string]any{"mode": "open"},
		"tenants":  map[string]any{"self_service": true},
		"accounts": map[string]any{"email_signup": "self"},
	}
	if !reflect.DeepEqual(decodeForTest(t, got), want) {
		t.Fatalf("settings = %s, want %v", got, want)
	}
}

func TestMemberSettings_EmptyAndUnsetConfig(t *testing.T) {
	for _, config := range []string{
		"", "{}", `{"oauth": {}}`, `{"access": null}`, `{"accounts": {"domain": "accounts.example.com"}}`,
		// Every field at its default is a section with nothing set.
		`{"tenants": {"self_service": false}, "access": {"mode": "", "allowed_emails": [], "blocked_domains": null}, "recovery_emails": {"max": 0}}`,
	} {
		got, err := MemberSettings(config)
		if err != nil {
			t.Fatalf("MemberSettings(%q): %v", config, err)
		}
		if got != "{}" {
			t.Errorf("MemberSettings(%q) = %s, want {}", config, got)
		}
	}
}

// The config parser reads keys without regard to case, at every level, so a
// member is shown the parsed config under its canonical names: a section or a
// field an operator stored under another letter case governs sign-in, and is
// what the console shows.
func TestMemberSettings_ReadsTheSpellingTheParserReads(t *testing.T) {
	got, err := MemberSettings(`{"Access": {"Mode": "allowlist", "ALLOWED_DOMAINS": ["example.com"]}, "accounts": {"Email_Signup": "admin"}}`)
	if err != nil {
		t.Fatalf("MemberSettings: %v", err)
	}
	want := map[string]any{
		"access":   map[string]any{"mode": "allowlist", "allowed_domains": []any{"example.com"}},
		"accounts": map[string]any{"email_signup": "admin"},
	}
	if !reflect.DeepEqual(decodeForTest(t, got), want) {
		t.Fatalf("settings = %s, want %v", got, want)
	}
}

// When a stored config spells one section, or one field, more than one way,
// the parser settles which value is in force. Whatever it settles on is what
// a member is shown: the view is the parser's, never a second reading.
func TestMemberSettings_AgreesWithTheParserOnDuplicateSpellings(t *testing.T) {
	for _, config := range []string{
		`{"ACCESS": {"mode": "closed"}, "access": {"mode": "open"}}`,
		`{"access": {"mode": "open"}, "ACCESS": {"mode": "closed"}}`,
		`{"Access": {"mode": "allowlist"}, "access": {"allowed_domains": ["example.com"]}}`,
		`{"access": {"MODE": "closed", "mode": "open", "Mode": "invite"}}`,
		`{"Tenants": {"self_service": true}, "tenants": {"self_service": false}}`,
	} {
		enforced, err := ParseProjectConfig(config)
		if err != nil {
			t.Fatalf("ParseProjectConfig(%s): %v", config, err)
		}
		got, err := MemberSettings(config)
		if err != nil {
			t.Fatalf("MemberSettings(%s): %v", config, err)
		}
		shown, err := ParseProjectConfig(got)
		if err != nil {
			t.Fatalf("the settings shown for %s do not parse: %v", config, err)
		}
		if !reflect.DeepEqual(shown.Access, enforced.Access) || shown.Tenants != enforced.Tenants {
			t.Errorf("config %s: shown access %+v tenants %+v, enforced access %+v tenants %+v",
				config, shown.Access, shown.Tenants, enforced.Access, enforced.Tenants)
		}
	}
}

func TestMemberSettings_RejectsAStoredConfigThatIsNotAnObject(t *testing.T) {
	if _, err := MemberSettings(`[1,2]`); err == nil {
		t.Fatal("want an error for a stored config that is not an object")
	}
}

func TestApplyMemberSettings_ReplacesPresentSectionsAndKeepsTheRest(t *testing.T) {
	config := `{
		"access": {"mode": "allowlist", "allowed_domains": ["example.com"]},
		"tenants": {"self_service": true},
		"oauth": {"google": {"client_id": "id", "client_secret_enc": "ciphertext"}},
		"branding": {"from": "team@example.com"}
	}`
	next, changed, err := ApplyMemberSettings(config, `{"access": {"mode": "open"}, "anonymous": {"enabled": true}}`)
	if err != nil {
		t.Fatalf("ApplyMemberSettings: %v", err)
	}
	want := map[string]any{
		"access":    map[string]any{"mode": "open"},
		"anonymous": map[string]any{"enabled": true},
		"tenants":   map[string]any{"self_service": true},
		"oauth":     map[string]any{"google": map[string]any{"client_id": "id", "client_secret_enc": "ciphertext"}},
		"branding":  map[string]any{"from": "team@example.com"},
	}
	if !reflect.DeepEqual(decodeForTest(t, next), want) {
		t.Fatalf("config = %s, want %v", next, want)
	}
	if !reflect.DeepEqual(changed, []string{"access", "anonymous"}) {
		t.Errorf("changed = %v, want [access anonymous]", changed)
	}
}

func TestApplyMemberSettings_ReportsOnlySectionsWhoseValueChanged(t *testing.T) {
	config := `{"access": {"mode": "open"}, "tenants": {"self_service": true}}`
	_, changed, err := ApplyMemberSettings(config, `{"access": { "mode" : "open" }, "tenants": {"self_service": false}, "login": null}`)
	if err != nil {
		t.Fatalf("ApplyMemberSettings: %v", err)
	}
	if !reflect.DeepEqual(changed, []string{"tenants"}) {
		t.Errorf("changed = %v, want [tenants]: re-sending a value, or clearing an unset section, changes nothing", changed)
	}
}

func TestApplyMemberSettings_NullClearsASection(t *testing.T) {
	next, changed, err := ApplyMemberSettings(`{"access": {"mode": "open"}, "branding": {"from": "team@example.com"}}`, `{"access": null}`)
	if err != nil {
		t.Fatalf("ApplyMemberSettings: %v", err)
	}
	if want := map[string]any{"branding": map[string]any{"from": "team@example.com"}}; !reflect.DeepEqual(decodeForTest(t, next), want) {
		t.Fatalf("config = %s, want %v", next, want)
	}
	if !reflect.DeepEqual(changed, []string{"access"}) {
		t.Errorf("changed = %v, want [access]", changed)
	}
}

func TestApplyMemberSettings_RefusesWhatIsNotEditable(t *testing.T) {
	cases := map[string]string{
		"operator section":               `{"oauth": {"google": {"client_id": "theirs"}}}`,
		"operator section, other case":   `{"OAuth": {"google": {"client_id": "theirs"}}}`,
		"editable section, other case":   `{"Access": {"mode": "open"}}`,
		"unknown section":                `{"nonsense": {}}`,
		"branding":                       `{"branding": {"from": "anyone@example.com"}}`,
		"operator field":                 `{"accounts": {"domain": "example.com"}}`,
		"operator field, other case":     `{"accounts": {"Domain": "example.com"}}`,
		"operator field beside editable": `{"accounts": {"email_signup": "self", "domain": "example.com"}}`,
		"restricted section, not object": `{"accounts": "self"}`,
		"whole section, not object":      `{"access": "open"}`,
		"key the config does not have":   `{"access": {"mode": "open", "nonsense": true}}`,
		"nested key it does not have":    `{"jurisdictions": {"thresholds": {"US": {"child_max_age": 12, "adult_age": 18, "nonsense": 1}}}}`,
		"not an object":                  `["access"]`,
		"null":                           `null`,
		"blank":                          `  `,
		"two objects":                    `{"access": {"mode": "open"}} {"oauth": {}}`,
		"malformed":                      `{"access": `,
	}
	const config = `{"accounts": {"domain": "accounts.example.com"}, "oauth": {"google": {"client_id": "ours", "client_secret_enc": "ciphertext"}}}`
	for name, settings := range cases {
		t.Run(name, func(t *testing.T) {
			next, changed, err := ApplyMemberSettings(config, settings)
			if !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("err = %v, want ErrInvalidArgument (next=%q changed=%v)", err, next, changed)
			}
			if next != "" || changed != nil {
				t.Errorf("a refused write returned a config: next=%q changed=%v", next, changed)
			}
		})
	}
}

func TestApplyMemberSettings_RestrictedSectionKeepsOperatorFields(t *testing.T) {
	config := `{"accounts": {"domain": "accounts.example.com", "email_signup": "self", "username_signup": "admin"}}`

	// Present fields are written; an editable field left out is cleared, as a
	// whole section's absent field is; the operator's field stays.
	next, changed, err := ApplyMemberSettings(config, `{"accounts": {"email_signup": "admin"}}`)
	if err != nil {
		t.Fatalf("ApplyMemberSettings: %v", err)
	}
	want := map[string]any{"accounts": map[string]any{"domain": "accounts.example.com", "email_signup": "admin"}}
	if !reflect.DeepEqual(decodeForTest(t, next), want) {
		t.Fatalf("config = %s, want %v", next, want)
	}
	if !reflect.DeepEqual(changed, []string{"accounts"}) {
		t.Errorf("changed = %v, want [accounts]", changed)
	}

	// Clearing the section clears the editable fields only.
	next, _, err = ApplyMemberSettings(config, `{"accounts": null}`)
	if err != nil {
		t.Fatalf("ApplyMemberSettings(null): %v", err)
	}
	want = map[string]any{"accounts": map[string]any{"domain": "accounts.example.com"}}
	if !reflect.DeepEqual(decodeForTest(t, next), want) {
		t.Fatalf("config after clear = %s, want %v", next, want)
	}
}

// A write removes every other spelling of what it sets. encoding/json reads
// keys without regard to case, so a stale "Access" left beside the member's
// "access" could be the one the parser honours.
func TestApplyMemberSettings_WriteReplacesEverySpelling(t *testing.T) {
	next, _, err := ApplyMemberSettings(
		`{"Access": {"mode": "open"}, "ACCESS": {"mode": "open"}, "accounts": {"Email_Signup": "self", "Domain": "accounts.example.com"}}`,
		`{"access": {"mode": "closed"}, "accounts": {"email_signup": "off"}}`,
	)
	if err != nil {
		t.Fatalf("ApplyMemberSettings: %v", err)
	}
	want := map[string]any{
		"access":   map[string]any{"mode": "closed"},
		"accounts": map[string]any{"email_signup": "off", "Domain": "accounts.example.com"},
	}
	if !reflect.DeepEqual(decodeForTest(t, next), want) {
		t.Fatalf("config = %s, want %v", next, want)
	}
	parsed, err := ParseProjectConfig(next)
	if err != nil {
		t.Fatalf("ParseProjectConfig: %v", err)
	}
	if parsed.Access.Mode != "closed" {
		t.Errorf("parsed access mode = %q, want closed", parsed.Access.Mode)
	}
	if parsed.Accounts.Domain != "accounts.example.com" || parsed.Accounts.EmailSignup != "off" {
		t.Errorf("parsed accounts = %+v, want the operator's domain and the member's email_signup", parsed.Accounts)
	}
}

// A whole section is stored as the parser read it, not as it was sent. Two
// keys that differ only in case name one field, and which wins depends on
// their order, which the store does not keep; stored as sent, a section could
// be validated under one reading and enforced under another.
func TestApplyMemberSettings_StoresAWholeSectionAsParsed(t *testing.T) {
	const written = `{"access": {"Mode": "closed", "mode": "open", "ALLOWED_EMAILS": [], "block_public_email_domains": false}}`
	next, changed, err := ApplyMemberSettings(`{}`, written)
	if err != nil {
		t.Fatalf("ApplyMemberSettings: %v", err)
	}
	// What the parser makes of the member's own text is what must be stored.
	var sent struct {
		Access ProjectAccessConfig `json:"access"`
	}
	if err := json.Unmarshal([]byte(written), &sent); err != nil {
		t.Fatalf("decode the written section: %v", err)
	}
	want := map[string]any{"access": map[string]any{"mode": sent.Access.Mode}}
	if !reflect.DeepEqual(decodeForTest(t, next), want) {
		t.Fatalf("config = %s, want %v: one canonical key, defaults left out", next, want)
	}
	if !reflect.DeepEqual(changed, []string{"access"}) {
		t.Errorf("changed = %v, want [access]", changed)
	}

	// A section written with nothing but defaults is a section unset.
	next, changed, err = ApplyMemberSettings(`{"tenants": {"self_service": true}}`, `{"tenants": {"self_service": false}}`)
	if err != nil {
		t.Fatalf("ApplyMemberSettings(defaults): %v", err)
	}
	if next != "{}" {
		t.Errorf("config = %s, want {}", next)
	}
	if !reflect.DeepEqual(changed, []string{"tenants"}) {
		t.Errorf("changed = %v, want [tenants]", changed)
	}
}

// While a project has a product age guardrail, the sections it is built on
// are the operator's: a member who lowered a threshold, or stopped asking for
// a date of birth, would let every account through it. Other sections stay
// editable, and a product configured for its branding alone guards nothing.
func TestApplyMemberSettings_ProductGuardrailsHoldTheAgeSections(t *testing.T) {
	const guarded = `{"products": {"studio": {"minimum_age_band": "teen"}}, "jurisdictions": {"default": "US", "thresholds": {"US": {"child_max_age": 12, "adult_age": 18}}}, "age_gate": {"require_dob": true}}`
	for name, settings := range map[string]string{
		"lowering a threshold":         `{"jurisdictions": {"default": "US", "thresholds": {"US": {"child_max_age": 0, "adult_age": 1}}}}`,
		"clearing the thresholds":      `{"jurisdictions": null}`,
		"dropping the date of birth":   `{"age_gate": {"require_dob": false}}`,
		"beside an editable section":   `{"access": {"mode": "open"}, "age_gate": null}`,
		"re-sending the stored values": `{"age_gate": {"require_dob": true}}`,
	} {
		t.Run(name, func(t *testing.T) {
			next, changed, err := ApplyMemberSettings(guarded, settings)
			if !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("err = %v, want ErrInvalidArgument (next=%q changed=%v)", err, next, changed)
			}
			if next != "" || changed != nil {
				t.Errorf("a refused write returned a config: next=%q changed=%v", next, changed)
			}
		})
	}

	if _, changed, err := ApplyMemberSettings(guarded, `{"access": {"mode": "open"}, "guardian": {"require_step_up": true}}`); err != nil || !reflect.DeepEqual(changed, []string{"access", "guardian"}) {
		t.Errorf("sections no guardrail rests on: changed = %v, err = %v, want [access guardian]", changed, err)
	}

	const brandingOnly = `{"products": {"studio": {"branding": {"from": "studio@example.com"}}}}`
	if _, changed, err := ApplyMemberSettings(brandingOnly, `{"age_gate": {"require_dob": true}}`); err != nil || !reflect.DeepEqual(changed, []string{"age_gate"}) {
		t.Errorf("a product with no age band: changed = %v, err = %v, want [age_gate]", changed, err)
	}
}

// A field-restricted section the stored config spells more than one way is
// not merged into: the parser reads the operator's fields from every
// spelling, in an order the merge cannot reproduce, so the write is refused
// and the config left as it was. A whole section spelled twice is simply
// replaced, and counts as changed even when the value written equals one of
// the spellings, since the other one stops being read.
func TestApplyMemberSettings_DuplicateSectionSpellings(t *testing.T) {
	next, changed, err := ApplyMemberSettings(
		`{"Accounts": {"domain": "accounts.example.com"}, "accounts": {"email_signup": "self"}}`,
		`{"accounts": {"email_signup": "admin"}}`,
	)
	if !errors.Is(err, ErrProjectConfigAmbiguous) {
		t.Fatalf("err = %v, want ErrProjectConfigAmbiguous (next=%q changed=%v)", err, next, changed)
	}
	if next != "" || changed != nil {
		t.Errorf("a refused write returned a config: next=%q changed=%v", next, changed)
	}

	next, changed, err = ApplyMemberSettings(
		`{"Access": {"mode": "closed"}, "access": {"mode": "open"}}`,
		`{"access": {"mode": "open"}}`,
	)
	if err != nil {
		t.Fatalf("ApplyMemberSettings: %v", err)
	}
	if want := map[string]any{"access": map[string]any{"mode": "open"}}; !reflect.DeepEqual(decodeForTest(t, next), want) {
		t.Fatalf("config = %s, want %v", next, want)
	}
	if !reflect.DeepEqual(changed, []string{"access"}) {
		t.Errorf("changed = %v, want [access]", changed)
	}
}

// Every name in the allow list must be a section, or a field, the typed
// config really has: a typo would silently open a key the parser ignores and
// close the one that was meant.
func TestMemberEditableSettings_NameRealConfigFields(t *testing.T) {
	sections := jsonFieldTypes(reflect.TypeOf(ProjectConfig{}))
	for section, fields := range memberEditableSettings {
		sectionType, ok := sections[section]
		if !ok {
			t.Errorf("section %q is not a field of ProjectConfig", section)
			continue
		}
		known := jsonFieldTypes(sectionType)
		for _, field := range fields {
			if _, ok := known[field]; !ok {
				t.Errorf("field %q is not a field of section %q", field, section)
			}
		}
	}
}

// The sections that carry secrets, or bind the project to an identity the
// operator vouches for, stay out of members' reach.
func TestMemberEditableSettings_LeavesOperatorSectionsOut(t *testing.T) {
	for _, section := range []string{"oauth", "branding", "email_delivery", "phone", "passkey", "assurance", "products"} {
		if _, ok := memberEditableSettings[section]; ok {
			t.Errorf("section %q is member-editable; it is the operator's", section)
		}
	}
	if fields := memberEditableSettings["accounts"]; fields == nil || strings.Contains(strings.Join(fields, ","), "domain") {
		t.Errorf("accounts fields = %v: accounts.domain is the operator's", fields)
	}
}

// jsonFieldTypes maps a struct type's JSON field names to their types.
func jsonFieldTypes(t reflect.Type) map[string]reflect.Type {
	out := map[string]reflect.Type{}
	if t.Kind() != reflect.Struct {
		return out
	}
	for i := range t.NumField() {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name != "" && name != "-" {
			out[name] = f.Type
		}
	}
	return out
}
