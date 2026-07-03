package scim

import (
	"encoding/json"
	"errors"
	"strings"
)

// PatchRequest is the SCIM PatchOp message (RFC 7644 §3.5.2). The provider
// supports the attribute set enterprises drive through PATCH — Microsoft Entra
// ID, for one, performs ALL profile updates (and de/re-provisioning) via PATCH
// replace, never PUT — so the mapped attributes (userName, emails/email, name,
// externalId, active) are all patchable. Operations targeting an attribute this
// server does not model are surfaced as errors rather than silently dropped.
type PatchRequest struct {
	Schemas    []string    `json:"schemas"`
	Operations []Operation `json:"Operations"`
}

// Operation is one entry in a PatchOp's Operations array.
type Operation struct {
	Op    string          `json:"op"`
	Path  string          `json:"path,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

// errNoSupportedPatch is returned when a PatchRequest carries no operation that
// touches an attribute this server models (so the caller can 400 rather than
// silently no-op).
var errNoSupportedPatch = errors.New("no supported attribute in patch")

// mutabilityError signals a PATCH operation that would remove/blank a required,
// login-identifier attribute (userName / email). The provider maps it to a SCIM
// 400 with scimType "mutability" (RFC 7644 §3.12) rather than silently clearing
// the account's only login identifier.
type mutabilityError struct{ detail string }

func (e *mutabilityError) Error() string { return e.detail }

// toUserPatch folds a PatchRequest's operations into a partial UserPatch. It
// handles the two shapes IdPs emit — a targeted op with a `path`
// (`{"op":"replace","path":"name.givenName","value":"Ada"}`) and a no-path op
// whose value is an attribute object (`{"op":"replace","value":{"active":false,
// "name":{"givenName":"Ada"}}}`) — for replace, add (treated as set), and
// remove (treated as clear). An operation targeting an unmodelled attribute, or
// a patch with no modelled attribute at all, is an error so the handler returns
// 400 instead of pretending success.
func (p PatchRequest) toUserPatch() (UserPatch, error) {
	var patch UserPatch
	touched := false
	for _, op := range p.Operations {
		opName := strings.ToLower(strings.TrimSpace(op.Op))
		switch opName {
		case "replace", "add", "remove":
		default:
			return UserPatch{}, errors.New("unsupported patch op: " + op.Op)
		}
		remove := opName == "remove"

		path := strings.TrimSpace(op.Path)
		if path == "" {
			// No path: the value is an object whose keys are attribute paths.
			var attrs map[string]json.RawMessage
			if err := json.Unmarshal(op.Value, &attrs); err != nil {
				return UserPatch{}, errors.New("patch operation without a path must carry an attribute object")
			}
			for attr, raw := range attrs {
				if err := applyPatchAttr(&patch, attr, raw, false); err != nil {
					return UserPatch{}, err
				}
				touched = true
			}
			continue
		}
		if err := applyPatchAttr(&patch, path, op.Value, remove); err != nil {
			return UserPatch{}, err
		}
		touched = true
	}
	if !touched {
		return UserPatch{}, errNoSupportedPatch
	}
	return patch, nil
}

// applyPatchAttr sets the field of patch named by attr from raw (or clears it
// when remove is true). attr is a SCIM attribute path (case-insensitive,
// optional filter brackets and schema-URN prefix stripped). An unmodelled
// attribute is an error.
func applyPatchAttr(patch *UserPatch, attr string, raw json.RawMessage, remove bool) error {
	switch normalizeAttrPath(attr) {
	case "active":
		if remove {
			return errors.New("the 'active' attribute cannot be removed")
		}
		b, err := decodeSCIMBool(raw)
		if err != nil {
			return err
		}
		patch.Active = &b
	case "username":
		if remove {
			return &mutabilityError{"userName cannot be removed: it is the required login identifier"}
		}
		patch.UserName = stringValue(raw, remove)
	case "externalid":
		patch.ExternalID = stringValue(raw, remove)
	case "email", "emails", "emails.value":
		if remove {
			return &mutabilityError{"email cannot be removed: it is the required login identifier"}
		}
		v, err := emailValue(raw, remove)
		if err != nil {
			return err
		}
		patch.Email = v
	case "name.givenname":
		patch.GivenName = stringValue(raw, remove)
	case "name.familyname":
		patch.FamilyName = stringValue(raw, remove)
	case "name.formatted", "displayname":
		given, family := splitName(stringOrEmpty(raw, remove))
		patch.GivenName = &given
		patch.FamilyName = &family
	case "name":
		// A whole-name object: {givenName, familyName, formatted}.
		if remove {
			empty := ""
			patch.GivenName, patch.FamilyName = &empty, &empty
			return nil
		}
		var n Name
		if err := json.Unmarshal(raw, &n); err != nil {
			return errors.New("name value must be an object")
		}
		if n.GivenName == "" && n.FamilyName == "" && n.Formatted != "" {
			g, f := splitName(n.Formatted)
			patch.GivenName, patch.FamilyName = &g, &f
		} else {
			patch.GivenName, patch.FamilyName = &n.GivenName, &n.FamilyName
		}
	default:
		return errors.New("unsupported patch attribute: " + attr)
	}
	return nil
}

// normalizeAttrPath lower-cases an attribute path and strips the SCIM
// schema-URN prefix and any value-selector filter brackets (e.g.
// `emails[type eq "work"].value` → `emails.value`) so the switch in
// applyPatchAttr matches the bare attribute path.
func normalizeAttrPath(attr string) string {
	attr = strings.TrimSpace(attr)
	if i := strings.LastIndex(attr, ":"); i >= 0 {
		// Strip a leading schema URN like
		// urn:ietf:params:scim:schemas:core:2.0:User:userName.
		attr = attr[i+1:]
	}
	for {
		open := strings.IndexByte(attr, '[')
		if open < 0 {
			break
		}
		rel := strings.IndexByte(attr[open:], ']')
		if rel < 0 {
			break
		}
		attr = attr[:open] + attr[open+rel+1:]
	}
	return strings.ToLower(strings.TrimSpace(attr))
}

// stringValue decodes a JSON string into a *string, or returns a pointer to ""
// when remove is true.
func stringValue(raw json.RawMessage, remove bool) *string {
	s := stringOrEmpty(raw, remove)
	return &s
}

func stringOrEmpty(raw json.RawMessage, remove bool) string {
	if remove || len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return strings.Trim(string(raw), `"`)
	}
	return s
}

// emailValue extracts an email from the several shapes SCIM clients send for
// the emails attribute: a bare string, an object {"value":...}, or an array of
// {value, primary} entries (primary wins, else first).
func emailValue(raw json.RawMessage, remove bool) (*string, error) {
	if remove || len(raw) == 0 {
		empty := ""
		return &empty, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return &s, nil
	}
	var one Email
	if err := json.Unmarshal(raw, &one); err == nil && one.Value != "" {
		return &one.Value, nil
	}
	var many []Email
	if err := json.Unmarshal(raw, &many); err == nil {
		v := primaryEmail(many)
		return &v, nil
	}
	return nil, errors.New("email value must be a string, an object, or an array")
}

// decodeSCIMBool parses the active value as a JSON boolean or, for
// interoperability with IdPs (Entra) that send it as a quoted string, the
// strings "true"/"false" (case-insensitive).
func decodeSCIMBool(raw json.RawMessage) (bool, error) {
	var b bool
	if err := json.Unmarshal(raw, &b); err == nil {
		return b, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "true":
			return true, nil
		case "false":
			return false, nil
		}
	}
	return false, errors.New("active value must be a boolean")
}
