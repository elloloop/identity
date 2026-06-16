package scim

import (
	"encoding/json"
	"errors"
	"strings"
)

// PatchRequest is the SCIM PatchOp message (RFC 7644 §3.5.2). The provider
// supports the single operation enterprises drive for deprovisioning:
// replacing the `active` attribute. Other paths are surfaced as errors by the
// handler rather than silently dropped.
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

// activeValue extracts the desired `active` state from the patch. It returns
// ok=false when no operation touches `active`, so the caller can reject an
// unsupported patch. Both shapes IdPs emit are handled:
//
//	{"op":"replace","path":"active","value":false}
//	{"op":"replace","value":{"active":false}}
func (p PatchRequest) activeValue() (active, ok bool, err error) {
	for _, op := range p.Operations {
		if !strings.EqualFold(op.Op, "replace") && !strings.EqualFold(op.Op, "add") {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(op.Path), "active") {
			var b bool
			if err := json.Unmarshal(op.Value, &b); err != nil {
				return false, false, errors.New("active value must be a boolean")
			}
			return b, true, nil
		}
		if strings.TrimSpace(op.Path) == "" && len(op.Value) > 0 {
			var m map[string]json.RawMessage
			if err := json.Unmarshal(op.Value, &m); err != nil {
				continue
			}
			if raw, present := m["active"]; present {
				var b bool
				if err := json.Unmarshal(raw, &b); err != nil {
					return false, false, errors.New("active value must be a boolean")
				}
				return b, true, nil
			}
		}
	}
	return false, false, nil
}
