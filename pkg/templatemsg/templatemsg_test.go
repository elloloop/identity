package templatemsg

import (
	"errors"
	"testing"
)

func TestMessage_Validate(t *testing.T) {
	t.Parallel()
	ok := Message{To: "+14155550123", Template: "verification_code", Params: []string{"482915"}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("Validate(%+v): %v", ok, err)
	}
	for name, m := range map[string]Message{
		"no number":       {Template: "verification_code"},
		"no plus":         {To: "14155550123", Template: "verification_code"},
		"letters":         {To: "+1415555O123", Template: "verification_code"},
		"sixteen digits":  {To: "+1234567890123456", Template: "verification_code"},
		"no template":     {To: "+14155550123"},
		"blank template":  {To: "+14155550123", Template: "  "},
		"plus alone":      {To: "+", Template: "verification_code"},
		"spaces in digit": {To: "+1 415 555 0123", Template: "verification_code"},
	} {
		if err := m.Validate(); !errors.Is(err, ErrInvalidMessage) {
			t.Errorf("%s: want ErrInvalidMessage, got %v", name, err)
		}
	}
}
