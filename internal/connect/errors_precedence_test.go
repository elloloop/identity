package connect

import (
	"errors"
	"fmt"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

func TestToConnectErrorPreservesSentinelPrecedenceAndCompletionDetails(t *testing.T) {
	dob := &service.DOBRequiredError{Ticket: "dob-completion-ticket"}
	password := &service.PasswordChangeRequiredError{Ticket: "password-completion-ticket", SecondFactorRequired: true}
	cases := []struct {
		name   string
		err    error
		code   connect.Code
		detail proto.Message
	}{
		{"revision before not found", errors.Join(service.ErrNotFound, service.ErrOAuthClientRevision), connect.CodeAborted, nil},
		{"revision before fallback message", fmt.Errorf("user not found: %w", service.ErrOAuthClientRevision), connect.CodeAborted, nil},
		{"not found before completion", errors.Join(dob, service.ErrNotFound), connect.CodeNotFound, nil},
		{"ordinary precondition before completion", errors.Join(dob, service.ErrNoPasswordSet), connect.CodeFailedPrecondition, nil},
		{"step up before completion", errors.Join(password, service.ErrTotpRequired), connect.CodeFailedPrecondition, nil},
		{"DOB before password completion", errors.Join(password, dob), connect.CodeFailedPrecondition, &identitypb.DOBRequiredDetails{CompletionToken: dob.Ticket}},
		{"password completion before merge conflict", errors.Join(service.ErrMergeConflict, password), connect.CodeFailedPrecondition, &identitypb.PasswordChangeRequiredDetails{CompletionToken: password.Ticket, SecondFactorRequired: true}},
		{"wrapped DOB", fmt.Errorf("wrapped: %w", dob), connect.CodeFailedPrecondition, &identitypb.DOBRequiredDetails{CompletionToken: dob.Ticket}},
		{"wrapped password and second factor", fmt.Errorf("wrapped: %w", password), connect.CodeFailedPrecondition, &identitypb.PasswordChangeRequiredDetails{CompletionToken: password.Ticket, SecondFactorRequired: true}},
		{"plain DOB sentinel", service.ErrDOBRequired, connect.CodeFailedPrecondition, nil},
		{"empty DOB ticket", &service.DOBRequiredError{}, connect.CodeFailedPrecondition, nil},
		{"plain password sentinel", service.ErrPasswordChangeRequired, connect.CodeFailedPrecondition, nil},
		{"empty password ticket", &service.PasswordChangeRequiredError{SecondFactorRequired: true}, connect.CodeFailedPrecondition, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := toConnectError(tc.err)
			if got == nil || got.Code() != tc.code {
				t.Fatalf("code = %v, want %v", got, tc.code)
			}
			if !errors.Is(got.Unwrap(), tc.err) || got.Message() != tc.err.Error() {
				t.Fatal("the original error and message must remain unchanged")
			}
			if tc.detail == nil {
				if len(got.Details()) != 0 {
					t.Fatal("an earlier sentinel or missing ticket must not expose a completion detail")
				}
				return
			}
			if len(got.Details()) != 1 {
				t.Fatalf("details = %d, want one", len(got.Details()))
			}
			actual, err := got.Details()[0].Value()
			if err != nil || !proto.Equal(actual, tc.detail) {
				t.Fatalf("completion detail = %v, error %v, want %v", actual, err, tc.detail)
			}
		})
	}
}
