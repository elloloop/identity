package connect

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

// TestHandler_SetAccountMarket exercises the full RPC path: the caller's
// identity comes from the authenticated session, the market is canonicalized
// and stored, and the response carries the updated user.
func TestHandler_SetAccountMarket(t *testing.T) {
	h := newHarness(t)
	uid, err := h.repo.CreateUser(context.Background(), &service.User{
		Email: "user@example.com", Status: "active", Role: "member",
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}

	req := connect.NewRequest(&identitypb.SetAccountMarketRequest{Market: "us"})
	authedReq(req, uid)

	res, err := h.client.SetAccountMarket(context.Background(), req)
	if err != nil {
		t.Fatalf("SetAccountMarket: %v", err)
	}
	if got := res.Msg.User.GetMarket(); got != "US" {
		t.Fatalf("market = %q, want US (canonicalized)", got)
	}
	stored, err := h.repo.GetUser(context.Background(), uid)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if stored.Market != "US" {
		t.Fatalf("stored market = %q, want US", stored.Market)
	}
}

// TestHandler_SetAccountMarket_RequiresAuthenticatedSession proves the RPC
// refuses a request with no verified session — the account being changed is
// always the caller's own, taken from the session.
func TestHandler_SetAccountMarket_RequiresAuthenticatedSession(t *testing.T) {
	h := newHarness(t)

	req := connect.NewRequest(&identitypb.SetAccountMarketRequest{Market: "US"})
	if _, err := h.client.SetAccountMarket(context.Background(), req); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", connect.CodeOf(err))
	}
}

// TestHandler_SetAccountMarket_RejectsEmptyMarket pins the wire-level mapping
// of the service's validation failure to CodeInvalidArgument.
func TestHandler_SetAccountMarket_RejectsEmptyMarket(t *testing.T) {
	h := newHarness(t)
	uid, err := h.repo.CreateUser(context.Background(), &service.User{
		Email: "user@example.com", Status: "active", Role: "member",
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}

	req := connect.NewRequest(&identitypb.SetAccountMarketRequest{Market: "  "})
	authedReq(req, uid)
	if _, err := h.client.SetAccountMarket(context.Background(), req); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", connect.CodeOf(err))
	}
}

// TestConsentRecordToProto_Market pins the granted-under market snapshot onto
// the wire representation.
func TestConsentRecordToProto_Market(t *testing.T) {
	rec := &service.ParentalConsentRecord{ConsentID: "pc-1", Market: "IN"}
	if got := consentRecordToProto(rec).GetMarket(); got != "IN" {
		t.Fatalf("market = %q, want IN", got)
	}
}
