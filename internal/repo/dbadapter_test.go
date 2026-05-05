package repo

import (
	"context"
	"testing"

	sdk "github.com/elloloop/tenant-shard-db/sdk/go/entdb"
)

func TestNewDBAdapter_NilClient(t *testing.T) {
	t.Parallel()

	if _, err := NewDBAdapter(nil); err == nil {
		t.Fatal("NewDBAdapter(nil) succeeded, want error")
	}
}

func TestNewDBAdapter_DelegatesToClientTransport(t *testing.T) {
	t.Parallel()

	client, err := sdk.NewClient("localhost:50051")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	db, err := NewDBAdapter(client)
	if err != nil {
		t.Fatalf("NewDBAdapter: %v", err)
	}

	if _, err := db.GetNode(context.Background(), "tenant-1", "user:alice", 1, "node-1"); err == nil {
		t.Fatal("GetNode without Connect succeeded, want connection error")
	}
}
