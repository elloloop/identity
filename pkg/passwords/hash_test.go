package passwords

import (
	"errors"
	"strings"
	"testing"
)

func TestHash_ReturnsValidBcrypt(t *testing.T) {
	hash, err := Hash("MyP@ssw0rd!")
	if err != nil {
		t.Fatalf("Hash returned error: %v", err)
	}
	// bcrypt hashes start with "$2a$" or "$2b$"
	if !strings.HasPrefix(hash, "$2a$") && !strings.HasPrefix(hash, "$2b$") {
		t.Errorf("expected bcrypt prefix ($2a$ or $2b$), got %q", hash[:4])
	}
	// bcrypt hashes are 60 characters long
	if len(hash) != 60 {
		t.Errorf("expected hash length 60, got %d", len(hash))
	}
}

func TestVerify_CorrectPassword(t *testing.T) {
	password := "C0rrect#Horse"
	hash, err := Hash(password)
	if err != nil {
		t.Fatalf("Hash returned error: %v", err)
	}
	if !Verify(password, hash) {
		t.Error("Verify should return true for the correct password")
	}
}

func TestVerify_WrongPassword(t *testing.T) {
	hash, err := Hash("C0rrect#Horse")
	if err != nil {
		t.Fatalf("Hash returned error: %v", err)
	}
	if Verify("Wr0ng#Horse", hash) {
		t.Error("Verify should return false for the wrong password")
	}
}

func TestVerify_EmptyHash(t *testing.T) {
	if Verify("anything", "") {
		t.Error("Verify should return false for an empty hash")
	}
}

func TestVerify_InvalidHash(t *testing.T) {
	if Verify("anything", "not-a-valid-bcrypt-hash") {
		t.Error("Verify should return false for an invalid hash")
	}
}

func TestHashRejectsNULPassword(t *testing.T) {
	if _, err := Hash("hello\x00world"); !errors.Is(err, errPasswordContainsNUL) {
		t.Fatalf("Hash error = %v, want %v", err, errPasswordContainsNUL)
	}
}

func TestVerifyRejectsNULCandidate(t *testing.T) {
	hash, err := Hash("")
	if err != nil {
		t.Fatalf("Hash returned error: %v", err)
	}
	if Verify("\x00", hash) {
		t.Error("Verify should reject a NUL candidate against an empty password hash")
	}
}

func TestHash_DifferentSalts(t *testing.T) {
	password := "SameP@ssw0rd!"
	hash1, err := Hash(password)
	if err != nil {
		t.Fatalf("Hash returned error: %v", err)
	}
	hash2, err := Hash(password)
	if err != nil {
		t.Fatalf("Hash returned error: %v", err)
	}
	if hash1 == hash2 {
		t.Error("two hashes of the same password should differ (different salts)")
	}
	// Both should still verify
	if !Verify(password, hash1) || !Verify(password, hash2) {
		t.Error("both hashes should verify against the original password")
	}
}
