package service

import (
	"os"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/elloloop/identity/pkg/passwords"
)

func TestMain(m *testing.M) {
	passwords.SetCostForTests(bcrypt.MinCost)
	os.Exit(m.Run())
}
