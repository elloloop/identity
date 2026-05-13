package passwords

import (
	"os"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestMain(m *testing.M) {
	SetCostForTests(bcrypt.MinCost)
	os.Exit(m.Run())
}
