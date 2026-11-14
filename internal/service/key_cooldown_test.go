package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKeyCooldown_AdmitsOncePerWindow(t *testing.T) {
	c := newKeyCooldown(1000, 0)
	assert.True(t, c.allow("a", 0))
	assert.False(t, c.allow("a", 999))
	assert.True(t, c.allow("b", 999), "keys are paced apart")
	assert.True(t, c.allow("a", 1000))
}

// An event that counts against several keys is admitted only when none of
// them is cooling down, and a refusal spends none.
func TestKeyCooldown_AllowAllSpendsNoKeyOnARefusal(t *testing.T) {
	c := newKeyCooldown(1000, 0)
	assert.True(t, c.allow("address", 0))
	assert.False(t, c.allowAll(500, "account", "address"), "the address is cooling down")
	assert.True(t, c.allow("account", 600), "the refused event did not spend the account's key")
	assert.False(t, c.allowAll(700, "", "account"), "an empty key is not counted, the other is")
	assert.True(t, c.allowAll(1600, "account", "address"))
	assert.False(t, c.allow("address", 1700))
	assert.False(t, c.allow("account", 1700))
}

// The tracker never holds more than maxSize keys, however many distinct keys
// arrive inside one window.
func TestKeyCooldown_BoundedMemory(t *testing.T) {
	c := newKeyCooldown(60_000, 3)
	for i, k := range []string{"a", "b", "c", "d", "e"} {
		assert.True(t, c.allow(k, int64(i)))
		assert.LessOrEqual(t, len(c.lastMs), 3)
	}
}
