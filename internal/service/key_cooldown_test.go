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

// The tracker never holds more than maxSize keys, however many distinct keys
// arrive inside one window.
func TestKeyCooldown_BoundedMemory(t *testing.T) {
	c := newKeyCooldown(60_000, 3)
	for i, k := range []string{"a", "b", "c", "d", "e"} {
		assert.True(t, c.allow(k, int64(i)))
		assert.LessOrEqual(t, len(c.lastMs), 3)
	}
}
