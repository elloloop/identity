package service

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUserCloneDateOfBirth(t *testing.T) {
	var absent *User
	require.Nil(t, absent.Clone())
	require.Nil(t, (&User{}).Clone().DateOfBirthMs)
	source := &User{DateOfBirthMs: new(int64(0))}
	cloned := source.Clone()
	*cloned.DateOfBirthMs = -1000
	require.Zero(t, *source.DateOfBirthMs)
	require.False(t, sameDateOfBirth(source.DateOfBirthMs, cloned.DateOfBirthMs))
	require.True(t, sameDateOfBirth(source.DateOfBirthMs, new(int64(0))))
	require.False(t, sameDateOfBirth(source.DateOfBirthMs, nil))
	require.True(t, sameDateOfBirth(nil, nil))
}
