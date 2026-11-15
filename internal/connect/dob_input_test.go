package connect

import (
	"testing"

	"github.com/elloloop/identity/internal/service"
	"github.com/stretchr/testify/require"
)

func TestDateOfBirthInput(t *testing.T) {
	for _, tc := range []struct {
		name           string
		legacy         int64
		explicit, want *int64
		invalid        bool
	}{
		{name: "absent"},
		{name: "legacy historical", legacy: -1000, want: new(int64(-1000))},
		{name: "legacy positive", legacy: 1000, want: new(int64(1000))},
		{name: "explicit epoch", explicit: new(int64(0)), want: new(int64(0))},
		{name: "explicit historical", explicit: new(int64(-1000)), want: new(int64(-1000))},
		{name: "matching", legacy: 1000, explicit: new(int64(1000)), want: new(int64(1000))},
		{name: "conflicting", legacy: 1000, explicit: new(int64(0)), invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := dateOfBirthInput(tc.legacy, tc.explicit)
			if tc.invalid {
				require.ErrorIs(t, err, service.ErrInvalidArgument)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestUserToProtoDateOfBirthPresence(t *testing.T) {
	for _, dob := range []*int64{nil, new(int64(0)), new(int64(-1000)), new(int64(1000))} {
		got := userToProto(&service.User{DateOfBirthMs: dob})
		require.Equal(t, dob, got.DateOfBirthUnixMs)
		if dob != nil {
			require.Equal(t, *dob, got.DateOfBirthMs)
		} else {
			require.Zero(t, got.DateOfBirthMs)
		}
	}
}
