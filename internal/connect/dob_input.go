package connect

import "github.com/elloloop/identity/internal/service"

// dateOfBirthInput preserves the public API's legacy zero-as-absent semantics.
func dateOfBirthInput(legacy int64, explicit *int64) (*int64, error) {
	if explicit != nil {
		if legacy != 0 && legacy != *explicit {
			return nil, service.ErrInvalidArgument
		}
		return new(*explicit), nil
	}
	if legacy == 0 {
		return nil, nil //nolint:nilnil // An omitted date is a valid optional input.
	}
	return new(legacy), nil
}
