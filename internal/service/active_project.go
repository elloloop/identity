package service

import "context"

// ActiveProjectStore reads authoritative project policy for admission, native
// sign-in and SCIM. A missing or suspended project returns (nil, nil); storage
// failure returns an error. Drivers without a control plane inject nil.
type ActiveProjectStore interface {
	ActiveProjectByID(ctx context.Context, projectID string) (*AdminProject, error)
}
