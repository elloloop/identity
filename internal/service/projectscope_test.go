package service

import (
	"context"
	"testing"
)

// projectBindRepo embeds StubRepository and records the project it was bound
// to, so the tests can assert which project a request is scoped to.
type projectBindRepo struct {
	StubRepository
	boundTo string
}

func (r *projectBindRepo) WithProject(projectID string) Repository {
	return &projectBindRepo{boundTo: projectID}
}

func TestScopedRepository(t *testing.T) {
	if got := scopedRepository(context.Background(), nil, "default"); got != nil {
		t.Fatalf("nil repo → %#v, want nil", got)
	}

	base := &projectBindRepo{boundTo: "boot"}
	for name, tc := range map[string]struct {
		ctx  context.Context
		want string
	}{
		"request scope wins":       {WithProjectScope(context.Background(), &ProjectScope{ProjectID: "p-request"}), "p-request"},
		"no scope → default":       {context.Background(), "default"},
		"blank scope id → default": {WithProjectScope(context.Background(), &ProjectScope{}), "default"},
	} {
		t.Run(name, func(t *testing.T) {
			got, ok := scopedRepository(tc.ctx, base, "default").(*projectBindRepo)
			if !ok || got.boundTo != tc.want {
				t.Fatalf("bound to %+v, want %q", got, tc.want)
			}
		})
	}
}
