package scim

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
)

// scimContentType is the SCIM media type (RFC 7644 §3.1). The provider
// accepts application/json too (Okta sends it) but always responds with the
// SCIM type.
const scimContentType = "application/scim+json"

// defaultPageSize and maxPageSize bound a SCIM list page. They mirror the
// host repository's clamp so a client cannot request an unbounded scan.
const (
	defaultPageSize = 50
	maxPageSize     = 500
)

// Provider serves the SCIM /Users surface and the discovery endpoints over a
// Store. It is mounted by the host under /scim/v2/ once the host has
// authenticated the request and resolved its project.
type Provider struct {
	store Store
}

// NewProvider returns a Provider backed by store. store is required.
func NewProvider(store Store) *Provider {
	return &Provider{store: store}
}

// Handler returns an http.Handler routing the SCIM v2 endpoints. The host
// mounts it at /scim/v2/ (StripPrefix not required — the provider matches on
// the full path suffix).
func (p *Provider) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/scim/v2/ServiceProviderConfig", p.handleServiceProviderConfig)
	mux.HandleFunc("/scim/v2/Schemas", p.handleSchemas)
	mux.HandleFunc("/scim/v2/ResourceTypes", p.handleResourceTypes)
	mux.HandleFunc("/scim/v2/Users", p.handleUsersCollection)
	mux.HandleFunc("/scim/v2/Users/", p.handleUserItem)
	return mux
}

func (p *Provider) handleUsersCollection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		p.listUsers(w, r)
	case http.MethodPost:
		p.createUser(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "", "method not allowed")
	}
}

func (p *Provider) handleUserItem(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, userResourceLocationPrefix)
	if id == "" || strings.Contains(id, "/") {
		writeError(w, http.StatusNotFound, "", "user not found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		p.getUser(w, r, id)
	case http.MethodPut:
		p.replaceUser(w, r, id)
	case http.MethodPatch:
		p.patchUser(w, r, id)
	case http.MethodDelete:
		p.deleteUser(w, r, id)
	default:
		writeError(w, http.StatusMethodNotAllowed, "", "method not allowed")
	}
}

func (p *Provider) createUser(w http.ResponseWriter, r *http.Request) {
	var body Resource
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalidValue", err.Error())
		return
	}
	if strings.TrimSpace(body.UserName) == "" {
		writeError(w, http.StatusBadRequest, "invalidValue", "userName is required")
		return
	}
	created, err := p.store.CreateUser(r.Context(), fromResource(body))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeResource(w, http.StatusCreated, created)
}

func (p *Provider) getUser(w http.ResponseWriter, r *http.Request, id string) {
	u, err := p.store.GetUser(r.Context(), id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeResource(w, http.StatusOK, u)
}

func (p *Provider) replaceUser(w http.ResponseWriter, r *http.Request, id string) {
	var body Resource
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalidValue", err.Error())
		return
	}
	updated, err := p.store.ReplaceUser(r.Context(), id, fromResource(body))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeResource(w, http.StatusOK, updated)
}

func (p *Provider) patchUser(w http.ResponseWriter, r *http.Request, id string) {
	var body PatchRequest
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalidValue", err.Error())
		return
	}
	active, ok, err := body.activeValue()
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalidValue", err.Error())
		return
	}
	if !ok {
		// The only PATCH the provider supports today is toggling active
		// (the deprovision/reprovision path every IdP drives). Anything
		// else is rejected explicitly rather than silently ignored.
		writeError(w, http.StatusBadRequest, "invalidValue",
			"only the 'active' attribute may be patched")
		return
	}
	updated, err := p.store.SetActive(r.Context(), id, active)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeResource(w, http.StatusOK, updated)
}

func (p *Provider) deleteUser(w http.ResponseWriter, r *http.Request, id string) {
	if err := p.store.DeleteUser(r.Context(), id); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (p *Provider) listUsers(w http.ResponseWriter, r *http.Request) {
	filter, err := parseListFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalidFilter", err.Error())
		return
	}
	users, total, err := p.store.ListUsers(r.Context(), filter)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	resources := make([]Resource, 0, len(users))
	for _, u := range users {
		resources = append(resources, toResource(u))
	}
	writeJSON(w, http.StatusOK, ListResponse{
		Schemas:      []string{SchemaListResponse},
		TotalResults: total,
		StartIndex:   filter.StartIndex,
		ItemsPerPage: len(resources),
		Resources:    resources,
	})
}

// parseListFilter reads SCIM pagination (startIndex, count) and the supported
// subset of the filter grammar (userName eq, emails eq / email eq,
// externalId eq) from the query string.
func parseListFilter(r *http.Request) (ListFilter, error) {
	q := r.URL.Query()
	f := ListFilter{StartIndex: 1, Count: defaultPageSize}

	if v := q.Get("startIndex"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return f, errors.New("startIndex must be a positive integer")
		}
		f.StartIndex = n
	}
	if v := q.Get("count"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return f, errors.New("count must be a non-negative integer")
		}
		if n == 0 || n > maxPageSize {
			n = maxPageSize
		}
		f.Count = n
	}

	if raw := strings.TrimSpace(q.Get("filter")); raw != "" {
		attr, val, err := parseEqFilter(raw)
		if err != nil {
			return f, err
		}
		switch strings.ToLower(attr) {
		case "username":
			f.UserName = val
		case "email", "emails", "emails.value":
			f.Email = val
		case "externalid":
			f.ExternalID = val
		default:
			return f, errors.New("unsupported filter attribute: " + attr)
		}
	}
	return f, nil
}

// parseEqFilter parses the single-term SCIM equality filter
// `<attr> eq "<value>"` (the only operator enterprises require for user
// lookup). It returns the attribute and the unquoted value.
func parseEqFilter(raw string) (attr, value string, err error) {
	parts := strings.SplitN(raw, " ", 3)
	if len(parts) != 3 || !strings.EqualFold(parts[1], "eq") {
		return "", "", errors.New(`filter must be of the form: <attribute> eq "<value>"`)
	}
	v := strings.TrimSpace(parts[2])
	if len(v) < 2 || v[0] != '"' || v[len(v)-1] != '"' {
		return "", "", errors.New("filter value must be a quoted string")
	}
	return parts[0], v[1 : len(v)-1], nil
}

// decodeJSON parses a SCIM request body into dst. Unknown fields are
// tolerated on purpose: SCIM clients (Okta/Entra) send the full resource
// including attributes this server does not model, and rejecting those would
// break interoperability. Only structurally malformed JSON is an error.
func decodeJSON(r *http.Request, dst any) error {
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		return errors.New("malformed JSON body")
	}
	return nil
}

func writeResource(w http.ResponseWriter, status int, u User) {
	writeJSON(w, status, toResource(u))
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", scimContentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, scimType, detail string) {
	writeJSON(w, status, ErrorResponse{
		Schemas:  []string{SchemaError},
		Detail:   detail,
		Status:   strconv.Itoa(status),
		SCIMType: scimType,
	})
}

func writeStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusNotFound, "", "resource not found")
	case errors.Is(err, ErrConflict):
		writeError(w, http.StatusConflict, "uniqueness", "a resource with this attribute already exists")
	default:
		writeError(w, http.StatusInternalServerError, "", "internal error")
	}
}
