package scim

import "time"

// scimTimeFormat is the SCIM/ISO 8601 timestamp layout (RFC 7643 §2.3.5).
const scimTimeFormat = time.RFC3339

// Resource is the SCIM JSON representation of a core User. Only the
// attributes the host can populate are emitted; SCIM clients tolerate the
// absence of optional attributes.
type Resource struct {
	Schemas    []string `json:"schemas"`
	ID         string   `json:"id"`
	ExternalID string   `json:"externalId,omitempty"`
	UserName   string   `json:"userName"`
	Name       *Name    `json:"name,omitempty"`
	Emails     []Email  `json:"emails,omitempty"`
	Active     bool     `json:"active"`
	Meta       *Meta    `json:"meta,omitempty"`
}

// Name is the SCIM complex name attribute.
type Name struct {
	Formatted  string `json:"formatted,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
}

// Email is a SCIM multi-valued email entry.
type Email struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary,omitempty"`
	Type    string `json:"type,omitempty"`
}

// Meta is the SCIM common resource metadata.
type Meta struct {
	ResourceType string `json:"resourceType"`
	Created      string `json:"created,omitempty"`
	LastModified string `json:"lastModified,omitempty"`
	Location     string `json:"location,omitempty"`
}

// ListResponse is the SCIM paginated list envelope (RFC 7644 §3.4.2).
type ListResponse struct {
	Schemas      []string   `json:"schemas"`
	TotalResults int        `json:"totalResults"`
	StartIndex   int        `json:"startIndex"`
	ItemsPerPage int        `json:"itemsPerPage"`
	Resources    []Resource `json:"Resources"`
}

// ErrorResponse is the SCIM error envelope (RFC 7644 §3.12).
type ErrorResponse struct {
	Schemas  []string `json:"schemas"`
	Detail   string   `json:"detail"`
	Status   string   `json:"status"`
	SCIMType string   `json:"scimType,omitempty"`
}

// toResource maps a host User to its SCIM JSON representation.
func toResource(u User) Resource {
	r := Resource{
		Schemas:    []string{SchemaUser},
		ID:         u.ID,
		ExternalID: u.ExternalID,
		UserName:   u.UserName,
		Active:     u.Active,
		Meta: &Meta{
			ResourceType: resourceTypeUser,
			Location:     userResourceLocationPrefix + u.ID,
		},
	}
	if !u.CreatedAt.IsZero() {
		r.Meta.Created = u.CreatedAt.UTC().Format(scimTimeFormat)
	}
	if !u.UpdatedAt.IsZero() {
		r.Meta.LastModified = u.UpdatedAt.UTC().Format(scimTimeFormat)
	}
	if u.GivenName != "" || u.FamilyName != "" {
		r.Name = &Name{
			Formatted:  fullName(u.GivenName, u.FamilyName),
			GivenName:  u.GivenName,
			FamilyName: u.FamilyName,
		}
	}
	if u.Email != "" {
		r.Emails = []Email{{Value: u.Email, Primary: true, Type: "work"}}
	}
	return r
}

// fromResource maps an inbound SCIM Resource (POST/PUT body) to a host User.
// userName is the authoritative email when no primary email is supplied, so
// the host always has a login identifier. The id is taken from the caller,
// not the body, so a client cannot forge it on create.
func fromResource(r Resource) User {
	u := User{
		ExternalID: r.ExternalID,
		UserName:   r.UserName,
		Active:     r.Active,
	}
	if r.Name != nil {
		u.GivenName = r.Name.GivenName
		u.FamilyName = r.Name.FamilyName
		if u.GivenName == "" && u.FamilyName == "" && r.Name.Formatted != "" {
			u.GivenName, u.FamilyName = splitName(r.Name.Formatted)
		}
	}
	u.Email = primaryEmail(r.Emails)
	if u.Email == "" {
		u.Email = r.UserName
	}
	return u
}

// primaryEmail returns the primary email from a SCIM multi-valued emails
// array, falling back to the first entry when none is flagged primary.
func primaryEmail(emails []Email) string {
	if len(emails) == 0 {
		return ""
	}
	for _, e := range emails {
		if e.Primary && e.Value != "" {
			return e.Value
		}
	}
	return emails[0].Value
}
