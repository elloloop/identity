package scim

import "net/http"

// The discovery endpoints (/ServiceProviderConfig, /ResourceTypes, /Schemas)
// let a SCIM client introspect what this server supports before provisioning.
// They describe exactly the surface this provider implements: User CRUD +
// PATCH, filtering, pagination, and bearer-token auth — no PASSWORD change,
// no bulk, no ETag, no sort.

func (p *Provider) handleServiceProviderConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "", "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, serviceProviderConfig())
}

func (p *Provider) handleResourceTypes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "", "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"schemas":      []string{SchemaListResponse},
		"totalResults": 1,
		"startIndex":   1,
		"itemsPerPage": 1,
		"Resources":    []any{userResourceType()},
	})
}

func (p *Provider) handleSchemas(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "", "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"schemas":      []string{SchemaListResponse},
		"totalResults": 1,
		"startIndex":   1,
		"itemsPerPage": 1,
		"Resources":    []any{userSchema()},
	})
}

func serviceProviderConfig() map[string]any {
	return map[string]any{
		"schemas":               []string{SchemaServiceProviderConfig},
		"documentationUri":      "https://github.com/elloloop/identity",
		"patch":                 map[string]any{"supported": true},
		"bulk":                  map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":                map[string]any{"supported": true, "maxResults": maxPageSize},
		"changePassword":        map[string]any{"supported": false},
		"sort":                  map[string]any{"supported": false},
		"etag":                  map[string]any{"supported": false},
		"authenticationSchemes": []any{authenticationScheme()},
		"meta": map[string]any{
			"resourceType": "ServiceProviderConfig",
			"location":     "/scim/v2/ServiceProviderConfig",
		},
	}
}

func authenticationScheme() map[string]any {
	return map[string]any{
		"type":        "oauthbearertoken",
		"name":        "OAuth Bearer Token",
		"description": "Authentication via the SCIM bearer token configured for the project.",
		"primary":     true,
	}
}

func userResourceType() map[string]any {
	return map[string]any{
		"schemas":     []string{SchemaResourceTypeURN},
		"id":          resourceTypeUser,
		"name":        resourceTypeUser,
		"endpoint":    "/Users",
		"description": "User Account",
		"schema":      SchemaUser,
		"meta": map[string]any{
			"resourceType": "ResourceType",
			"location":     "/scim/v2/ResourceTypes/User",
		},
	}
}

func userSchema() map[string]any {
	attr := func(name, typ string, required, caseExact bool) map[string]any {
		return map[string]any{
			"name":        name,
			"type":        typ,
			"multiValued": false,
			"required":    required,
			"caseExact":   caseExact,
			"mutability":  "readWrite",
			"returned":    "default",
			"uniqueness":  "none",
		}
	}
	return map[string]any{
		"schemas":     []string{SchemaSchemaURN},
		"id":          SchemaUser,
		"name":        resourceTypeUser,
		"description": "User Account",
		"attributes": []any{
			func() map[string]any {
				a := attr("userName", "string", true, false)
				a["uniqueness"] = "server"
				return a
			}(),
			attr("externalId", "string", false, true),
			attr("active", "boolean", false, false),
			map[string]any{
				"name": "name", "type": "complex", "multiValued": false,
				"required": false, "mutability": "readWrite", "returned": "default",
				"subAttributes": []any{
					attr("givenName", "string", false, false),
					attr("familyName", "string", false, false),
					attr("formatted", "string", false, false),
				},
			},
			map[string]any{
				"name": "emails", "type": "complex", "multiValued": true,
				"required": false, "mutability": "readWrite", "returned": "default",
				"subAttributes": []any{
					attr("value", "string", false, false),
					attr("primary", "boolean", false, false),
					attr("type", "string", false, false),
				},
			},
		},
		"meta": map[string]any{
			"resourceType": "Schema",
			"location":     "/scim/v2/Schemas/" + SchemaUser,
		},
	}
}
