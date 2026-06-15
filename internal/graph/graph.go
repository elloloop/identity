// Package graph defines the in-process value types exchanged between
// identity's services and the relational repository drivers.
//
// Historically these types were imported from an external graph-store
// SDK whose gRPC backend identity once spoke to. That backend has been
// retired — Postgres is the primary datastore and the memory/postgres
// drivers implement the graph-shaped service.DB interface relationally.
// The handful of plain data structures the interface still trades in
// (nodes, edges, mutation operations, commit results) now live here,
// free of any transport or gRPC dependency.
//
// On-disk and on-the-wire, node/operation payloads are keyed by proto
// field id rendered as a decimal string ("1", "2", …), never by field
// name. Drivers and the service layer agree on those ids via the
// constants in internal/service and internal/repo/postgres.
package graph

// ── Node / Edge ─────────────────────────────────────────────────────

// Node represents a graph node. Payload is keyed by proto field id
// (decimal string), never by field name.
type Node struct {
	TenantID  string         `json:"tenant_id"`
	NodeID    string         `json:"node_id"`
	TypeID    int            `json:"type_id"`
	Payload   map[string]any `json:"payload"`
	CreatedAt int64          `json:"created_at"`
	UpdatedAt int64          `json:"updated_at"`
}

// Edge represents a graph edge between two nodes.
type Edge struct {
	TenantID   string         `json:"tenant_id"`
	EdgeTypeID int            `json:"edge_type_id"`
	FromNodeID string         `json:"from_node_id"`
	ToNodeID   string         `json:"to_node_id"`
	Props      map[string]any `json:"props,omitempty"`
	CreatedAt  int64          `json:"created_at"`
}

// ── Operations ──────────────────────────────────────────────────────

// OperationType enumerates the kinds of mutation in an atomic batch.
type OperationType int

const (
	OpCreateNode OperationType = iota
	OpUpdateNode
	OpDeleteNode
	OpCreateEdge
	OpDeleteEdge
)

// Operation is a single mutation applied atomically with its batch.
// Data and Patch are keyed by proto field id (decimal string).
type Operation struct {
	Type       OperationType  `json:"type"`
	TypeID     int            `json:"type_id,omitempty"`
	NodeID     string         `json:"node_id,omitempty"`
	Alias      string         `json:"alias,omitempty"`
	Data       map[string]any `json:"data,omitempty"`
	Patch      map[string]any `json:"patch,omitempty"`
	EdgeTypeID int            `json:"edge_type_id,omitempty"`
	FromNodeID string         `json:"from_node_id,omitempty"`
	ToNodeID   string         `json:"to_node_id,omitempty"`
}

// ── Commit result ───────────────────────────────────────────────────

// CommitResult is the outcome of applying an atomic batch.
type CommitResult struct {
	Success        bool     `json:"success"`
	CreatedNodeIDs []string `json:"created_node_ids,omitempty"`
	Applied        bool     `json:"applied"`
	Error          string   `json:"error,omitempty"`
}
