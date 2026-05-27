// errorDB wraps fakeDB and supports per-method error injection. Used to
// exercise DB error branches in admin/group/help/profile services.
package service

import (
	"context"

	"github.com/elloloop/tenant-shard-db/sdk/go/entdb/v2"
)

type errorDB struct {
	*fakeDB
	failGetNode       bool
	failQueryNodes    bool
	failExecuteAtomic bool
	failGetEdgesFrom  bool
	failGetEdgesTo    bool
	failSearchNodes   bool
	// failExecuteAfter triggers ExecuteAtomic to fail starting at the Nth call.
	failExecuteAfter int
	executeCount     int
	// failQueryAfter triggers QueryNodes to fail starting at the Nth call.
	failQueryAfter int
	queryCount     int
	// failGetNodeAfter triggers GetNode to fail starting at the Nth call.
	failGetNodeAfter int
	getNodeCount     int
}

func newErrorDB() *errorDB {
	return &errorDB{fakeDB: newFakeDB()}
}

func (d *errorDB) GetNode(ctx context.Context, t, a string, tid int, nid string) (*entdb.Node, error) {
	d.getNodeCount++
	if d.failGetNode || (d.failGetNodeAfter > 0 && d.getNodeCount >= d.failGetNodeAfter) {
		return nil, errInjected
	}
	return d.fakeDB.GetNode(ctx, t, a, tid, nid)
}

func (d *errorDB) QueryNodes(ctx context.Context, t, a string, tid int, f map[string]any) ([]*entdb.Node, error) {
	d.queryCount++
	if d.failQueryNodes || (d.failQueryAfter > 0 && d.queryCount >= d.failQueryAfter) {
		return nil, errInjected
	}
	return d.fakeDB.QueryNodes(ctx, t, a, tid, f)
}

func (d *errorDB) ExecuteAtomic(ctx context.Context, t, a string, ops []entdb.Operation) (*entdb.CommitResult, error) {
	d.executeCount++
	if d.failExecuteAtomic || (d.failExecuteAfter > 0 && d.executeCount >= d.failExecuteAfter) {
		return nil, errInjected
	}
	return d.fakeDB.ExecuteAtomic(ctx, t, a, ops)
}

func (d *errorDB) GetEdgesFrom(ctx context.Context, t, a, fid string, eid int) ([]*entdb.Edge, error) {
	if d.failGetEdgesFrom {
		return nil, errInjected
	}
	return d.fakeDB.GetEdgesFrom(ctx, t, a, fid, eid)
}

func (d *errorDB) GetEdgesTo(ctx context.Context, t, a, tid string, eid int) ([]*entdb.Edge, error) {
	if d.failGetEdgesTo {
		return nil, errInjected
	}
	return d.fakeDB.GetEdgesTo(ctx, t, a, tid, eid)
}

func (d *errorDB) SearchNodes(ctx context.Context, t, a string, tid int, q string) ([]*entdb.Node, error) {
	if d.failSearchNodes {
		return nil, errInjected
	}
	return d.fakeDB.SearchNodes(ctx, t, a, tid, q)
}
