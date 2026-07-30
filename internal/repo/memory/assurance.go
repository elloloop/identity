package memory

import (
	"context"
	"errors"
	"fmt"

	"github.com/elloloop/identity/internal/service"
)

func (r *Repo) CreateAttestedDevice(_ context.Context, d *service.AttestedDeviceRecord) (string, error) {
	if d == nil {
		return "", errors.New("memory: CreateAttestedDevice: nil record")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range r.attestedDevices {
		if existing.KeyID == d.KeyID {
			return "", fmt.Errorf("memory: CreateAttestedDevice: %w", service.ErrAlreadyExists)
		}
	}
	id := d.NodeID
	if id == "" {
		id = r.nextID()
	}
	cp := *d
	cp.NodeID = id
	r.attestedDevices[id] = &cp
	d.NodeID = id
	return id, nil
}

func (r *Repo) GetAttestedDeviceByKeyID(_ context.Context, keyID string) (*service.AttestedDeviceRecord, error) {
	if keyID == "" {
		return nil, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, d := range r.attestedDevices {
		if d.KeyID == keyID {
			cp := *d
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *Repo) UpdateAttestedDeviceCounter(_ context.Context, nodeID string, fromCount, toCount, lastUsedAtMs int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.attestedDevices[nodeID]
	if !ok {
		return fmt.Errorf("%w: attested device", service.ErrNotFound)
	}
	if d.SignCount != fromCount {
		return service.ErrCounterStale
	}
	d.SignCount = toCount
	d.LastUsedAt = lastUsedAtMs
	return nil
}

func (r *Repo) CreateAssuranceChallenge(_ context.Context, c *service.AssuranceChallengeRecord) (string, error) {
	if c == nil {
		return "", errors.New("memory: CreateAssuranceChallenge: nil record")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	id := c.NodeID
	if id == "" {
		id = r.nextID()
	}
	cp := *c
	cp.NodeID = id
	r.assuranceChallenges[id] = &cp
	c.NodeID = id
	return id, nil
}

func (r *Repo) ConsumeAssuranceChallenge(_ context.Context, nodeID string) (*service.AssuranceChallengeRecord, error) {
	if nodeID == "" {
		return nil, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.assuranceChallenges[nodeID]
	if !ok {
		return nil, nil
	}
	// Delete-then-return under the lock: single-use is atomic.
	delete(r.assuranceChallenges, nodeID)
	cp := *c
	return &cp, nil
}

func (r *Repo) DeleteExpiredAssuranceChallenges(_ context.Context, beforeMs int64, limit int) error {
	if limit <= 0 {
		return fmt.Errorf("memory: DeleteExpiredAssuranceChallenges: limit must be > 0, got %d", limit)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	deleted := 0
	for id, c := range r.assuranceChallenges {
		if deleted >= limit {
			break
		}
		if c.ExpiresAt < beforeMs {
			delete(r.assuranceChallenges, id)
			deleted++
		}
	}
	return nil
}
