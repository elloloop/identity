package app

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/audit"
)

func buildTeammateKeys(deps Deps, auditLog *audit.Logger, logger *zap.Logger) (*service.TeammateKeyService, error) {
	keys, err := service.NewTeammateKeyService(deps.Config, deps.DirectoryCredentials, deps.Repo, deps.Signer, auditLog, deps.MetricsRegistry)
	if err != nil {
		return nil, fmt.Errorf("teammate keys: %w", err)
	}
	logger.Info("teammate_keys_enabled", zap.String("audience", deps.Config.JWTAudience))
	return keys, nil
}

func configureTeammateKeySweep(sweep *sweeper, deps Deps, keys *service.TeammateKeyService) {
	if sweep == nil || keys == nil {
		return
	}
	sweep.teammateKeySweep = func(ctx context.Context, beforeMs int64, limit int) error {
		return sweepTeammateKeys(ctx, deps.Repo, deps.Projects, deps.Config.DefaultProjectID, beforeMs, limit)
	}
}

func sweepTeammateKeys(ctx context.Context, base service.Repository, projects service.ProjectLister, defaultProject string, beforeMs int64, limit int) error {
	ids := []string{defaultProject}
	if projects != nil {
		var err error
		if ids, err = projects.ListProjectIDs(ctx); err != nil {
			return err
		}
	}
	for _, id := range ids {
		store, ok := base.WithProject(id).(service.TeammateKeyRepository)
		if !ok {
			return service.ErrServiceUnavailable
		}
		if err := store.DeleteExpiredTeammateKeyChallenges(ctx, beforeMs, limit); err != nil {
			return err
		}
		if err := store.DeleteTeammateKeysRevokedBefore(ctx, beforeMs-service.TeammateKeyRetention.Milliseconds(), limit); err != nil {
			return err
		}
		if err := store.DeleteHireGrantsExpiredBefore(ctx, beforeMs, limit); err != nil {
			return err
		}
	}
	return nil
}
