package main

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/identityserver"
)

// repairEmailsSubcommand selects `identity repair-emails`: the one-time
// stored-email repair (identityserver.Server.RepairStoredEmails).
const repairEmailsSubcommand = "repair-emails"

// repairEmailsApplyArg makes the repair write; without it the run is a dry
// run that only reports.
const repairEmailsApplyArg = "--apply"

// repairEmailsUsage is the subcommand's synopsis, logged on a bad invocation.
const repairEmailsUsage = "identity " + repairEmailsSubcommand + " [" + repairEmailsApplyArg + "]"

// repairEmailsTimeout bounds one run, construction included.
const repairEmailsTimeout = 10 * time.Minute

func repairEmailsRequested(args []string) bool {
	return len(args) > 1 && args[1] == repairEmailsSubcommand
}

// parseRepairEmailsCommand returns whether the run applies its plan. Anything
// but nothing or --apply is refused, so a typo cannot turn a dry run into a
// write or the other way round.
func parseRepairEmailsCommand(args []string) (apply bool, err error) {
	switch {
	case len(args) == 2:
		return false, nil
	case len(args) == 3 && args[2] == repairEmailsApplyArg:
		return true, nil
	}
	return false, fmt.Errorf("usage: %s", repairEmailsUsage)
}

// repairEmailsDrainTimeout bounds delivering the user.merged events a run
// queued, after the repair itself.
const repairEmailsDrainTimeout = 5 * time.Minute

// runRepairEmails builds the server, without starting it, runs the repair,
// delivers the user.merged events its merges queued, and logs one line per
// mailbox and a summary. Accounts are named by id only. It returns a process
// exit code (repairEmailsExitCode).
func runRepairEmails(opts identityserver.Options, apply bool, logger *zap.Logger) int {
	ctx, cancel := context.WithTimeout(context.Background(), repairEmailsTimeout)
	defer cancel()
	srv, err := identityserver.New(ctx, opts)
	if err != nil {
		logger.Error("identity_repair_emails_init_failed", zap.Error(err))
		return 1
	}
	defer func() {
		if err := srv.Shutdown(context.Background()); err != nil {
			logger.Warn("identity_repair_emails_shutdown_error", zap.Error(err))
		}
	}()
	if apply && !opts.Config.WebhooksEnabled {
		logger.Warn("identity_repair_emails_without_webhooks",
			zap.String("detail", "merges emit no user.merged event; applications keeping data under a retired id are not told"))
	}
	return repairAndDrain(ctx, srv, apply, logger)
}

// emailRepairer is the part of identityserver.Server a repair run uses.
type emailRepairer interface {
	RepairStoredEmails(ctx context.Context, apply bool) (*identityserver.EmailRepairReport, error)
	DrainEvents(ctx context.Context) (int, error)
}

// repairAndDrain runs the repair, logs its report, and delivers the events
// it queued, and returns the exit code.
func repairAndDrain(ctx context.Context, srv emailRepairer, apply bool, logger *zap.Logger) int {
	report, repairErr := srv.RepairStoredEmails(ctx, apply)
	if report != nil {
		logRepairEmailsReport(logger, report)
	}
	if repairErr != nil {
		logger.Error("identity_repair_emails_failed", zap.Error(repairErr))
	}
	// Drained even when the run failed part-way: merges in the projects
	// before the failure are done and cannot be redone, so their events must
	// still go out. The run's own deadline may be what stopped it, so the
	// drain gets its own.
	drainCtx, drainCancel := context.WithTimeout(context.WithoutCancel(ctx), repairEmailsDrainTimeout)
	defer drainCancel()
	undelivered, drainErr := srv.DrainEvents(drainCtx)
	if drainErr != nil || undelivered > 0 {
		logger.Error("identity_repair_emails_events_undelivered",
			zap.Int("undelivered", undelivered), zap.Error(drainErr))
	}
	if repairErr != nil {
		return 1
	}
	return repairEmailsExitCode(report, undelivered)
}

// repairEmailsExitCode is 0 when every decision was made (and, applying,
// carried out) and every event delivered; 1 otherwise. A skipped mailbox is a
// decision, reported in the log, not a failure.
func repairEmailsExitCode(report *identityserver.EmailRepairReport, undelivered int) int {
	if report == nil || report.Failed() > 0 || undelivered > 0 {
		return 1
	}
	return 0
}

func logRepairEmailsReport(logger *zap.Logger, report *identityserver.EmailRepairReport) {
	for _, it := range report.Items {
		logger.Info("identity_repair_emails_item",
			zap.Bool("applied", report.Applied),
			zap.String("project_id", it.ProjectID),
			zap.String("user_id", it.UserID),
			zap.String("action", string(it.Action)),
			zap.String("survivor_id", it.SurvivorID),
			zap.String("retired_id", it.RetiredID),
			zap.Strings("other_ids", it.OtherIDs),
			zap.String("reason", it.Reason),
			zap.String("error", it.Error))
	}
	logger.Info("identity_repair_emails_done",
		zap.Bool("applied", report.Applied),
		zap.Int("rewrite", report.Count(identityserver.EmailRepairRewrite)),
		zap.Int("merge", report.Count(identityserver.EmailRepairMerge)),
		zap.Int("skip", report.Count(identityserver.EmailRepairSkip)),
		zap.Int("failed", report.Failed()))
}
