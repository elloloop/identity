package app

import (
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/elloloop/identity/internal/config"
)

func TestWarnMergeWithoutWebhooks(t *testing.T) {
	for _, tc := range []struct {
		merge, webhooks bool
		want            int
	}{{true, false, 1}, {true, true, 0}, {false, false, 0}} {
		core, logs := observer.New(zap.WarnLevel)
		warnMergeWithoutWebhooks(&config.Config{AccountMergeEnabled: tc.merge, WebhooksEnabled: tc.webhooks}, zap.New(core))
		if got := logs.FilterMessage("account_merge_without_webhooks").Len(); got != tc.want {
			t.Fatalf("merge=%v webhooks=%v: %d warnings, want %d", tc.merge, tc.webhooks, got, tc.want)
		}
	}
}
