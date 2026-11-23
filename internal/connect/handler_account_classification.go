package connect

import (
	"context"

	"connectrpc.com/connect"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

const AccountClassifierKeyHeader = "X-Account-Classifier-Key"

func (h *IdentityHandler) WithAccountClassification(s *service.AccountClassificationService) *IdentityHandler {
	h.accountClassification = s
	return h
}

func (h *IdentityHandler) ClassifyAccounts(ctx context.Context, req *connect.Request[identitypb.ClassifyAccountsRequest]) (*connect.Response[identitypb.ClassifyAccountsResponse], error) {
	if h.accountClassification == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, service.ErrUnimplemented)
	}
	classes, err := h.accountClassification.ClassifyAccounts(ctx, req.Header().Get(AccountClassifierKeyHeader), req.Msg.UserIds)
	if err != nil {
		return nil, toConnectError(err)
	}
	results := make([]*identitypb.ClassifiedAccount, len(classes))
	for i, result := range classes {
		classification := identitypb.AccountClassification_ACCOUNT_CLASSIFICATION_DENIED
		switch result.Classification {
		case service.AccountClassificationActiveKnownAdult:
			classification = identitypb.AccountClassification_ACCOUNT_CLASSIFICATION_ACTIVE_KNOWN_ADULT
		case service.AccountClassificationActiveKnownMinor:
			classification = identitypb.AccountClassification_ACCOUNT_CLASSIFICATION_ACTIVE_KNOWN_MINOR
		}
		results[i] = &identitypb.ClassifiedAccount{UserId: result.UserID, Classification: classification}
	}
	return connect.NewResponse(&identitypb.ClassifyAccountsResponse{Accounts: results}), nil
}
