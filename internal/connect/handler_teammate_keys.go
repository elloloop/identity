package connect

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"github.com/prometheus/client_golang/prometheus"

	identitypb "github.com/elloloop/identity/gen/go/identity/v1"
	"github.com/elloloop/identity/internal/service"
)

// TeammateKeyManagerHeader carries a teammate_key_manager project credential
// ("<public id>.<secret>") to TeammateKeyService. Like DirectoryKeyHeader it
// is not the Authorization header, so the JWT layer never sees it.
const TeammateKeyManagerHeader = "X-Teammate-Key-Manager-Key"

const (
	exchangeKindAgentMachine = "agent_machine"
	exchangeKindTeammate     = "teammate"
)

// TeammateKeyHandler serves TeammateKeyService.
type TeammateKeyHandler struct {
	keys *service.TeammateKeyService
}

func NewTeammateKeyHandler(keys *service.TeammateKeyService) *TeammateKeyHandler {
	return &TeammateKeyHandler{keys: keys}
}

func (h *TeammateKeyHandler) RegisterTeammateKey(ctx context.Context, req *connect.Request[identitypb.RegisterTeammateKeyRequest]) (*connect.Response[identitypb.RegisterTeammateKeyResponse], error) {
	algorithm := ""
	switch req.Msg.Algorithm {
	case identitypb.KeyAlgorithm_KEY_ALGORITHM_ED25519:
		algorithm = service.TeammateKeyEd25519
	case identitypb.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256:
		algorithm = service.TeammateKeyECDSAP256
	}
	id, err := h.keys.RegisterTeammateKey(ctx, req.Header().Get(TeammateKeyManagerHeader), service.TeammateKeyRegistration{ClaimID: req.Msg.ClaimId, TeammateID: req.Msg.TeammateId, CompanyID: req.Msg.CompanyId, WorkstationID: req.Msg.WorkstationId, PublicKey: req.Msg.PublicKey, Algorithm: algorithm})
	if err != nil {
		return nil, toConnectError(err)
	}
	return machineResponse(&identitypb.RegisterTeammateKeyResponse{KeyId: id}), nil
}

func (h *TeammateKeyHandler) RevokeTeammateKey(ctx context.Context, req *connect.Request[identitypb.RevokeTeammateKeyRequest]) (*connect.Response[identitypb.RevokeTeammateKeyResponse], error) {
	reason := ""
	switch req.Msg.Reason {
	case identitypb.TeammateKeyRevocationReason_TEAMMATE_KEY_REVOCATION_REASON_RELEASED:
		reason = service.TeammateKeyReleased
	case identitypb.TeammateKeyRevocationReason_TEAMMATE_KEY_REVOCATION_REASON_RECLAIMED:
		reason = service.TeammateKeyReclaimed
	case identitypb.TeammateKeyRevocationReason_TEAMMATE_KEY_REVOCATION_REASON_REMOVED:
		reason = service.TeammateKeyRemoved
	case identitypb.TeammateKeyRevocationReason_TEAMMATE_KEY_REVOCATION_REASON_DRIFTED:
		reason = service.TeammateKeyDrifted
	}
	if err := h.keys.RevokeTeammateKey(ctx, req.Header().Get(TeammateKeyManagerHeader), req.Msg.ClaimId, reason); err != nil {
		return nil, toConnectError(err)
	}
	return machineResponse(&identitypb.RevokeTeammateKeyResponse{}), nil
}

// NewAgentExchangeMetrics registers identity_agent_exchanges_total{key_kind,result},
// counting ExchangeAgentMachineCredential calls by the key that signed them.
func NewAgentExchangeMetrics(reg prometheus.Registerer) (*prometheus.CounterVec, error) {
	if reg == nil {
		reg = prometheus.NewRegistry()
	}
	exchanges := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "identity_agent_exchanges_total",
		Help: "ExchangeAgentMachineCredential calls, labelled by the kind of key that signed them and the result.",
	}, []string{"key_kind", "result"})
	if err := reg.Register(exchanges); err != nil {
		return nil, err
	}
	return exchanges, nil
}

// WithTeammateKeys lets the machine challenge and exchange RPCs serve
// teammate keys; nil refuses a request that names one.
func (h *IdentityHandler) WithTeammateKeys(keys *service.TeammateKeyService) *IdentityHandler {
	h.teammateKeys = keys
	return h
}

func (h *IdentityHandler) WithAgentExchangeMetrics(exchanges *prometheus.CounterVec) *IdentityHandler {
	h.exchanges = exchanges
	return h
}

func (h *IdentityHandler) countExchange(kind string, err error) {
	if h.exchanges == nil {
		return
	}
	result := "issued"
	var connectErr *connect.Error
	if err != nil {
		result = "error"
		if errors.As(err, &connectErr) {
			switch connectErr.Code() {
			case connect.CodeUnauthenticated, connect.CodePermissionDenied, connect.CodeInvalidArgument, connect.CodeFailedPrecondition, connect.CodeResourceExhausted:
				result = "refused"
			}
		}
	}
	h.exchanges.WithLabelValues(kind, result).Inc()
}

func (h *IdentityHandler) teammateKeysEnabled() error {
	if h.teammateKeys == nil {
		return connect.NewError(connect.CodeFailedPrecondition, service.ErrTeammateKeysDisabled)
	}
	return nil
}

func (h *IdentityHandler) createTeammateKeyChallenge(ctx context.Context, msg *identitypb.CreateAgentMachineChallengeRequest) (*connect.Response[identitypb.CreateAgentMachineChallengeResponse], error) {
	if err := h.teammateKeysEnabled(); err != nil {
		return nil, err
	}
	if msg.Operation != identitypb.AgentMachineOperation_AGENT_MACHINE_OPERATION_EXCHANGE_AGENT || msg.MachineId != "" || msg.AgentUserId != "" || msg.AgentPublicKey != "" || msg.Offset != 0 {
		return nil, toConnectError(service.ErrInvalidArgument)
	}
	challenge, err := h.teammateKeys.CreateChallenge(ctx, msg.TeammateKeyId)
	if err != nil {
		return nil, toConnectError(err)
	}
	return machineResponse(&identitypb.CreateAgentMachineChallengeResponse{ChallengeId: challenge.ID, Message: []byte(challenge.Message), ExpiresAtMs: challenge.ExpiresAtMs}), nil
}

func (h *IdentityHandler) exchangeTeammateKey(ctx context.Context, msg *identitypb.ExchangeAgentMachineCredentialRequest) (*connect.Response[identitypb.ExchangeAgentMachineCredentialResponse], error) {
	if err := h.teammateKeysEnabled(); err != nil {
		return nil, err
	}
	if msg.MachineId != "" || msg.AgentUserId != "" {
		return nil, toConnectError(service.ErrInvalidArgument)
	}
	tokens, err := h.teammateKeys.Exchange(ctx, msg.TeammateKeyId, machineProof(msg.Proof))
	if err != nil {
		return nil, toConnectError(err)
	}
	return machineResponse(&identitypb.ExchangeAgentMachineCredentialResponse{AccessToken: tokens.AccessToken, ExpiresIn: tokens.ExpiresIn, TokenType: "Bearer"}), nil
}
