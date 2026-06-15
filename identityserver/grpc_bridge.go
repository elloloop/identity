package identityserver

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	identitypb "github.com/elloloop/identity/gen/go/identity"
	identityconnect "github.com/elloloop/identity/internal/connect"
)

// grpcBridge adapts identity's Connect service implementation to the
// grpc-go IdentityServiceServer interface. Each method unwraps the plain
// proto request, wraps it in a connect.Request (copying incoming gRPC
// metadata into the request headers so the handler reads client IP,
// user-agent and the authenticated user id the same way it does over
// HTTP), invokes the existing Connect handler, and unwraps the response.
//
// This reuses the one service-layer wiring rather than duplicating
// handler logic: RegisterGRPC and Handler both drive the same
// *identityconnect.IdentityHandler.
type grpcBridge struct {
	identitypb.UnimplementedIdentityServiceServer
	h *identityconnect.IdentityHandler
}

func newGRPCBridge(h *identityconnect.IdentityHandler) *grpcBridge {
	return &grpcBridge{h: h}
}

// invoke runs one Connect handler method behind the gRPC interface. It
// is generic over the request/response message types so every RPC reuses
// the same metadata-copy + error-translation path.
func invoke[Req, Resp any](
	ctx context.Context,
	in *Req,
	fn func(context.Context, *connect.Request[Req]) (*connect.Response[Resp], error),
) (*Resp, error) {
	creq := connect.NewRequest(in)
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		for key, vals := range md {
			for _, v := range vals {
				creq.Header().Add(key, v)
			}
		}
	}
	cresp, err := fn(ctx, creq)
	if err != nil {
		return nil, toGRPCError(err)
	}
	return cresp.Msg, nil
}

// toGRPCError converts a Connect handler error into a gRPC status error.
// connect.Code and grpc/codes.Code share the same integer values
// (defined off the same RPC spec), so connect.CodeOf maps directly onto
// the gRPC code. The connect.Error message (which strips the code prefix
// connect.Error.Error() adds) is preserved as the status message.
func toGRPCError(err error) error {
	if err == nil {
		return nil
	}
	code := codes.Code(connect.CodeOf(err))
	var cerr *connect.Error
	if errors.As(err, &cerr) {
		return status.Error(code, cerr.Message())
	}
	return status.Error(code, err.Error())
}

// ─── Authentication ─────────────────────────────────────────────────

func (b *grpcBridge) BeginOAuthLogin(ctx context.Context, in *identitypb.BeginOAuthLoginRequest) (*identitypb.BeginOAuthLoginResponse, error) {
	return invoke(ctx, in, b.h.BeginOAuthLogin)
}

func (b *grpcBridge) OAuthLogin(ctx context.Context, in *identitypb.OAuthLoginRequest) (*identitypb.OAuthLoginResponse, error) {
	return invoke(ctx, in, b.h.OAuthLogin)
}

func (b *grpcBridge) RedeemOAuthCode(ctx context.Context, in *identitypb.RedeemOAuthCodeRequest) (*identitypb.RedeemOAuthCodeResponse, error) {
	return invoke(ctx, in, b.h.RedeemOAuthCode)
}

func (b *grpcBridge) PasswordSignup(ctx context.Context, in *identitypb.PasswordSignupRequest) (*identitypb.PasswordSignupResponse, error) {
	return invoke(ctx, in, b.h.PasswordSignup)
}

func (b *grpcBridge) PasswordLogin(ctx context.Context, in *identitypb.PasswordLoginRequest) (*identitypb.PasswordLoginResponse, error) {
	return invoke(ctx, in, b.h.PasswordLogin)
}

func (b *grpcBridge) RequestEmailLoginCode(ctx context.Context, in *identitypb.RequestEmailLoginCodeRequest) (*identitypb.RequestEmailLoginCodeResponse, error) {
	return invoke(ctx, in, b.h.RequestEmailLoginCode)
}

func (b *grpcBridge) VerifyEmailLoginCode(ctx context.Context, in *identitypb.VerifyEmailLoginCodeRequest) (*identitypb.VerifyEmailLoginCodeResponse, error) {
	return invoke(ctx, in, b.h.VerifyEmailLoginCode)
}

func (b *grpcBridge) RequestMagicLink(ctx context.Context, in *identitypb.RequestMagicLinkRequest) (*identitypb.RequestMagicLinkResponse, error) {
	return invoke(ctx, in, b.h.RequestMagicLink)
}

func (b *grpcBridge) RedeemMagicLink(ctx context.Context, in *identitypb.RedeemMagicLinkRequest) (*identitypb.RedeemMagicLinkResponse, error) {
	return invoke(ctx, in, b.h.RedeemMagicLink)
}

// ─── Session / Token ────────────────────────────────────────────────

func (b *grpcBridge) GetCurrentUser(ctx context.Context, in *identitypb.GetCurrentUserRequest) (*identitypb.GetCurrentUserResponse, error) {
	return invoke(ctx, in, b.h.GetCurrentUser)
}

func (b *grpcBridge) RefreshToken(ctx context.Context, in *identitypb.RefreshTokenRequest) (*identitypb.RefreshTokenResponse, error) {
	return invoke(ctx, in, b.h.RefreshToken)
}

func (b *grpcBridge) Logout(ctx context.Context, in *identitypb.LogoutRequest) (*identitypb.LogoutResponse, error) {
	return invoke(ctx, in, b.h.Logout)
}

// ─── Profile / Password ─────────────────────────────────────────────

func (b *grpcBridge) UpdateProfile(ctx context.Context, in *identitypb.UpdateProfileRequest) (*identitypb.UpdateProfileResponse, error) {
	return invoke(ctx, in, b.h.UpdateProfile)
}

func (b *grpcBridge) ChangePassword(ctx context.Context, in *identitypb.ChangePasswordRequest) (*identitypb.ChangePasswordResponse, error) {
	return invoke(ctx, in, b.h.ChangePassword)
}

func (b *grpcBridge) RequestPasswordReset(ctx context.Context, in *identitypb.RequestPasswordResetRequest) (*identitypb.RequestPasswordResetResponse, error) {
	return invoke(ctx, in, b.h.RequestPasswordReset)
}

func (b *grpcBridge) ConfirmPasswordReset(ctx context.Context, in *identitypb.ConfirmPasswordResetRequest) (*identitypb.ConfirmPasswordResetResponse, error) {
	return invoke(ctx, in, b.h.ConfirmPasswordReset)
}

// ─── Email verification / change ────────────────────────────────────

func (b *grpcBridge) SendEmailVerification(ctx context.Context, in *identitypb.SendEmailVerificationRequest) (*identitypb.SendEmailVerificationResponse, error) {
	return invoke(ctx, in, b.h.SendEmailVerification)
}

func (b *grpcBridge) VerifyEmail(ctx context.Context, in *identitypb.VerifyEmailRequest) (*identitypb.VerifyEmailResponse, error) {
	return invoke(ctx, in, b.h.VerifyEmail)
}

func (b *grpcBridge) RequestEmailChange(ctx context.Context, in *identitypb.RequestEmailChangeRequest) (*identitypb.RequestEmailChangeResponse, error) {
	return invoke(ctx, in, b.h.RequestEmailChange)
}

func (b *grpcBridge) ConfirmEmailChange(ctx context.Context, in *identitypb.ConfirmEmailChangeRequest) (*identitypb.ConfirmEmailChangeResponse, error) {
	return invoke(ctx, in, b.h.ConfirmEmailChange)
}

// ─── Identity verification ──────────────────────────────────────────

func (b *grpcBridge) BeginIdentityVerification(ctx context.Context, in *identitypb.BeginIdentityVerificationRequest) (*identitypb.BeginIdentityVerificationResponse, error) {
	return invoke(ctx, in, b.h.BeginIdentityVerification)
}

func (b *grpcBridge) GetIdentityVerificationStatus(ctx context.Context, in *identitypb.GetIdentityVerificationStatusRequest) (*identitypb.GetIdentityVerificationStatusResponse, error) {
	return invoke(ctx, in, b.h.GetIdentityVerificationStatus)
}

// ─── Admin help ─────────────────────────────────────────────────────

func (b *grpcBridge) RequestAdminHelp(ctx context.Context, in *identitypb.RequestAdminHelpRequest) (*identitypb.RequestAdminHelpResponse, error) {
	return invoke(ctx, in, b.h.RequestAdminHelp)
}

func (b *grpcBridge) ListHelpRequests(ctx context.Context, in *identitypb.ListHelpRequestsRequest) (*identitypb.ListHelpRequestsResponse, error) {
	return invoke(ctx, in, b.h.ListHelpRequests)
}

func (b *grpcBridge) ResolveHelpRequest(ctx context.Context, in *identitypb.ResolveHelpRequestRequest) (*identitypb.ResolveHelpRequestResponse, error) {
	return invoke(ctx, in, b.h.ResolveHelpRequest)
}

// ─── Passkeys ───────────────────────────────────────────────────────

func (b *grpcBridge) BeginPasskeyRegistration(ctx context.Context, in *identitypb.BeginPasskeyRegistrationRequest) (*identitypb.BeginPasskeyRegistrationResponse, error) {
	return invoke(ctx, in, b.h.BeginPasskeyRegistration)
}

func (b *grpcBridge) CompletePasskeyRegistration(ctx context.Context, in *identitypb.CompletePasskeyRegistrationRequest) (*identitypb.CompletePasskeyRegistrationResponse, error) {
	return invoke(ctx, in, b.h.CompletePasskeyRegistration)
}

func (b *grpcBridge) BeginPasskeyLogin(ctx context.Context, in *identitypb.BeginPasskeyLoginRequest) (*identitypb.BeginPasskeyLoginResponse, error) {
	return invoke(ctx, in, b.h.BeginPasskeyLogin)
}

func (b *grpcBridge) CompletePasskeyLogin(ctx context.Context, in *identitypb.CompletePasskeyLoginRequest) (*identitypb.CompletePasskeyLoginResponse, error) {
	return invoke(ctx, in, b.h.CompletePasskeyLogin)
}

func (b *grpcBridge) ListPasskeys(ctx context.Context, in *identitypb.ListPasskeysRequest) (*identitypb.ListPasskeysResponse, error) {
	return invoke(ctx, in, b.h.ListPasskeys)
}

func (b *grpcBridge) DeletePasskey(ctx context.Context, in *identitypb.DeletePasskeyRequest) (*identitypb.DeletePasskeyResponse, error) {
	return invoke(ctx, in, b.h.DeletePasskey)
}

// ─── QR login ───────────────────────────────────────────────────────

func (b *grpcBridge) InitiateQrLogin(ctx context.Context, in *identitypb.InitiateQrLoginRequest) (*identitypb.InitiateQrLoginResponse, error) {
	return invoke(ctx, in, b.h.InitiateQrLogin)
}

func (b *grpcBridge) GetQrLoginSession(ctx context.Context, in *identitypb.GetQrLoginSessionRequest) (*identitypb.GetQrLoginSessionResponse, error) {
	return invoke(ctx, in, b.h.GetQrLoginSession)
}

func (b *grpcBridge) ApproveQrLogin(ctx context.Context, in *identitypb.ApproveQrLoginRequest) (*identitypb.ApproveQrLoginResponse, error) {
	return invoke(ctx, in, b.h.ApproveQrLogin)
}

func (b *grpcBridge) PollQrLogin(ctx context.Context, in *identitypb.PollQrLoginRequest) (*identitypb.PollQrLoginResponse, error) {
	return invoke(ctx, in, b.h.PollQrLogin)
}

// ─── TOTP ───────────────────────────────────────────────────────────

func (b *grpcBridge) BeginTotpSetup(ctx context.Context, in *identitypb.BeginTotpSetupRequest) (*identitypb.BeginTotpSetupResponse, error) {
	return invoke(ctx, in, b.h.BeginTotpSetup)
}

func (b *grpcBridge) VerifyTotpSetup(ctx context.Context, in *identitypb.VerifyTotpSetupRequest) (*identitypb.VerifyTotpSetupResponse, error) {
	return invoke(ctx, in, b.h.VerifyTotpSetup)
}

func (b *grpcBridge) DisableTotp(ctx context.Context, in *identitypb.DisableTotpRequest) (*identitypb.DisableTotpResponse, error) {
	return invoke(ctx, in, b.h.DisableTotp)
}

func (b *grpcBridge) VerifyTotp(ctx context.Context, in *identitypb.VerifyTotpRequest) (*identitypb.VerifyTotpResponse, error) {
	return invoke(ctx, in, b.h.VerifyTotp)
}

func (b *grpcBridge) RegenerateRecoveryCodes(ctx context.Context, in *identitypb.RegenerateRecoveryCodesRequest) (*identitypb.RegenerateRecoveryCodesResponse, error) {
	return invoke(ctx, in, b.h.RegenerateRecoveryCodes)
}

// ─── Session management ─────────────────────────────────────────────

func (b *grpcBridge) ListMySessions(ctx context.Context, in *identitypb.ListMySessionsRequest) (*identitypb.ListMySessionsResponse, error) {
	return invoke(ctx, in, b.h.ListMySessions)
}

func (b *grpcBridge) RevokeSession(ctx context.Context, in *identitypb.RevokeSessionRequest) (*identitypb.RevokeSessionResponse, error) {
	return invoke(ctx, in, b.h.RevokeSession)
}

func (b *grpcBridge) RevokeAllSessions(ctx context.Context, in *identitypb.RevokeAllSessionsRequest) (*identitypb.RevokeAllSessionsResponse, error) {
	return invoke(ctx, in, b.h.RevokeAllSessions)
}

func (b *grpcBridge) SignOutEverywhere(ctx context.Context, in *identitypb.SignOutEverywhereRequest) (*identitypb.SignOutEverywhereResponse, error) {
	return invoke(ctx, in, b.h.SignOutEverywhere)
}

// ─── Audit ──────────────────────────────────────────────────────────

func (b *grpcBridge) ListAuditEvents(ctx context.Context, in *identitypb.ListAuditEventsRequest) (*identitypb.ListAuditEventsResponse, error) {
	return invoke(ctx, in, b.h.ListAuditEvents)
}

// ─── Users ──────────────────────────────────────────────────────────

func (b *grpcBridge) CreateUser(ctx context.Context, in *identitypb.CreateUserRequest) (*identitypb.CreateUserResponse, error) {
	return invoke(ctx, in, b.h.CreateUser)
}

func (b *grpcBridge) GetUser(ctx context.Context, in *identitypb.GetUserRequest) (*identitypb.GetUserResponse, error) {
	return invoke(ctx, in, b.h.GetUser)
}

func (b *grpcBridge) UpdateUser(ctx context.Context, in *identitypb.UpdateUserRequest) (*identitypb.UpdateUserResponse, error) {
	return invoke(ctx, in, b.h.UpdateUser)
}

func (b *grpcBridge) DeleteUser(ctx context.Context, in *identitypb.DeleteUserRequest) (*identitypb.DeleteUserResponse, error) {
	return invoke(ctx, in, b.h.DeleteUser)
}

func (b *grpcBridge) ListUsers(ctx context.Context, in *identitypb.ListUsersRequest) (*identitypb.ListUsersResponse, error) {
	return invoke(ctx, in, b.h.ListUsers)
}

// ─── Groups ─────────────────────────────────────────────────────────

func (b *grpcBridge) CreateGroup(ctx context.Context, in *identitypb.CreateGroupRequest) (*identitypb.CreateGroupResponse, error) {
	return invoke(ctx, in, b.h.CreateGroup)
}

func (b *grpcBridge) UpdateGroup(ctx context.Context, in *identitypb.UpdateGroupRequest) (*identitypb.UpdateGroupResponse, error) {
	return invoke(ctx, in, b.h.UpdateGroup)
}

func (b *grpcBridge) DeleteGroup(ctx context.Context, in *identitypb.DeleteGroupRequest) (*identitypb.DeleteGroupResponse, error) {
	return invoke(ctx, in, b.h.DeleteGroup)
}

func (b *grpcBridge) ListGroups(ctx context.Context, in *identitypb.ListGroupsRequest) (*identitypb.ListGroupsResponse, error) {
	return invoke(ctx, in, b.h.ListGroups)
}

func (b *grpcBridge) AddGroupMember(ctx context.Context, in *identitypb.AddGroupMemberRequest) (*identitypb.AddGroupMemberResponse, error) {
	return invoke(ctx, in, b.h.AddGroupMember)
}

func (b *grpcBridge) RemoveGroupMember(ctx context.Context, in *identitypb.RemoveGroupMemberRequest) (*identitypb.RemoveGroupMemberResponse, error) {
	return invoke(ctx, in, b.h.RemoveGroupMember)
}

func (b *grpcBridge) ListGroupMembers(ctx context.Context, in *identitypb.ListGroupMembersRequest) (*identitypb.ListGroupMembersResponse, error) {
	return invoke(ctx, in, b.h.ListGroupMembers)
}

// ─── Tenant domains ─────────────────────────────────────────────────

func (b *grpcBridge) CreateDomain(ctx context.Context, in *identitypb.CreateDomainRequest) (*identitypb.CreateDomainResponse, error) {
	return invoke(ctx, in, b.h.CreateDomain)
}

func (b *grpcBridge) VerifyDomain(ctx context.Context, in *identitypb.VerifyDomainRequest) (*identitypb.VerifyDomainResponse, error) {
	return invoke(ctx, in, b.h.VerifyDomain)
}

func (b *grpcBridge) ListTenantDomains(ctx context.Context, in *identitypb.ListTenantDomainsRequest) (*identitypb.ListTenantDomainsResponse, error) {
	return invoke(ctx, in, b.h.ListTenantDomains)
}

// ─── Admin user management ──────────────────────────────────────────

func (b *grpcBridge) InviteUser(ctx context.Context, in *identitypb.InviteUserRequest) (*identitypb.InviteUserResponse, error) {
	return invoke(ctx, in, b.h.InviteUser)
}

func (b *grpcBridge) AcceptInvitation(ctx context.Context, in *identitypb.AcceptInvitationRequest) (*identitypb.AcceptInvitationResponse, error) {
	return invoke(ctx, in, b.h.AcceptInvitation)
}

func (b *grpcBridge) DeactivateUser(ctx context.Context, in *identitypb.DeactivateUserRequest) (*identitypb.DeactivateUserResponse, error) {
	return invoke(ctx, in, b.h.DeactivateUser)
}

func (b *grpcBridge) ReactivateUser(ctx context.Context, in *identitypb.ReactivateUserRequest) (*identitypb.ReactivateUserResponse, error) {
	return invoke(ctx, in, b.h.ReactivateUser)
}

func (b *grpcBridge) ResetUserPassword(ctx context.Context, in *identitypb.ResetUserPasswordRequest) (*identitypb.ResetUserPasswordResponse, error) {
	return invoke(ctx, in, b.h.ResetUserPassword)
}

func (b *grpcBridge) SetUserQuota(ctx context.Context, in *identitypb.SetUserQuotaRequest) (*identitypb.SetUserQuotaResponse, error) {
	return invoke(ctx, in, b.h.SetUserQuota)
}

var _ identitypb.IdentityServiceServer = (*grpcBridge)(nil)
