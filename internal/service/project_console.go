package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/audit"
)

// A project member's role. An owner created the project or was made one; an
// admin was added by an owner. Both may read and change the project's
// member-editable settings.
const (
	ProjectRoleOwner = "owner"
	ProjectRoleAdmin = "admin"
)

// projectNameMaxRunes bounds a project's name as tenantNameMaxRunes bounds a
// tenant's.
const projectNameMaxRunes = 100

// auditReasonProjectLimit is the reason recorded when CreateProject is
// refused because the caller already owns as many projects as one account
// may.
const auditReasonProjectLimit = "project_limit"

var (
	// ErrSelfServiceProjectsDisabled is returned by CreateProject when the
	// server does not let console accounts create projects
	// (GATEWAY_CONSOLE_SELF_SERVICE_PROJECTS_ENABLED). Mapped to
	// CodeFailedPrecondition.
	ErrSelfServiceProjectsDisabled = errors.New("this server does not let accounts create projects")

	// ErrProjectCreationLimited is returned by CreateProject when the caller
	// already owns GATEWAY_CONSOLE_MAX_PROJECTS_PER_ACCOUNT projects. Mapped to
	// CodeResourceExhausted.
	ErrProjectCreationLimited = errors.New("this account owns as many projects as one account may")
)

// MemberProject is a project as one of its members sees it.
type MemberProject struct {
	ID   string
	Name string
	// Role is the member's role in the project (ProjectRoleOwner or
	// ProjectRoleAdmin).
	Role string
	// PublishableKey is the public id of the project's oldest active
	// publishable credential, or "" when it has none.
	PublishableKey string
	CreatedAtMs    int64
}

// OwnedProjectRequest is what CreateOwnedProject creates.
type OwnedProjectRequest struct {
	Name    string
	OwnerID string
	// MaxOwned is how many projects OwnerID may own, this one included.
	MaxOwned int
	// PublishableKey is the public id of the publishable credential the
	// project is created with.
	PublishableKey string
	// NowMs stamps the rows (now when 0).
	NowMs int64
}

// ProjectMemberStore is the control-plane store of who belongs to which
// project. *pgrepo.ProjectStore satisfies it.
type ProjectMemberStore interface {
	// CreateOwnedProject creates a project, its creator's owner membership
	// and its first publishable credential in one transaction, and returns
	// ErrProjectCreationLimited when OwnerID already owns MaxOwned projects.
	// The count and the insert are serialized per owner, so concurrent
	// requests cannot both pass a limit only one fits under.
	CreateOwnedProject(ctx context.Context, req OwnedProjectRequest) (*MemberProject, error)
	// ListMemberProjects returns the ACTIVE projects userID is a member of,
	// oldest first.
	ListMemberProjects(ctx context.Context, userID string) ([]*MemberProject, error)
	// GetMemberProject returns projectID as userID sees it, or (nil, nil)
	// when userID is not a member of it, the project does not exist, or it is
	// suspended.
	GetMemberProject(ctx context.Context, projectID, userID string) (*MemberProject, error)
}

// ProjectSettingsStore is the part of the control-plane project store the
// console reads and writes a project's config through. See
// ControlPlaneProjectStore for the contract of both methods.
type ProjectSettingsStore interface {
	GetProjectConfig(ctx context.Context, projectID string) (configJSON string, version int64, err error)
	UpdateProjectConfig(ctx context.Context, projectID string, expectedVersion int64, configJSON string) (stored string, version int64, err error)
}

// ProjectConsoleConfig is the console's server-wide configuration.
type ProjectConsoleConfig struct {
	// ConsoleProjectID is the project whose accounts are console accounts:
	// the deployment's own (default) project.
	ConsoleProjectID string
	// SelfServiceProjects lets a console account create projects.
	SelfServiceProjects bool
	// MaxProjectsPerAccount is how many projects one account may own.
	MaxProjectsPerAccount int
}

// ProjectConsoleService implements the project console (ADR-0022): the RPCs a
// project's own members manage it with. Unlike ControlPlaneAdminService,
// which the operator's shared secret authenticates, every call here is made
// by a signed-in account of the console project and authorized by that
// account's membership of the project it names.
//
// It exists only where there is a control plane (postgres): on memory the app
// constructs none and the handler answers Unimplemented.
type ProjectConsoleService struct {
	cfg      ProjectConsoleConfig
	members  ProjectMemberStore
	settings ProjectSettingsStore
	users    UserDirectory
	// repo is the boot repository; scoped to the console project it is where
	// refuseHeldSession reads a session's recovery hold from.
	repo    Repository
	audit   *audit.Logger
	logger  *zap.Logger
	nowFunc func() time.Time
}

// NewProjectConsoleService wires the console service. A nil logger or audit
// logger defaults to a no-op.
func NewProjectConsoleService(
	cfg ProjectConsoleConfig,
	members ProjectMemberStore,
	settings ProjectSettingsStore,
	users UserDirectory,
	repo Repository,
	auditLog *audit.Logger,
	logger *zap.Logger,
) *ProjectConsoleService {
	if logger == nil {
		logger = zap.NewNop()
	}
	if auditLog == nil {
		auditLog = audit.NewLogger(nil, "", zap.NewNop())
	}
	return &ProjectConsoleService{
		cfg:      cfg,
		members:  members,
		settings: settings,
		users:    users,
		repo:     repo,
		audit:    auditLog,
		logger:   logger,
		nowFunc:  time.Now,
	}
}

// SelfServiceProjects reports whether console accounts may create projects.
func (s *ProjectConsoleService) SelfServiceProjects() bool {
	return s.cfg.SelfServiceProjects
}

// requireConsoleAccount admits callerID as a console account: a signed-in,
// active person of the console project with a verified email. A project's
// settings decide who can sign in to it, so the rule is the one for owning a
// tenant (judgeTenantOwner), and an account another party controls, a
// tenant-managed one, is refused as on every path only a personal account
// may take.
//
// The request must have resolved to the console project. A token is only
// ever checked against the project its request resolved to, so this is what
// stops an account of some other project, whose ids the console project knows
// nothing of, from being read as a console account.
func (s *ProjectConsoleService) requireConsoleAccount(ctx context.Context, callerID string) error {
	if callerID == "" {
		return ErrUnauthenticated
	}
	scope := ProjectScopeFromContext(ctx)
	if scope == nil || scope.ProjectID != s.cfg.ConsoleProjectID {
		return fmt.Errorf("%w: the console takes an account of the server's own project", ErrPermissionDenied)
	}
	caller, err := s.users.GetUserInProject(ctx, s.cfg.ConsoleProjectID, callerID)
	if err != nil {
		return err
	}
	if err := refuseManagedAccountPath(ctx, s.logger, s.cfg.ConsoleProjectID, caller, "project_console"); err != nil {
		return err
	}
	switch judgeTenantOwner(caller) {
	case notAnActivePerson:
		return fmt.Errorf("%w: only an active, signed-up person may use the console", ErrPermissionDenied)
	case ownerEmailUnverified:
		return fmt.Errorf("%w: verify your email before using the console", ErrEmailVerificationRequired)
	}
	return nil
}

// requireConsoleChange is requireConsoleAccount for a call whose effect
// outlasts the session: creating a project or changing one's settings. A
// session a recovery hold binds, or whose recovery email is gone, is refused
// (refuseHeldSession), as it is for an admin's changes (requireAdminChange).
func (s *ProjectConsoleService) requireConsoleChange(ctx context.Context, callerID string, signIn SessionSignIn) error {
	// The account check comes first: it is what establishes that the request
	// resolved to the console project, whose repository holds the session.
	if err := s.requireConsoleAccount(ctx, callerID); err != nil {
		return err
	}
	repo := scopedRepository(ctx, s.repo, s.cfg.ConsoleProjectID)
	return refuseHeldSession(ctx, repo, s.logger, callerID, signIn, s.nowFunc().UnixMilli())
}

// requireMember returns projectID as its member callerID sees it. A project
// the caller does not belong to is refused exactly as one that does not
// exist, so the answer says nothing about other people's projects.
func (s *ProjectConsoleService) requireMember(ctx context.Context, callerID, projectID string) (*MemberProject, error) {
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return nil, fmt.Errorf("%w: missing project_id", ErrInvalidArgument)
	}
	project, err := s.members.GetMemberProject(ctx, projectID, callerID)
	if err != nil {
		return nil, err
	}
	if project == nil {
		return nil, fmt.Errorf("%w: not a member of this project", ErrPermissionDenied)
	}
	return project, nil
}

// CreateProject creates a project callerID owns, with one publishable
// credential an application selects it by. The project has no access mode
// yet, and an unset mode denies all authentication (ProjectAccessConfig), so
// it serves nobody until its owner chooses one.
func (s *ProjectConsoleService) CreateProject(ctx context.Context, callerID string, signIn SessionSignIn, name, ip, userAgent string) (*MemberProject, error) {
	if err := s.requireConsoleChange(ctx, callerID, signIn); err != nil {
		return nil, err
	}
	if !s.cfg.SelfServiceProjects {
		return nil, ErrSelfServiceProjectsDisabled
	}
	name, err := normalizeText("name", name, projectNameMaxRunes)
	if err != nil {
		return nil, err
	}

	project, err := s.members.CreateOwnedProject(ctx, OwnedProjectRequest{
		Name:           name,
		OwnerID:        callerID,
		MaxOwned:       s.cfg.MaxProjectsPerAccount,
		PublishableKey: publishableKeyPrefix + randomToken(adminPublicIDBytes),
		NowMs:          s.nowFunc().UnixMilli(),
	})
	if errors.Is(err, ErrProjectCreationLimited) {
		s.auditProject(ctx, audit.EventProjectCreated, callerID, false, ip, userAgent, map[string]any{
			"reason": auditReasonProjectLimit,
		})
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	s.auditProject(ctx, audit.EventProjectCreated, callerID, true, ip, userAgent, map[string]any{
		"project_id": project.ID,
	})
	return project, nil
}

// ListMyProjects returns the active projects callerID is a member of.
func (s *ProjectConsoleService) ListMyProjects(ctx context.Context, callerID string) ([]*MemberProject, error) {
	if err := s.requireConsoleAccount(ctx, callerID); err != nil {
		return nil, err
	}
	return s.members.ListMemberProjects(ctx, callerID)
}

// GetProjectSettings returns the member-editable part of projectID's config
// and the version it was read at.
func (s *ProjectConsoleService) GetProjectSettings(ctx context.Context, callerID, projectID string) (settingsJSON string, version int64, err error) {
	if err := s.requireConsoleAccount(ctx, callerID); err != nil {
		return "", 0, err
	}
	project, err := s.requireMember(ctx, callerID, projectID)
	if err != nil {
		return "", 0, err
	}
	configJSON, version, err := s.settings.GetProjectConfig(ctx, project.ID)
	if err != nil {
		return "", 0, err
	}
	settingsJSON, err = MemberSettings(configJSON)
	if err != nil {
		return "", 0, err
	}
	return settingsJSON, version, nil
}

// UpdateProjectSettings writes settingsJSON's sections into projectID's
// config, provided the config is still at expectedVersion, and returns the
// settings and version as stored. The merged config passes the same checks
// as an operator's UpsertProjectConfig before it is stored.
//
// The write is a single compare-and-swap on the version the member read, not
// the operator path's read-modify-write retry: a retry would re-apply the
// member's sections over a config they have not seen.
func (s *ProjectConsoleService) UpdateProjectSettings(
	ctx context.Context,
	callerID string, signIn SessionSignIn,
	projectID, settingsJSON string, expectedVersion int64,
	ip, userAgent string,
) (stored string, version int64, err error) {
	if err := s.requireConsoleChange(ctx, callerID, signIn); err != nil {
		return "", 0, err
	}
	project, err := s.requireMember(ctx, callerID, projectID)
	if err != nil {
		return "", 0, err
	}

	current, currentVersion, err := s.settings.GetProjectConfig(ctx, project.ID)
	if err != nil {
		return "", 0, err
	}
	if currentVersion != expectedVersion {
		return "", 0, ErrProjectConfigConflict
	}
	next, changed, err := ApplyMemberSettings(current, settingsJSON)
	if err != nil {
		return "", 0, err
	}
	if err := validateProjectConfigJSON(next); err != nil {
		return "", 0, err
	}
	if err := checkNewHostKeys(current, next); err != nil {
		return "", 0, err
	}
	if len(changed) == 0 {
		// Nothing to store. Writing anyway would advance the version, and
		// with it refuse whoever else is editing for a change nobody made.
		stored, err = MemberSettings(current)
		return stored, currentVersion, err
	}

	storedConfig, version, err := s.settings.UpdateProjectConfig(ctx, project.ID, expectedVersion, next)
	if err != nil {
		return "", 0, err
	}
	s.auditProject(ctx, audit.EventProjectSettingsUpdated, callerID, true, ip, userAgent, map[string]any{
		"project_id": project.ID,
		"sections":   changed,
	})
	stored, err = MemberSettings(storedConfig)
	if err != nil {
		return "", 0, err
	}
	return stored, version, nil
}

// auditProject records a console event. The actor is the console account and
// the event lands under the console project, where that account lives; the
// project acted on is in the details.
func (s *ProjectConsoleService) auditProject(ctx context.Context, event audit.EventType, callerID string, ok bool, ip, userAgent string, details map[string]any) {
	s.audit.Log(ctx, event,
		audit.WithActor(callerID), audit.WithTarget(callerID),
		audit.WithIP(ip), audit.WithUserAgent(userAgent),
		audit.WithSuccess(ok), audit.WithDetails(details),
	)
}
