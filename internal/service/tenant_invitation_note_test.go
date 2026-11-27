package service

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/email"
)

func TestNormalizeInvitationNote_Accepted(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, in, want string }{
		{"empty", "", ""},
		{"only whitespace", "  \n\t \r\n ", ""},
		{"plain email address", "Your mail address will be jane@example.com", "Your mail address will be jane@example.com"},
		{"plain sentence with an email address", "Hi Jane, write to jane@example.org if anything is unclear.", "Hi Jane, write to jane@example.org if anything is unclear."},
		{"email address ending a sentence", "Write to jane_doe+team@example.com.", "Write to jane_doe+team@example.com."},
		{"email address on a subdomain", "Write to jane@mail.example.com", "Write to jane@mail.example.com"},
		{"email address in brackets", "(ask jane@example.com)", "(ask jane@example.com)"},
		{"uppercase email address", "Mail JANE@EXAMPLE.COM", "Mail JANE@EXAMPLE.COM"},
		{"email address after a label and a space", "Contact: jane@example.com", "Contact: jane@example.com"},
		{"email address after a fullwidth comma", "ようこそ、jane@example.com", "ようこそ、jane@example.com"},
		{"email address next to fullwidth punctuation", "（jane@example.com）！", "（jane@example.com）！"},
		{"abbreviation before a space", "Dr. Smith says hi. See you at 9 a. m.", "Dr. Smith says hi. See you at 9 a. m."},
		{"six digits", "Room 123456 or 12 34 56", "Room 123456 or 12 34 56"},
		{"colon after a scheme word with a space", "Data: the shared folder. Tel: ask reception.", "Data: the shared folder. Tel: ask reception."},
		{"time", "Stand-up at 10:30", "Stand-up at 10:30"},
		{"ellipsis and dashes", "Welcome… see you Monday — Acme team", "Welcome… see you Monday — Acme team"},
		{"japanese sentence", "ようこそ。", "ようこそ。"},
		{"japanese sentences with a space", "ようこそ。 明日から始めましょう。", "ようこそ。 明日から始めましょう。"},
		{"japanese sentences with no space", "ようこそ。明日から始めましょう。", "ようこそ。明日から始めましょう。"},
		{"japanese sentences after a prolonged sound mark", "コーヒー。明日もどうぞ。", "コーヒー。明日もどうぞ。"},
		{"japanese sentences with a halfwidth full stop", "ようこそ｡明日から", "ようこそ｡明日から"},
		{"chinese sentences with no space", "欢迎。明天见。", "欢迎。明天见。"},
		{"korean sentences with no space", "환영합니다。내일 봐요。", "환영합니다。내일 봐요。"},
		{"cyrillic sentence", "Привет, команда.", "Привет, команда."},
		{"emoji joined by ZWJ", "Welcome 👩\u200D💻", "Welcome 👩\u200D💻"},
		{"persian with ZWNJ", "می\u200Cخواهم", "می\u200Cخواهم"},
		{"lines trimmed and CRLF read as LF", "  Hi Jane, \r\n  welcome aboard.  ", "Hi Jane,\nwelcome aboard."},
		{"four lines", "a\nb\nc\nd", "a\nb\nc\nd"},
		{"at the length cap", strings.Repeat("é", maxInvitationNoteRunes), strings.Repeat("é", maxInvitationNoteRunes)},
		{"at the length cap counting line breaks", strings.Repeat("a", 139) + "\n" + strings.Repeat("b", 140), strings.Repeat("a", 139) + "\n" + strings.Repeat("b", 140)},
		{"surrounding space past the cap", "  " + strings.Repeat("a", maxInvitationNoteRunes) + "  ", strings.Repeat("a", maxInvitationNoteRunes)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := normalizeInvitationNote(tc.in)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestNormalizeInvitationNote_Refused(t *testing.T) {
	t.Parallel()
	const (
		markup = "link or markup"
		dotted = "no web addresses or dotted words"
		scheme = "colon and text"
		phone  = "phone number"
		email  = "email address only in plain ASCII"
	)
	for _, tc := range []struct{ name, in, reason string }{
		{"one past the length cap", strings.Repeat("é", maxInvitationNoteRunes+1), "longer than 280"},
		{"five lines", "a\nb\nc\nd\ne", "more than 4 lines"},
		{"blank line", "Hi\n\nwelcome", "blank line"},
		{"line of spaces", "Hi\n   \nwelcome", "blank line"},
		{"invalid UTF-8", "Hi \xff", "UTF-8"},
		{"NUL", "Hi\x00there", "control"},
		{"tab", "Hi\tthere", "control"},
		{"lone carriage return", "Hi\rthere", "control"},
		{"escape", "Hi\x1b[31mthere", "control"},
		{"next line", "Hi\u0085there", "control"},
		{"right-to-left override", "Hi \u202Emoc.elpmaxe", "invisible"},
		{"left-to-right isolate", "Hi \u2066there\u2069", "invisible"},
		{"left-to-right mark", "Hi\u200Ethere", "invisible"},
		{"arabic letter mark", "Hi\u061Cthere", "invisible"},
		{"byte order mark", "Hi\uFEFFthere", "invisible"},
		{"soft hyphen", "Hi\u00ADthere", "invisible"},
		{"zero-width space", "Hi\u200Bthere", "invisible"},
		{"line separator", "Hi\u2028there", "invisible"},
		{"paragraph separator", "Hi\u2029there", "invisible"},

		{"https URL", "Sign in at https://example.com", markup},
		{"scheme without a known name", "go to hxxp://example", markup},
		{"HTML anchor", `<a href="x">here</a>`, markup},
		{"angle bracket", "a > b", markup},
		{"fullwidth angle bracket", "＜b＞hi", markup},
		{"markdown link", "[click](x)", markup},

		{"bare domain", "Sign in at example.com", dotted},
		{"www host", "Visit www.example now", dotted},
		{"uppercase domain", "Visit WWW.EXAMPLE.COM", dotted},
		{"domain and path", "see example.com/login", dotted},
		{"domain in brackets", "(acme.example)", dotted},
		{"subdomain", "auth.acme.example", dotted},
		{"punycode domain", "xn--80ak6aa92e.xn--p1ai", dotted},
		{"IPv4 address", "use 192.168.0.1", dotted},
		{"cyrillic lookalike letter", "Sign in at ex\u0430mple.com", dotted},
		{"cyrillic domain", "пример.рф", dotted},
		{"fullwidth domain", "ｅｘａｍｐｌｅ．ｃｏｍ", dotted},
		{"mathematical bold domain", "𝐞𝐱𝐚𝐦𝐩𝐥𝐞.𝐜𝐨𝐦", dotted},
		{"ideographic full stop for a dot", "example。com", dotted},
		{"halfwidth ideographic full stop for a dot", "example｡com", dotted},
		{"one dot leader for a dot", "example․com", dotted},
		{"ideographic full stop between CJK and a Latin label", "例子。com", dotted},
		{"ZWJ hiding a domain", "exa\u200Dmple.com", dotted},
		{"ZWNJ before the dot", "example\u200C.com", dotted},
		{"domain followed by a plus", "evil.com+login", dotted},
		{"domain followed by an underscore", "evil.com_login", dotted},
		{"domain followed by a dot and a digit", "evil.com.1", dotted},
		{"domain followed by a hyphen and a digit", "evil.com-1", dotted},
		{"domain followed by a non-ASCII digit", "evil.com\u0661", dotted},
		{"dotted word", "Built with Node.js", dotted},
		{"version", "v1.2 ships today", dotted},
		{"decimal", "at 3.14 pm", dotted},
		{"abbreviation without a space", "Bring e.g. a laptop", dotted},
		{"missing space after a full stop", "We are done.See you", dotted},
		{"ideographic full stop between CJK and a Latin label after kana", "ここ。com", dotted},
		{"halfwidth ideographic full stop between CJK and a Latin label", "ここ｡com", dotted},
		{"ideographic full stops between CJK and Latin labels", "例子。evil。com", dotted},
		{"ideographic full stop between a Latin label and CJK", "evil。例子", dotted},

		{"mailto", "mailto:jane@example.com", scheme},
		{"tel", "Call tel:+15550100", scheme},
		{"sms", "sms:+15550100", scheme},
		{"javascript", "javascript:alert(1)", scheme},
		{"data", "data:text/html,hi", scheme},
		{"skype", "skype:jane.doe?call", scheme},
		{"magnet", "magnet:?xt=urn:btih:abc", scheme},
		{"scheme with a plus, digit and dot", "web+app2.x:open", scheme},
		{"uppercase scheme", "MAILTO:jane", scheme},
		{"fullwidth scheme", "ｍａｉｌｔｏ：jane", scheme},
		{"domain with a port", "example:8443", scheme},
		{"email address with a port", "jane@example.com:8443", scheme},
		{"sip address", "sip:jane@example.com", scheme},
		{"xmpp address", "Chat at xmpp:jane@example.com", scheme},
		{"uppercase scheme before an address", "SIP:jane@example.com", scheme},
		{"fullwidth colon after a scheme before an address", "xmpp：jane@example.com", scheme},
		{"mailto before an address", "Mail mailto:jane@example.com today", scheme},

		{"phone number", "Call +1 (555) 010-0199", phone},
		{"phone number with spaces", "555 010 0199", phone},
		{"seven digits", "Room 1234567", phone},
		{"fullwidth digits", "１２３４５６７", phone},
		{"date", "Starts 2026-11-27", phone},

		{"handle with no local part", "ping @jane", email},
		{"address with no local part", "@example.com", email},
		{"two at signs", "jane@@example.com", email},
		{"address with two at signs", "jane@bob@example.com", email},
		{"address with no domain dot", "jane@localhost", email},
		{"address with a dotted local part", "jane.doe@example.org", email},
		{"address whose local part is a website", "www.evil.com@example.org", email},
		{"address whose local part ends in a dot", "jane.@example.com", email},
		{"address with a lookalike domain", "jane@ex\u0430mple.com", email},
		{"address with a non-ASCII local part", "jäne@example.com", email},
		{"address with a one-letter top-level label", "jane@example.x", email},
		{"address with a numeric top-level label", "jane@example.1", email},
		{"address followed by a plus", "jane@example.com+login", email},
		{"address followed by an underscore", "jane@example.com_login", email},
		{"fullwidth email address", "Mail ｊａｎｅ＠ｅｘａｍｐｌｅ．ｃｏｍ", email},
		{"fullwidth at sign", "jane＠example.com", email},
		{"fullwidth at sign before a path", "jane＠example.com/login", email},
		{"fullwidth at sign before a port", "jane＠example.com:8443", email},
		{"small at sign", "jane﹫example.com", email},
		{"small at sign before a path", "jane﹫example.com/login", email},
		{"small at sign before a port and path", "jane﹫example.com:8443/login", email},
		{"fullwidth at sign and fullwidth dot", "jane＠example．com/login", email},
		{"small at sign and ideographic full stop", "jane﹫example。com/login", email},
		{"fullwidth dot in the domain of an ASCII address", "jane@example．com/login", email},
		{"ideographic full stop in the domain of an ASCII address", "jane@example。com", email},
		{"fullwidth letters in the domain of an ASCII address", "jane@ｅｘａｍｐｌｅ.com/login", email},
		{"fullwidth slash after a lookalike address", "jane＠example.com／login", email},
		{"unknown scheme before a lookalike address", "im:jane＠example.com", email},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := normalizeInvitationNote(tc.in)
			require.ErrorIs(t, err, ErrInvalidArgument)
			require.Contains(t, err.Error(), tc.reason)
			require.Empty(t, got)
			require.NotContains(t, err.Error(), tc.in, "the refusal does not repeat the note")
		})
	}
}

const noteLabel = "A note from the administrator who invited you:"

// withNotesProject is withProject for a project whose tenant policy allows
// invitation notes or not.
func withNotesProject(allowed bool) context.Context {
	return withTenantsPolicy(ProjectTenantsConfig{InvitationNotes: allowed})
}

// withTenantsPolicy is withProject for a project with the tenant policy
// tenants, taken as given, unvalidated.
func withTenantsPolicy(tenants ProjectTenantsConfig) context.Context {
	return WithProjectScope(context.Background(), &ProjectScope{
		ProjectID: mTestProject,
		Access:    ProjectAccessConfig{Mode: AccessModeOpen},
		Tenants:   tenants,
	})
}

// A note on an invitation to an operator's tenant, where the project allows
// notes, is in both parts of the email: quoted line by line in the text part,
// and escaped, its lines kept apart, in the HTML part.
func TestCreateTenantInvitation_NoteInTheEmail(t *testing.T) {
	f := newMembershipFixture()
	f.seedAdmin(mTestProject, mTestTenant, mAdminID)

	out, err := f.svc.CreateTenantInvitation(withNotesProject(true), mAdminID, SessionSignIn{}, mTestTenant, mInvitee, RoleMember,
		" Your mail address will be jane@example.com \r\nTom & Jerry's \"team\" says hi")
	require.NoError(t, err)
	require.Equal(t, EmailSent, out.EmailStatus)
	require.Equal(t, 1, f.mailer.count())
	msg := f.mailer.last()

	require.Contains(t, msg.Text, "become a member.\n\n"+noteLabel+"\n> Your mail address will be jane@example.com\n> Tom & Jerry's \"team\" says hi\n\nhttp")
	require.Contains(t, msg.HTML, noteLabel)
	require.Contains(t, msg.HTML, ">Your mail address will be jane@example.com<br>Tom &amp; Jerry&#39;s &#34;team&#34; says hi</blockquote>")
}

// With no note, or one that is only whitespace, the email carries no note
// section, whether or not the project allows notes.
func TestCreateTenantInvitation_NoNoteNoNoteSection(t *testing.T) {
	for _, tc := range []struct {
		name    string
		allowed bool
		note    string
	}{
		{"none, notes allowed", true, ""},
		{"none, notes not allowed", false, ""},
		{"whitespace, notes not allowed", false, " \r\n\t "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newMembershipFixture()
			f.seedAdmin(mTestProject, mTestTenant, mAdminID)

			_, err := f.svc.CreateTenantInvitation(withNotesProject(tc.allowed), mAdminID, SessionSignIn{}, mTestTenant, mInvitee, RoleMember, tc.note)
			require.NoError(t, err)
			msg := f.mailer.last()
			for part, body := range map[string]string{"text": msg.Text, "html": msg.HTML} {
				require.NotContains(t, body, "A note from", part)
				require.NotContains(t, body, "blockquote", part)
			}
		})
	}
}

// A note is refused before anything is stored or sent: where the project does
// not allow notes, even if it allows them on self-service tenants; on a tenant
// a user created unless the project allows notes there too; and when it reads
// as a link, on any tenant. A caller who is not an owner or admin is refused
// as one, so a note never tells them whether the project allows notes or
// whether the tenant is one a user created.
func TestCreateTenantInvitation_NoteRefused(t *testing.T) {
	off := ProjectTenantsConfig{}
	notes := ProjectTenantsConfig{InvitationNotes: true}
	both := ProjectTenantsConfig{InvitationNotes: true, InvitationNotesSelfService: true}
	selfServiceOnly := ProjectTenantsConfig{InvitationNotesSelfService: true}
	for _, tc := range []struct {
		name      string
		policy    ProjectTenantsConfig
		createdBy string
		role      string
		note      string
		want      error
	}{
		{"project does not allow notes", off, "", RoleOwner, "Welcome aboard", ErrInvitationNoteNotAllowed},
		{"self-service tenant, notes allowed only elsewhere", notes, "user-creator", RoleOwner, "Welcome aboard", ErrInvitationNoteNotAllowed},
		{"self-service setting without notes, self-service tenant", selfServiceOnly, "user-creator", RoleOwner, "Welcome aboard", ErrInvitationNoteNotAllowed},
		{"self-service setting without notes, operator tenant", selfServiceOnly, "", RoleOwner, "Welcome aboard", ErrInvitationNoteNotAllowed},
		{"link", notes, "", RoleOwner, "Sign in at example.com", ErrInvalidArgument},
		{"link where notes are not allowed", off, "", RoleOwner, "Sign in at example.com", ErrInvalidArgument},
		{"link on a self-service tenant allowed notes", both, "user-creator", RoleOwner, "Sign in at example.com", ErrInvalidArgument},
		{"lookalike domain on a self-service tenant allowed notes", both, "user-creator", RoleOwner, "Sign in at ex\u0430mple.com", ErrInvalidArgument},
		{"bidirectional override", notes, "", RoleOwner, "Hi \u202Emoc.elpmaxe", ErrInvalidArgument},
		{"over the cap on a self-service tenant allowed notes", both, "user-creator", RoleOwner, strings.Repeat("a", maxInvitationNoteRunes+1), ErrInvalidArgument},
		{"plain member of a self-service tenant", notes, "user-creator", RoleMember, "Welcome aboard", ErrPermissionDenied},
		{"plain member where self-service tenants allow notes", both, "user-creator", RoleMember, "Welcome aboard", ErrPermissionDenied},
		{"plain member where the project does not allow notes", off, "", RoleMember, "Welcome aboard", ErrPermissionDenied},
		{"plain member with a link", off, "", RoleMember, "Sign in at example.com", ErrPermissionDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newMembershipFixture()
			f.tenants.put(&Tenant{ID: mTestTenant, ProjectID: mTestProject, Status: TenantStatusClaimed, CreatedBy: tc.createdBy})
			f.seedMember(mTestProject, mTestTenant, mAdminID, tc.role)

			_, err := f.svc.CreateTenantInvitation(withTenantsPolicy(tc.policy), mAdminID, SessionSignIn{}, mTestTenant, mInvitee, RoleMember, tc.note)
			require.ErrorIs(t, err, tc.want)
			require.Empty(t, f.invitations.byID, "a refused invitation is not stored")
			require.Zero(t, f.mailer.count(), "a refused invitation sends no email")
		})
	}
}

// With notes allowed, and on self-service tenants too, an owner or admin of
// either kind of tenant sends a note, normalized as anywhere else, and the
// self-service tenant's name still stays out of the email.
func TestCreateTenantInvitation_NoteOnSelfServiceTenantWhereAllowed(t *testing.T) {
	const crafted = "Payroll update"
	for _, tc := range []struct {
		name      string
		createdBy string
		role      string
	}{
		{"self-service tenant, owner", "user-creator", RoleOwner},
		{"self-service tenant, admin", "user-creator", RoleAdmin},
		{"operator tenant", "", RoleOwner},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newMembershipFixture()
			f.tenants.put(&Tenant{ID: mTestTenant, ProjectID: mTestProject, Name: crafted, Status: TenantStatusClaimed, CreatedBy: tc.createdBy})
			f.seedMember(mTestProject, mTestTenant, mAdminID, tc.role)
			policy := ProjectTenantsConfig{InvitationNotes: true, InvitationNotesSelfService: true}

			_, err := f.svc.CreateTenantInvitation(withTenantsPolicy(policy), mAdminID, SessionSignIn{}, mTestTenant, mInvitee, RoleMember,
				"  Your mail address will be jane@example.com  \r\nSee you Monday.")
			require.NoError(t, err)
			msg := f.mailer.last()
			require.Contains(t, msg.Text, noteLabel+"\n> Your mail address will be jane@example.com\n> See you Monday.\n")
			require.Contains(t, msg.HTML, ">Your mail address will be jane@example.com<br>See you Monday.</blockquote>")
			if tc.createdBy != "" {
				require.NotContains(t, msg.Text, crafted, "a self-service tenant's name stays out")
				require.NotContains(t, msg.HTML, crafted, "a self-service tenant's name stays out")
			}
		})
	}
}

// The note is not stored with the invitation: a resend is a new call, and its
// email carries the note that call passes, the same note when it passes it
// again and none when it passes none.
func TestCreateTenantInvitation_ResendCarriesItsOwnNote(t *testing.T) {
	f := newMembershipFixture()
	f.seedAdmin(mTestProject, mTestTenant, mAdminID)
	ctx := withNotesProject(true)
	start := time.Now()
	cooldown := config.DefaultTenantInvitationResendCooldownSeconds*time.Second + time.Second
	const note = "Your mail address will be jane@example.com"

	for i, sent := range []string{note, note, ""} {
		f.svc.nowFunc = func() time.Time { return start.Add(time.Duration(i) * cooldown) }
		out, err := f.svc.CreateTenantInvitation(ctx, mAdminID, SessionSignIn{}, mTestTenant, mInvitee, RoleMember, sent)
		require.NoError(t, err, "send %d", i)
		msg := f.mailer.last()
		if sent == "" {
			require.NotContains(t, msg.Text, note, "send %d", i)
			require.NotContains(t, msg.HTML, note, "send %d", i)
		} else {
			require.Contains(t, msg.Text, "> "+note, "send %d", i)
			require.Contains(t, msg.HTML, note, "send %d", i)
		}
		open := 0
		for _, inv := range f.invitations.byID {
			if inv.Status == InvitationStatusPending {
				open++
				require.Equal(t, out.Invitation.ID, inv.ID, "the resend revoked the earlier invitation")
			}
		}
		require.Equal(t, 1, open)
	}
	require.Equal(t, 3, f.mailer.count())
}

// No log line carries the note, including those of a send that fails.
func TestCreateTenantInvitation_NoteIsNotLogged(t *testing.T) {
	core, logs := observer.New(zap.DebugLevel)
	logger := zap.New(core)
	f := newMembershipFixture()
	f.svc = NewMembershipService(f.invitations, f.memberships, f.tenants, f.users,
		email.NewChain(logger, &recordingMailer{sendErr: email.ErrTransport}), true, &config.Config{}, logger)
	f.seedAdmin(mTestProject, mTestTenant, mAdminID)
	const note = "Your mail address will be jane@example.com"

	out, err := f.svc.CreateTenantInvitation(withNotesProject(true), mAdminID, SessionSignIn{}, mTestTenant, mInvitee, RoleMember, note)
	require.NoError(t, err)
	require.Equal(t, EmailSendFailed, out.EmailStatus)
	require.NotZero(t, logs.Len())
	for _, entry := range logs.All() {
		require.NotContains(t, entry.Message, "jane@example.com")
		for key, value := range entry.ContextMap() {
			require.NotContains(t, key+"="+fmt.Sprint(value), "jane@example.com", entry.Message)
		}
	}
}
