package service

import "time"

func (f UserListFilter) Matches(u *User) bool {
	return u != nil &&
		(f.Email == "" || FoldEmail(u.Email) == FoldEmail(f.Email)) &&
		(f.ExternalID == "" || u.ExternalID == f.ExternalID) &&
		(f.IncludeAnonymous || !u.IsAnonymous) &&
		(f.IncludeAgents || !u.IsAgent()) &&
		(f.OwnerUserID == "" || u.OwnerUserID == f.OwnerUserID) &&
		(f.PendingOwnerUserID == "" || u.PendingOwnerUserID == f.PendingOwnerUserID)
}

func (u *User) SettleAgentTransfer(pendingOwnerID string, accept bool, atMs int64) bool {
	if !u.IsAgent() || pendingOwnerID == "" || u.PendingOwnerUserID != pendingOwnerID {
		return false
	}
	if accept {
		u.OwnerUserID = pendingOwnerID
	}
	u.PendingOwnerUserID = ""
	u.UpdatedAt = time.UnixMilli(atMs)
	return true
}

func (u *User) SetAgentOwnership(expectedOwnerID, ownerID, pendingOwnerID string, atMs int64) bool {
	if !u.IsAgent() || expectedOwnerID == "" || ownerID == "" || u.OwnerUserID != expectedOwnerID {
		return false
	}
	u.OwnerUserID, u.PendingOwnerUserID = ownerID, pendingOwnerID
	u.UpdatedAt = time.UnixMilli(atMs)
	return true
}
