package service

// Clone copies a user without sharing nullable profile values with storage.
func (u *User) Clone() *User {
	if u == nil {
		return nil
	}
	copy := *u
	if u.DateOfBirthMs != nil {
		copy.DateOfBirthMs = new(*u.DateOfBirthMs)
	}
	return &copy
}
