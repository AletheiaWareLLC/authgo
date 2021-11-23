package authgo

import "time"

type Database interface {
	Close() error

	CreateUser(string, string, []byte, time.Time) (int64, error)
	SelectUser(string) (int64, string, []byte, time.Time, error)
	SelectUsernameByEmail(string) (string, error)
	ChangePassword(string, []byte) (int64, error)

	IsEmailVerified(string) (bool, error)
	SetEmailVerified(string, bool) (int64, error)

	CreateSignUpSession(string, time.Time) (int64, error)
	SelectSignUpSession(string) (string, string, string, string, string, time.Time, error)
	UpdateSignUpSessionError(string, string) (int64, error)
	UpdateSignUpSessionIdentity(string, string, string) (int64, error)
	UpdateSignUpSessionChallenge(string, string) (int64, error)
	UpdateSignUpSessionReferrer(string, string) (int64, error)

	CreateSignInSession(string, string, bool, time.Time) (int64, error)
	SelectSignInSession(string) (string, string, time.Time, bool, error)
	UpdateSignInSessionError(string, string) (int64, error)
	UpdateSignInSessionUsername(string, string) (int64, error)
	UpdateSignInSessionAuthenticated(string, bool) (int64, error)

	CreateAccountPasswordSession(string, string, time.Time) (int64, error)
	SelectAccountPasswordSession(string) (string, string, time.Time, error)
	UpdateAccountPasswordSessionError(string, string) (int64, error)

	CreateAccountRecoverySession(string, time.Time) (int64, error)
	SelectAccountRecoverySession(string) (string, string, string, string, time.Time, error)
	UpdateAccountRecoverySessionError(string, string) (int64, error)
	UpdateAccountRecoverySessionEmail(string, string) (int64, error)
	UpdateAccountRecoverySessionUsername(string, string) (int64, error)
	UpdateAccountRecoverySessionChallenge(string, string) (int64, error)
}
