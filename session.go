package authgo

import (
	"aletheiaware.com/cryptogo"
	"time"
)

const (
	SESSION_TOKEN_LENGTH             = 16
	SESSION_SIGN_IN_TIMEOUT          = 30 * time.Minute
	SESSION_SIGN_UP_TIMEOUT          = 10 * time.Minute
	SESSION_ACCOUNT_PASSWORD_TIMEOUT = 5 * time.Minute
	SESSION_ACCOUNT_RECOVERY_TIMEOUT = 5 * time.Minute
)

func NewSessionToken() (string, error) {
	return cryptogo.RandomString(SESSION_TOKEN_LENGTH)
}
