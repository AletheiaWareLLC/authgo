package authgo

import "aletheiaware.com/cryptogo"

const SESSION_TOKEN_LENGTH = 16

func NewSessionToken() (string, error) {
	return cryptogo.RandomString(SESSION_TOKEN_LENGTH)
}
