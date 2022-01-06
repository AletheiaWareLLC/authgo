package authgo_test

import (
	"aletheiaware.com/authgo"
	"aletheiaware.com/authgo/authtest"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

var password = []byte(authtest.TEST_PASSWORD)

func Test_ValidatePassword(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		assert.NoError(t, authgo.ValidatePassword(password))
	})
	t.Run("Short", func(t *testing.T) {
		password := []byte(strings.Repeat("x", authgo.MINIMUM_PASSWORD_LENGTH-1))
		assert.Error(t, authgo.ErrPasswordTooShort, authgo.ValidatePassword(password))
	})
	t.Run("Long", func(t *testing.T) {
		password := []byte(strings.Repeat("x", authgo.MAXIMUM_PASSWORD_LENGTH+1))
		assert.Error(t, authgo.ErrPasswordTooLong, authgo.ValidatePassword(password))
	})
}

func Test_MatchPasswords(t *testing.T) {
	t.Run("Matching", func(t *testing.T) {
		assert.NoError(t, authgo.MatchPasswords(password, password))
	})
	t.Run("NotMatching", func(t *testing.T) {
		assert.Error(t, authgo.ErrPasswordsDoNotMatch, authgo.MatchPasswords(password, []byte("1234password")))
	})
}

func Test_PasswordHash(t *testing.T) {
	hash, err := authgo.GeneratePasswordHash(password)
	assert.NoError(t, err)
	t.Run("Matching", func(t *testing.T) {
		assert.True(t, authgo.CheckPasswordHash(hash, password))
	})
	t.Run("NotMatching", func(t *testing.T) {
		assert.False(t, authgo.CheckPasswordHash(hash, []byte("1234password")))
	})
}
