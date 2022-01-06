package authgo_test

import (
	"aletheiaware.com/authgo"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func Test_ValidateEmail(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		for _, tt := range []string{
			"foo@bar.baz",
			"foo.bar@foo.bar",
			"foo+bar@foo.bar",
		} {
			assert.NoError(t, authgo.ValidateEmail(tt))
		}
	})
	t.Run("Invalid", func(t *testing.T) {
		for _, tt := range []string{
			"foo",
			"foo.bar",
			"foo@bar",
			"foo.bar@baz",
			"foo@bar@baz",
			"foo@bar+baz",
		} {
			assert.Error(t, authgo.ErrEmailInvalid, authgo.ValidateEmail(tt))
		}
	})
	t.Run("Long", func(t *testing.T) {
		emailLong := strings.Repeat("x", authgo.MAXIMUM_EMAIL_LENGTH+1)
		assert.Error(t, authgo.ErrEmailTooLong, authgo.ValidateEmail(emailLong))
	})
}
