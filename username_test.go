package authgo_test

import (
	"aletheiaware.com/authgo"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestValidateUsername(t *testing.T) {
	t.Run("TooShort", func(t *testing.T) {
		assert.Equal(t, authgo.ErrUsernameTooShort, authgo.ValidateUsername("a"))
		assert.Equal(t, authgo.ErrUsernameTooShort, authgo.ValidateUsername("aa"))
	})
	t.Run("TooLong", func(t *testing.T) {
		assert.Equal(t, authgo.ErrUsernameTooLong, authgo.ValidateUsername(strings.Repeat("a", authgo.MAXIMUM_USERNAME_LENGTH+1)))
	})
	t.Run("Valid", func(t *testing.T) {
		assert.Nil(t, authgo.ValidateUsername("alice"))
		assert.Nil(t, authgo.ValidateUsername("bob"))
		assert.Nil(t, authgo.ValidateUsername("charlie"))
		assert.Nil(t, authgo.ValidateUsername("AlIcE"))
		assert.Nil(t, authgo.ValidateUsername("BoB"))
		assert.Nil(t, authgo.ValidateUsername("ChArLiE"))
	})
	t.Run("Invalid", func(t *testing.T) {
		for name, username := range map[string]string{
			"space":       "a b",
			"spaces":      "a b c",
			"exclamation": "a!b",
			"question":    "a?b",
			"at":          "a@b",
			"hash":        "a#b",
			"dollar":      "a$b",
			"percent":     "a%%b",
			"caret":       "a^b",
			"and":         "a&b",
			"asterisk":    "a*b",
			"openround":   "a(b",
			"closeround":  "a)b",
			"opensquare":  "a[b",
			"closesquare": "a]b",
			"opencurly":   "a{b",
			"closecurly":  "a}b",
			"openangle":   "a<b",
			"closeangle":  "a>b",
			"hyphen":      "a-b",
			"underscore":  "a_b",
			"plus":        "a+b",
			"equals":      "a=b",
			"backslash":   "a\\b",
			"foreslash":   "a/b",
			"pipe":        "a|b",
			"singlequote": "a'b",
			"doublequote": "a\"b",
			"colon":       "a:b",
			"semicolor":   "a;b",
			"period":      "a.b",
			"coma":        "a,b",
			"graveaccent": "a`b",
			"tilde":       "a~b",
		} {
			t.Run(name, func(t *testing.T) {
				assert.Equal(t, authgo.ErrUsernameInvalid, authgo.ValidateUsername(username))
			})
		}
	})
}
