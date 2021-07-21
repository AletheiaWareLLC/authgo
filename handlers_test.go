package authgo_test

import (
	"aletheiaware.com/authgo"
	"aletheiaware.com/authgo/authtest"
	"github.com/stretchr/testify/assert"
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"
)

func TestAccount(t *testing.T) {
	tmpl, err := template.New("account.go.html").Parse(`{{.Account.Username}}`)
	assert.Nil(t, err)
	t.Run("Returns 200 When Signed In", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		authtest.NewTestAccount(t, a)
		token, _ := authtest.SignIn(t, a)
		mux := http.NewServeMux()
		authgo.AttachHandlers(a, mux, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/account", nil)
		request.AddCookie(authgo.NewSignInCookie(token))
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Equal(t, authtest.TEST_USERNAME, string(body))
	})
	t.Run("Redirects When Not Signed In", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		mux := http.NewServeMux()
		authgo.AttachHandlers(a, mux, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/account", nil)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/sign-in", u.String())
	})
}

func TestAccountPassword(t *testing.T) {
	tmpl, err := template.New("account-password.go.html").Parse(`{{.Error}}`)
	assert.Nil(t, err)
	t.Run("Returns 200 When Signed In", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		authtest.NewTestAccount(t, a)
		token, _ := authtest.SignIn(t, a)
		mux := http.NewServeMux()
		authgo.AttachHandlers(a, mux, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/account-password", nil)
		request.AddCookie(authgo.NewSignInCookie(token))
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Empty(t, string(body))
	})
	t.Run("Redirects When Not Signed In", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		mux := http.NewServeMux()
		authgo.AttachHandlers(a, mux, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/account-password", nil)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/sign-in", u.String())
	})
	t.Run("Redirects After Password Change", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		authtest.NewTestAccount(t, a)
		token, _ := authtest.SignIn(t, a)
		mux := http.NewServeMux()
		authgo.AttachHandlers(a, mux, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/account-password", nil)
		request.AddCookie(authgo.NewSignInCookie(token))
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		cookies := result.Cookies()
		assert.Equal(t, 2, len(cookies))
		assert.Equal(t, authgo.SESSION_SIGN_IN_COOKIE, cookies[0].Name)
		assert.Equal(t, authgo.SESSION_ACCOUNT_PASSWORD_COOKIE, cookies[1].Name)
		assert.Empty(t, string(body))
		values := url.Values{}
		values.Add("password", authtest.TEST_PASSWORD)
		values.Add("confirmation", authtest.TEST_PASSWORD)
		reader := strings.NewReader(values.Encode())
		request = httptest.NewRequest(http.MethodPost, "/account-password", reader)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(cookies[0])
		request.AddCookie(cookies[1])
		response = httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result = response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/account", u.String())
	})
	t.Run("Redirects When Form Data Is Invalid", func(t *testing.T) {
		for name, tt := range map[string]struct {
			form   map[string]string
			result string
		}{
			"Password Too Short": {
				form: map[string]string{
					"password":     "password",
					"confirmation": "password",
				},
				result: authgo.ErrPasswordTooShort.Error(),
			},
			"Passwords Do Not Match": {
				form: map[string]string{
					"password":     authtest.TEST_PASSWORD,
					"confirmation": "1234password",
				},
				result: authgo.ErrPasswordsDoNotMatch.Error(),
			},
		} {
			t.Run(name, func(t *testing.T) {
				a := authtest.NewAuthenticator(t)
				authtest.NewTestAccount(t, a)
				token, _ := authtest.SignIn(t, a)
				mux := http.NewServeMux()
				authgo.AttachHandlers(a, mux, tmpl)
				request := httptest.NewRequest(http.MethodGet, "/account-password", nil)
				request.AddCookie(authgo.NewSignInCookie(token))
				response := httptest.NewRecorder()
				mux.ServeHTTP(response, request)
				result := response.Result()
				assert.Equal(t, http.StatusOK, result.StatusCode)
				body, err := io.ReadAll(result.Body)
				assert.Nil(t, err)
				assert.Empty(t, string(body))
				cookies := result.Cookies()
				assert.Equal(t, 2, len(cookies))
				signInCookie := cookies[0]
				accountPasswordCookie := cookies[1]
				assert.Equal(t, authgo.SESSION_SIGN_IN_COOKIE, signInCookie.Name)
				assert.Equal(t, authgo.SESSION_ACCOUNT_PASSWORD_COOKIE, accountPasswordCookie.Name)
				values := url.Values{}
				for k, v := range tt.form {
					values.Add(k, v)
				}
				reader := strings.NewReader(values.Encode())
				request = httptest.NewRequest(http.MethodPost, "/account-password", reader)
				request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				request.AddCookie(cookies[0])
				request.AddCookie(cookies[1])
				response = httptest.NewRecorder()
				mux.ServeHTTP(response, request)
				result = response.Result()
				assert.Equal(t, http.StatusFound, result.StatusCode)
				// Sign In Cookie should get refreshed
				cookies = result.Cookies()
				assert.Equal(t, 1, len(cookies))
				signInCookie = cookies[0]
				assert.Equal(t, authgo.SESSION_SIGN_IN_COOKIE, signInCookie.Name)
				u, err := result.Location()
				assert.Nil(t, err)
				assert.Equal(t, "/account-password", u.String())

				// Subsequent Get request should show error
				request = httptest.NewRequest(http.MethodGet, "/account-password", nil)
				request.AddCookie(signInCookie)
				request.AddCookie(accountPasswordCookie)
				response = httptest.NewRecorder()
				mux.ServeHTTP(response, request)
				result = response.Result()
				assert.Equal(t, http.StatusOK, result.StatusCode)
				body, err = io.ReadAll(result.Body)
				assert.Nil(t, err)
				assert.Equal(t, tt.result, string(body))
			})
		}
	})
}

func TestAccountRecovery(t *testing.T) {
	tmpl, err := template.New("account-recovery.go.html").Parse(`{{.Error}}`)
	assert.Nil(t, err)
	t.Run("Redirects When Signed In", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		authtest.NewTestAccount(t, a)
		token, _ := authtest.SignIn(t, a)
		mux := http.NewServeMux()
		authgo.AttachHandlers(a, mux, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/account-recovery", nil)
		request.AddCookie(authgo.NewSignInCookie(token))
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/account", u.String())
	})
	t.Run("Returns 200 When Not Signed In", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		mux := http.NewServeMux()
		authgo.AttachHandlers(a, mux, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/account-recovery", nil)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Empty(t, string(body))
		cookies := result.Cookies()
		assert.Equal(t, 1, len(cookies))
		assert.Equal(t, authgo.SESSION_ACCOUNT_RECOVERY_COOKIE, cookies[0].Name)
	})
	t.Run("Redirects When Email Is Registered", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		acc := authtest.NewTestAccount(t, a)
		assert.Nil(t, a.AccountManager().SetEmailVerified(acc.Email, true))
		mux := http.NewServeMux()
		authgo.AttachHandlers(a, mux, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/account-recovery", nil)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Empty(t, string(body))
		cookies := result.Cookies()
		assert.Equal(t, 1, len(cookies))
		assert.Equal(t, authgo.SESSION_ACCOUNT_RECOVERY_COOKIE, cookies[0].Name)
		reader := strings.NewReader("email=" + authtest.TEST_EMAIL)
		request = httptest.NewRequest(http.MethodPost, "/account-recovery", reader)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(cookies[0])
		response = httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result = response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		body, err = io.ReadAll(result.Body)
		assert.Nil(t, err)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/account-recovery-verification", u.String())
	})
	t.Run("Redirects When Email Is Not Registered", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		mux := http.NewServeMux()
		authgo.AttachHandlers(a, mux, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/account-recovery", nil)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Empty(t, string(body))
		cookies := result.Cookies()
		assert.Equal(t, 1, len(cookies))
		assert.Equal(t, authgo.SESSION_ACCOUNT_RECOVERY_COOKIE, cookies[0].Name)
		reader := strings.NewReader("email=" + authtest.TEST_EMAIL)
		request = httptest.NewRequest(http.MethodPost, "/account-recovery", reader)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(cookies[0])
		response = httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result = response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/account-recovery", u.String())

		// Subsequent Get request should show error
		request = httptest.NewRequest(http.MethodGet, "/account-recovery", nil)
		request.AddCookie(cookies[0])
		response = httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result = response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)
		body, err = io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Equal(t, authgo.ErrEmailNotRegistered.Error(), string(body))
	})
	t.Run("Redirects When Post Requested Before Get", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		mux := http.NewServeMux()
		authgo.AttachHandlers(a, mux, tmpl)
		reader := strings.NewReader("email=" + authtest.TEST_EMAIL)
		request := httptest.NewRequest(http.MethodPost, "/account-recovery", reader)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/account-recovery", u.String())
	})
}

func TestAccountRecoveryVerification(t *testing.T) {
	tmpl, err := template.New("account-recovery-verification.go.html").Parse(`{{.Error}}`)
	assert.Nil(t, err)
	t.Run("Returns 200 When Recovering", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		authtest.NewTestAccount(t, a)
		token, err := a.SessionManager().NewAccountRecovery()
		assert.Nil(t, err)
		mux := http.NewServeMux()
		authgo.AttachHandlers(a, mux, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/account-recovery-verification", nil)
		request.AddCookie(authgo.NewAccountRecoveryCookie(token))
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Empty(t, string(body))
	})
	t.Run("Redirects When Not Recovering", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		mux := http.NewServeMux()
		authgo.AttachHandlers(a, mux, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/account-recovery-verification", nil)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/account-recovery", u.String())
	})
	t.Run("Redirects After Recovery", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		authtest.NewTestAccount(t, a)
		sm := a.SessionManager()
		token, err := sm.NewAccountRecovery()
		assert.Nil(t, err)
		err = sm.SetAccountRecoveryEmail(token, authtest.TEST_EMAIL)
		assert.Nil(t, err)
		err = sm.SetAccountRecoveryUsername(token, authtest.TEST_USERNAME)
		assert.Nil(t, err)
		err = sm.SetAccountRecoveryChallenge(token, authtest.TEST_CHALLENGE)
		assert.Nil(t, err)
		mux := http.NewServeMux()
		authgo.AttachHandlers(a, mux, tmpl)
		values := url.Values{}
		values.Add("verification", authtest.TEST_CHALLENGE)
		reader := strings.NewReader(values.Encode())
		request := httptest.NewRequest(http.MethodPost, "/account-recovery-verification", reader)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(authgo.NewAccountRecoveryCookie(token))
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		cookies := result.Cookies()
		assert.Equal(t, 1, len(cookies))
		assert.Equal(t, authgo.SESSION_SIGN_IN_COOKIE, cookies[0].Name)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/account-password", u.String())
		username, authenticated, errmsg, ok := sm.LookupSignIn(cookies[0].Value)
		assert.Equal(t, authtest.TEST_USERNAME, username)
		assert.True(t, authenticated)
		assert.Empty(t, errmsg)
		assert.True(t, ok)
	})
	t.Run("Redirects When Challenge Is Incorrect", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		sm := a.SessionManager()
		token, err := sm.NewAccountRecovery()
		assert.Nil(t, err)
		cookie := authgo.NewAccountRecoveryCookie(token)
		err = sm.SetAccountRecoveryChallenge(token, authtest.TEST_CHALLENGE)
		assert.Nil(t, err)
		mux := http.NewServeMux()
		authgo.AttachHandlers(a, mux, tmpl)
		values := url.Values{}
		values.Add("verification", "1234abcd")
		reader := strings.NewReader(values.Encode())
		request := httptest.NewRequest(http.MethodPost, "/account-recovery-verification", reader)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(cookie)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/account-recovery-verification", u.String())

		// Subsequent Get request should show error
		request = httptest.NewRequest(http.MethodGet, "/account-recovery-verification", nil)
		request.AddCookie(cookie)
		response = httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result = response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Equal(t, authgo.ErrIncorrectEmailVerification.Error(), string(body))
	})
}

func TestSignIn(t *testing.T) {
	tmpl, err := template.New("sign-in.go.html").Parse(`{{.Error}}`)
	assert.Nil(t, err)
	t.Run("Redirects When Signed In", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		authtest.NewTestAccount(t, a)
		token, _ := authtest.SignIn(t, a)
		mux := http.NewServeMux()
		authgo.AttachHandlers(a, mux, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/sign-in", nil)
		request.AddCookie(authgo.NewSignInCookie(token))
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/account", u.String())
	})
	t.Run("Returns 200 When Not Signed In", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		mux := http.NewServeMux()
		authgo.AttachHandlers(a, mux, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/sign-in", nil)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Empty(t, string(body))
		cookies := result.Cookies()
		assert.Equal(t, 1, len(cookies))
		assert.Equal(t, authgo.SESSION_SIGN_IN_COOKIE, cookies[0].Name)
	})
	t.Run("Redirects When Credentials Are Correct", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		acc := authtest.NewTestAccount(t, a)
		assert.Nil(t, a.AccountManager().SetEmailVerified(acc.Email, true))
		mux := http.NewServeMux()
		authgo.AttachHandlers(a, mux, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/sign-in", nil)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Empty(t, string(body))
		cookies := result.Cookies()
		assert.Equal(t, 1, len(cookies))
		assert.Equal(t, authgo.SESSION_SIGN_IN_COOKIE, cookies[0].Name)
		reader := strings.NewReader("username=" + authtest.TEST_USERNAME + "&password=" + authtest.TEST_PASSWORD)
		request = httptest.NewRequest(http.MethodPost, "/sign-in", reader)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(cookies[0])
		response = httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result = response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		body, err = io.ReadAll(result.Body)
		assert.Nil(t, err)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/account", u.String())
	})
	t.Run("Redirects When Post Requested Before Get", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		mux := http.NewServeMux()
		authgo.AttachHandlers(a, mux, tmpl)
		reader := strings.NewReader("username=" + authtest.TEST_USERNAME + "&password=" + authtest.TEST_PASSWORD)
		request := httptest.NewRequest(http.MethodPost, "/sign-in", reader)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/sign-in", u.String())
	})
	t.Run("Redirects When Username Is Unregistered", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		mux := http.NewServeMux()
		authgo.AttachHandlers(a, mux, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/sign-in", nil)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Empty(t, string(body))
		cookies := result.Cookies()
		assert.Equal(t, 1, len(cookies))
		assert.Equal(t, authgo.SESSION_SIGN_IN_COOKIE, cookies[0].Name)
		reader := strings.NewReader("username=foobar&password=" + authtest.TEST_PASSWORD)
		request = httptest.NewRequest(http.MethodPost, "/sign-in", reader)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(cookies[0])
		response = httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result = response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/sign-in", u.String())

		// Subsequent Get request should show error
		request = httptest.NewRequest(http.MethodGet, "/sign-in", nil)
		request.AddCookie(cookies[0])
		response = httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result = response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)
		body, err = io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Equal(t, authgo.ErrIncorrectCredentials.Error(), string(body))
	})
	t.Run("Redirects When Password Is Wrong", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		authtest.NewTestAccount(t, a)
		mux := http.NewServeMux()
		authgo.AttachHandlers(a, mux, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/sign-in", nil)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Empty(t, string(body))
		cookies := result.Cookies()
		assert.Equal(t, 1, len(cookies))
		assert.Equal(t, authgo.SESSION_SIGN_IN_COOKIE, cookies[0].Name)
		reader := strings.NewReader("username=" + authtest.TEST_USERNAME + "&password=foobarfoobar")
		request = httptest.NewRequest(http.MethodPost, "/sign-in", reader)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(cookies[0])
		response = httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result = response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/sign-in", u.String())

		// Subsequent Get request should show error
		request = httptest.NewRequest(http.MethodGet, "/sign-in", nil)
		request.AddCookie(cookies[0])
		response = httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result = response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)
		body, err = io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Equal(t, authgo.ErrIncorrectCredentials.Error(), string(body))
	})
	t.Run("Redirects When Email Is Not Verified", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		authtest.NewTestAccount(t, a)
		mux := http.NewServeMux()
		authgo.AttachHandlers(a, mux, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/sign-in", nil)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Empty(t, string(body))
		cookies := result.Cookies()
		assert.Equal(t, 1, len(cookies))
		assert.Equal(t, authgo.SESSION_SIGN_IN_COOKIE, cookies[0].Name)
		reader := strings.NewReader("username=" + authtest.TEST_USERNAME + "&password=" + authtest.TEST_PASSWORD)
		request = httptest.NewRequest(http.MethodPost, "/sign-in", reader)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(cookies[0])
		response = httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result = response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		body, err = io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Empty(t, string(body))
		cookies = result.Cookies()
		assert.Equal(t, 1, len(cookies))
		assert.Equal(t, authgo.SESSION_SIGN_UP_COOKIE, cookies[0].Name)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/sign-up-verification", u.String())
	})
}

func TestSignOut(t *testing.T) {
	tmpl, err := template.New("sign-out.go.html").Parse(`{{.Error}}`)
	assert.Nil(t, err)
	t.Run("Returns 200 When Signed In", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		authtest.NewTestAccount(t, a)
		token, _ := authtest.SignIn(t, a)
		mux := http.NewServeMux()
		authgo.AttachHandlers(a, mux, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/sign-out", nil)
		request.AddCookie(authgo.NewSignInCookie(token))
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Empty(t, string(body))
	})
	t.Run("Redirects After Sign Out", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		authtest.NewTestAccount(t, a)
		token, _ := authtest.SignIn(t, a)
		mux := http.NewServeMux()
		authgo.AttachHandlers(a, mux, tmpl)
		request := httptest.NewRequest(http.MethodPost, "/sign-out", nil)
		request.AddCookie(authgo.NewSignInCookie(token))
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/", u.String())
		username, authenticated, errmsg, ok := a.SessionManager().LookupSignIn(token)
		assert.Equal(t, username, authtest.TEST_USERNAME)
		assert.False(t, authenticated)
		assert.Empty(t, errmsg)
		assert.True(t, ok)
	})
	t.Run("Redirects When Not Signed In", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		mux := http.NewServeMux()
		authgo.AttachHandlers(a, mux, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/sign-out", nil)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/", u.String())
	})
}

func TestSignUp(t *testing.T) {
	tmpl, err := template.New("sign-up.go.html").Parse(`{{.Error}}{{.Email}}{{.Username}}`)
	assert.Nil(t, err)
	t.Run("Redirects When Signed In", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		authtest.NewTestAccount(t, a)
		token, _ := authtest.SignIn(t, a)
		mux := http.NewServeMux()
		authgo.AttachHandlers(a, mux, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/sign-up", nil)
		request.AddCookie(authgo.NewSignInCookie(token))
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/account", u.String())
	})
	t.Run("Returns 200 When Not Signed In", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		mux := http.NewServeMux()
		authgo.AttachHandlers(a, mux, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/sign-up", nil)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Empty(t, string(body))
		cookies := result.Cookies()
		assert.Equal(t, 1, len(cookies))
		assert.Equal(t, authgo.SESSION_SIGN_UP_COOKIE, cookies[0].Name)
	})
	t.Run("Redirects After Sign Up", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		mux := http.NewServeMux()
		authgo.AttachHandlers(a, mux, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/sign-up", nil)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Empty(t, string(body))
		cookies := result.Cookies()
		assert.Equal(t, 1, len(cookies))
		assert.Equal(t, authgo.SESSION_SIGN_UP_COOKIE, cookies[0].Name)
		values := url.Values{}
		values.Add("email", authtest.TEST_EMAIL)
		values.Add("username", authtest.TEST_USERNAME)
		values.Add("password", authtest.TEST_PASSWORD)
		values.Add("confirmation", authtest.TEST_PASSWORD)
		reader := strings.NewReader(values.Encode())
		request = httptest.NewRequest(http.MethodPost, "/sign-up", reader)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(cookies[0])
		response = httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result = response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/sign-up-verification", u.String())
		email, username, challenge, errmsg, ok := a.SessionManager().LookupSignUp(cookies[0].Value)
		assert.Equal(t, authtest.TEST_EMAIL, email)
		assert.Equal(t, authtest.TEST_USERNAME, username)
		assert.Equal(t, authtest.TEST_CHALLENGE, challenge)
		assert.Empty(t, errmsg)
		assert.True(t, ok)
	})
	t.Run("Redirects When Form Data Is Invalid", func(t *testing.T) {
		usernameShort := strings.Repeat("x", authgo.MINIMUM_USERNAME_LENGTH-1)
		usernameLong := strings.Repeat("x", authgo.MAXIMUM_USERNAME_LENGTH+1)
		existingEmail := "bob@example.com"
		existingUsername := "bob"
		for name, tt := range map[string]struct {
			form   map[string]string
			result string
		}{
			"Empty": {
				result: authgo.ErrInvalidEmail.Error(),
			},
			"Email Missing": {
				form: map[string]string{
					"username":     authtest.TEST_USERNAME,
					"password":     authtest.TEST_PASSWORD,
					"confirmation": authtest.TEST_PASSWORD,
				},
				result: authgo.ErrInvalidEmail.Error() + authtest.TEST_USERNAME,
			},
			"Email Invalid": {
				form: map[string]string{
					"email":        "abc",
					"username":     authtest.TEST_USERNAME,
					"password":     authtest.TEST_PASSWORD,
					"confirmation": authtest.TEST_PASSWORD,
				},
				result: authgo.ErrInvalidEmail.Error() + "abc" + authtest.TEST_USERNAME,
			},
			"Email Already Registered": {
				form: map[string]string{
					"email":        existingEmail,
					"username":     existingUsername,
					"password":     authtest.TEST_PASSWORD,
					"confirmation": authtest.TEST_PASSWORD,
				},
				result: authgo.ErrEmailAlreadyRegistered.Error() + existingEmail + existingUsername,
			},
			"Username Too Short": {
				form: map[string]string{
					"email":        authtest.TEST_EMAIL,
					"username":     usernameShort,
					"password":     authtest.TEST_PASSWORD,
					"confirmation": authtest.TEST_PASSWORD,
				},
				result: authgo.ErrInvalidUsername.Error() + authtest.TEST_EMAIL + usernameShort,
			},
			"Username Too Long": {
				form: map[string]string{
					"email":        authtest.TEST_EMAIL,
					"username":     usernameLong,
					"password":     authtest.TEST_PASSWORD,
					"confirmation": authtest.TEST_PASSWORD,
				},
				result: authgo.ErrInvalidUsername.Error() + authtest.TEST_EMAIL + usernameLong,
			},
			"Username Already Registered": {
				form: map[string]string{
					"email":        "bobby@example.com",
					"username":     existingUsername,
					"password":     authtest.TEST_PASSWORD,
					"confirmation": authtest.TEST_PASSWORD,
				},
				result: authgo.ErrUsernameAlreadyRegistered.Error() + "bobby@example.com" + existingUsername,
			},
			"Password Too Short": {
				form: map[string]string{
					"email":        authtest.TEST_EMAIL,
					"username":     authtest.TEST_USERNAME,
					"password":     "password",
					"confirmation": "password",
				},
				result: authgo.ErrPasswordTooShort.Error() + authtest.TEST_EMAIL + authtest.TEST_USERNAME,
			},
			"Passwords Do Not Match": {
				form: map[string]string{
					"email":        authtest.TEST_EMAIL,
					"username":     authtest.TEST_USERNAME,
					"password":     authtest.TEST_PASSWORD,
					"confirmation": "1234password",
				},
				result: authgo.ErrPasswordsDoNotMatch.Error() + authtest.TEST_EMAIL + authtest.TEST_USERNAME,
			},
		} {
			t.Run(name, func(t *testing.T) {
				a := authtest.NewAuthenticator(t)
				_, err := a.AccountManager().New(existingEmail, existingUsername, []byte(authtest.TEST_PASSWORD))
				assert.Nil(t, err)
				mux := http.NewServeMux()
				authgo.AttachHandlers(a, mux, tmpl)
				request := httptest.NewRequest(http.MethodGet, "/sign-up", nil)
				response := httptest.NewRecorder()
				mux.ServeHTTP(response, request)
				result := response.Result()
				assert.Equal(t, http.StatusOK, result.StatusCode)
				body, err := io.ReadAll(result.Body)
				assert.Nil(t, err)
				assert.Empty(t, string(body))
				cookies := result.Cookies()
				assert.Equal(t, 1, len(cookies))
				assert.Equal(t, authgo.SESSION_SIGN_UP_COOKIE, cookies[0].Name)
				values := url.Values{}
				for k, v := range tt.form {
					values.Add(k, v)
				}
				reader := strings.NewReader(values.Encode())
				request = httptest.NewRequest(http.MethodPost, "/sign-up", reader)
				request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				request.AddCookie(cookies[0])
				response = httptest.NewRecorder()
				mux.ServeHTTP(response, request)
				result = response.Result()
				assert.Equal(t, http.StatusFound, result.StatusCode)
				u, err := result.Location()
				assert.Nil(t, err)
				assert.Equal(t, "/sign-up", u.String())

				// Subsequent Get request should show error
				request = httptest.NewRequest(http.MethodGet, "/sign-up", nil)
				request.AddCookie(cookies[0])
				response = httptest.NewRecorder()
				mux.ServeHTTP(response, request)
				result = response.Result()
				assert.Equal(t, http.StatusOK, result.StatusCode)
				body, err = io.ReadAll(result.Body)
				assert.Nil(t, err)
				assert.Equal(t, tt.result, string(body))
			})
		}
	})
}

func TestSignUpVerification(t *testing.T) {
	tmpl, err := template.New("sign-up-verification.go.html").Parse(`{{.Error}}`)
	assert.Nil(t, err)
	t.Run("Returns 200 When Signed Up", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		authtest.NewTestAccount(t, a)
		token, err := a.SessionManager().NewSignUp()
		assert.Nil(t, err)
		mux := http.NewServeMux()
		authgo.AttachHandlers(a, mux, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/sign-up-verification", nil)
		request.AddCookie(authgo.NewSignUpCookie(token))
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Empty(t, string(body))
	})
	t.Run("Redirects When Not Signed Up", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		mux := http.NewServeMux()
		authgo.AttachHandlers(a, mux, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/sign-up-verification", nil)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/sign-up", u.String())
	})
	t.Run("Redirects After Sign Up Verification", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		authtest.NewTestAccount(t, a)
		sm := a.SessionManager()
		token, err := sm.NewSignUp()
		assert.Nil(t, err)
		err = sm.SetSignUpIdentity(token, authtest.TEST_EMAIL, authtest.TEST_USERNAME)
		assert.Nil(t, err)
		err = sm.SetSignUpChallenge(token, authtest.TEST_CHALLENGE)
		assert.Nil(t, err)
		mux := http.NewServeMux()
		authgo.AttachHandlers(a, mux, tmpl)
		values := url.Values{}
		values.Add("verification", authtest.TEST_CHALLENGE)
		reader := strings.NewReader(values.Encode())
		request := httptest.NewRequest(http.MethodPost, "/sign-up-verification", reader)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(authgo.NewSignUpCookie(token))
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		cookies := result.Cookies()
		assert.Equal(t, 1, len(cookies))
		assert.Equal(t, authgo.SESSION_SIGN_IN_COOKIE, cookies[0].Name)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/", u.String())
		username, authenticated, errmsg, ok := sm.LookupSignIn(cookies[0].Value)
		assert.Equal(t, authtest.TEST_USERNAME, username)
		assert.True(t, authenticated)
		assert.Empty(t, errmsg)
		assert.True(t, ok)
		assert.True(t, a.AccountManager().IsEmailVerified(authtest.TEST_EMAIL))
	})
	t.Run("Redirects When Challenge Is Incorrect", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		sm := a.SessionManager()
		token, err := sm.NewSignUp()
		assert.Nil(t, err)
		cookie := authgo.NewSignUpCookie(token)
		err = sm.SetSignUpChallenge(token, authtest.TEST_CHALLENGE)
		assert.Nil(t, err)
		mux := http.NewServeMux()
		authgo.AttachHandlers(a, mux, tmpl)
		values := url.Values{}
		values.Add("verification", "1234abcd")
		reader := strings.NewReader(values.Encode())
		request := httptest.NewRequest(http.MethodPost, "/sign-up-verification", reader)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(cookie)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/sign-up-verification", u.String())

		// Subsequent Get request should show error
		request = httptest.NewRequest(http.MethodGet, "/sign-up-verification", nil)
		request.AddCookie(cookie)
		response = httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result = response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Equal(t, authgo.ErrIncorrectEmailVerification.Error(), string(body))
	})
}

func TestSignUpSignOutSignInAccountFlow(t *testing.T) {
	fs := fstest.MapFS{
		"sign-up.go.html": {
			Data: []byte(`{{.Error}}{{.Email}}{{.Username}}`),
		},
		"sign-up-verification.go.html": {
			Data: []byte(`{{.Error}}`),
		},
		"sign-out.go.html": {
			Data: []byte(`{{.Error}}`),
		},
		"sign-in.go.html": {
			Data: []byte(`{{.Error}}`),
		},
		"account.go.html": {
			Data: []byte(`{{.Account.Username}}`),
		},
	}
	tmpl, err := template.ParseFS(fs, "*.go.html")
	assert.Nil(t, err)

	a := authtest.NewAuthenticator(t)
	mux := http.NewServeMux()
	authgo.AttachHandlers(a, mux, tmpl)

	// Sign Up
	request := httptest.NewRequest(http.MethodGet, "/sign-up", nil)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result := response.Result()
	assert.Equal(t, http.StatusOK, result.StatusCode)
	body, err := io.ReadAll(result.Body)
	assert.Nil(t, err)
	assert.Empty(t, string(body))
	cookies := result.Cookies()
	assert.Equal(t, 1, len(cookies))
	assert.Equal(t, authgo.SESSION_SIGN_UP_COOKIE, cookies[0].Name)
	values := url.Values{}
	values.Add("email", authtest.TEST_EMAIL)
	values.Add("username", authtest.TEST_USERNAME)
	values.Add("password", authtest.TEST_PASSWORD)
	values.Add("confirmation", authtest.TEST_PASSWORD)
	reader := strings.NewReader(values.Encode())
	request = httptest.NewRequest(http.MethodPost, "/sign-up", reader)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookies[0])
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusFound, result.StatusCode)
	u, err := result.Location()
	assert.Nil(t, err)
	assert.Equal(t, "/sign-up-verification", u.String())

	// Sign Up Verification
	request = httptest.NewRequest(http.MethodGet, "/sign-up-verification", nil)
	request.AddCookie(cookies[0])
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusOK, result.StatusCode)
	body, err = io.ReadAll(result.Body)
	assert.Nil(t, err)
	values = url.Values{}
	values.Add("verification", authtest.TEST_CHALLENGE)
	reader = strings.NewReader(values.Encode())
	request = httptest.NewRequest(http.MethodPost, "/sign-up-verification", reader)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookies[0])
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusFound, result.StatusCode)
	cookies = result.Cookies()
	assert.Equal(t, 1, len(cookies))
	assert.Equal(t, authgo.SESSION_SIGN_IN_COOKIE, cookies[0].Name)
	u, err = result.Location()
	assert.Nil(t, err)
	assert.Equal(t, "/", u.String())

	// Sign Out
	request = httptest.NewRequest(http.MethodGet, "/sign-out", nil)
	request.AddCookie(cookies[0])
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusOK, result.StatusCode)
	body, err = io.ReadAll(result.Body)
	assert.Nil(t, err)
	assert.Empty(t, string(body))
	request = httptest.NewRequest(http.MethodPost, "/sign-out", nil)
	request.AddCookie(cookies[0])
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusFound, result.StatusCode)
	u, err = result.Location()
	assert.Nil(t, err)
	assert.Equal(t, "/", u.String())

	// Sign In
	request = httptest.NewRequest(http.MethodGet, "/sign-in", nil)
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusOK, result.StatusCode)
	body, err = io.ReadAll(result.Body)
	assert.Nil(t, err)
	assert.Empty(t, string(body))
	cookies = result.Cookies()
	assert.Equal(t, 1, len(cookies))
	assert.Equal(t, authgo.SESSION_SIGN_IN_COOKIE, cookies[0].Name)
	reader = strings.NewReader("username=" + authtest.TEST_USERNAME + "&password=" + authtest.TEST_PASSWORD)
	request = httptest.NewRequest(http.MethodPost, "/sign-in", reader)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookies[0])
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusFound, result.StatusCode)
	body, err = io.ReadAll(result.Body)
	assert.Nil(t, err)
	assert.Empty(t, string(body))
	u, err = result.Location()
	assert.Nil(t, err)
	assert.Equal(t, "/account", u.String())

	// Account
	request = httptest.NewRequest(http.MethodGet, "/account", nil)
	request.AddCookie(cookies[0])
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusOK, result.StatusCode)
	body, err = io.ReadAll(result.Body)
	assert.Nil(t, err)
	assert.Equal(t, authtest.TEST_USERNAME, string(body))
}

func TestAccountPasswordSignOutSignInAccountFlow(t *testing.T) {
	fs := fstest.MapFS{
		"account.go.html": {
			Data: []byte(`{{.Account.Username}}`),
		},
		"account-password.go.html": {
			Data: []byte(`{{.Error}}`),
		},
		"sign-out.go.html": {
			Data: []byte(`{{.Error}}`),
		},
		"sign-in.go.html": {
			Data: []byte(`{{.Error}}`),
		},
	}
	tmpl, err := template.ParseFS(fs, "*.go.html")
	assert.Nil(t, err)

	a := authtest.NewAuthenticator(t)
	authtest.NewTestAccount(t, a)
	assert.Nil(t, a.AccountManager().SetEmailVerified(authtest.TEST_EMAIL, true))
	mux := http.NewServeMux()
	authgo.AttachHandlers(a, mux, tmpl)
	token, _ := authtest.SignIn(t, a)
	newPassword := "foobarfoobar"

	// Account Password
	request := httptest.NewRequest(http.MethodGet, "/account-password", nil)
	request.AddCookie(authgo.NewSignInCookie(token))
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result := response.Result()
	assert.Equal(t, http.StatusOK, result.StatusCode)
	body, err := io.ReadAll(result.Body)
	assert.Nil(t, err)
	assert.Empty(t, string(body))
	cookies := result.Cookies()
	assert.Equal(t, 2, len(cookies))
	assert.Equal(t, authgo.SESSION_SIGN_IN_COOKIE, cookies[0].Name)
	assert.Equal(t, authgo.SESSION_ACCOUNT_PASSWORD_COOKIE, cookies[1].Name)
	values := url.Values{}
	values.Add("password", newPassword)
	values.Add("confirmation", newPassword)
	reader := strings.NewReader(values.Encode())
	request = httptest.NewRequest(http.MethodPost, "/account-password", reader)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookies[0])
	request.AddCookie(cookies[1])
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusFound, result.StatusCode)
	cookies = result.Cookies()
	assert.Equal(t, 1, len(cookies))
	assert.Equal(t, authgo.SESSION_SIGN_IN_COOKIE, cookies[0].Name)
	u, err := result.Location()
	assert.Nil(t, err)
	assert.Equal(t, "/account", u.String())

	// Sign Out
	request = httptest.NewRequest(http.MethodGet, "/sign-out", nil)
	request.AddCookie(cookies[0])
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusOK, result.StatusCode)
	body, err = io.ReadAll(result.Body)
	assert.Nil(t, err)
	assert.Empty(t, string(body))
	request = httptest.NewRequest(http.MethodPost, "/sign-out", nil)
	request.AddCookie(cookies[0])
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusFound, result.StatusCode)
	u, err = result.Location()
	assert.Nil(t, err)
	assert.Equal(t, "/", u.String())

	// Sign In
	request = httptest.NewRequest(http.MethodGet, "/sign-in", nil)
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusOK, result.StatusCode)
	body, err = io.ReadAll(result.Body)
	assert.Nil(t, err)
	assert.Empty(t, string(body))
	cookies = result.Cookies()
	assert.Equal(t, 1, len(cookies))
	assert.Equal(t, authgo.SESSION_SIGN_IN_COOKIE, cookies[0].Name)
	reader = strings.NewReader("username=" + authtest.TEST_USERNAME + "&password=" + newPassword)
	request = httptest.NewRequest(http.MethodPost, "/sign-in", reader)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookies[0])
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusFound, result.StatusCode)
	body, err = io.ReadAll(result.Body)
	assert.Nil(t, err)
	assert.Empty(t, string(body))
	u, err = result.Location()
	assert.Nil(t, err)
	assert.Equal(t, "/account", u.String())

	// Account
	request = httptest.NewRequest(http.MethodGet, "/account", nil)
	request.AddCookie(cookies[0])
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusOK, result.StatusCode)
	body, err = io.ReadAll(result.Body)
	assert.Nil(t, err)
	assert.Equal(t, authtest.TEST_USERNAME, string(body))
}

func TestAccountRecoveryAccountPasswordAccountFlow(t *testing.T) {
	fs := fstest.MapFS{
		"account.go.html": {
			Data: []byte(`{{.Account.Username}}`),
		},
		"account-password.go.html": {
			Data: []byte(`{{.Error}}`),
		},
		"account-recovery.go.html": {
			Data: []byte(`{{.Error}}{{.Email}}`),
		},
		"account-recovery-verification.go.html": {
			Data: []byte(`{{.Error}}{{.Username}}`),
		},
	}
	tmpl, err := template.ParseFS(fs, "*.go.html")
	assert.Nil(t, err)

	a := authtest.NewAuthenticator(t)
	authtest.NewTestAccount(t, a)
	mux := http.NewServeMux()
	authgo.AttachHandlers(a, mux, tmpl)
	newPassword := "foobarfoobar"

	// Account Recovery
	request := httptest.NewRequest(http.MethodGet, "/account-recovery", nil)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result := response.Result()
	assert.Equal(t, http.StatusOK, result.StatusCode)
	body, err := io.ReadAll(result.Body)
	assert.Nil(t, err)
	assert.Empty(t, string(body))
	cookies := result.Cookies()
	assert.Equal(t, 1, len(cookies))
	assert.Equal(t, authgo.SESSION_ACCOUNT_RECOVERY_COOKIE, cookies[0].Name)
	values := url.Values{}
	values.Add("email", authtest.TEST_EMAIL)
	reader := strings.NewReader(values.Encode())
	request = httptest.NewRequest(http.MethodPost, "/account-recovery", reader)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookies[0])
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusFound, result.StatusCode)
	u, err := result.Location()
	assert.Nil(t, err)
	assert.Equal(t, "/account-recovery-verification", u.String())

	// Account Recovery Verification
	request = httptest.NewRequest(http.MethodGet, "/account-recovery-verification", nil)
	request.AddCookie(cookies[0])
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusOK, result.StatusCode)
	body, err = io.ReadAll(result.Body)
	assert.Nil(t, err)
	values = url.Values{}
	values.Add("verification", authtest.TEST_CHALLENGE)
	reader = strings.NewReader(values.Encode())
	request = httptest.NewRequest(http.MethodPost, "/account-recovery-verification", reader)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookies[0])
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusFound, result.StatusCode)
	cookies = result.Cookies()
	assert.Equal(t, 1, len(cookies))
	assert.Equal(t, authgo.SESSION_SIGN_IN_COOKIE, cookies[0].Name)
	u, err = result.Location()
	assert.Nil(t, err)
	assert.Equal(t, "/account-password", u.String())

	// Account Password
	request = httptest.NewRequest(http.MethodGet, "/account-password", nil)
	request.AddCookie(cookies[0])
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusOK, result.StatusCode)
	body, err = io.ReadAll(result.Body)
	assert.Nil(t, err)
	assert.Empty(t, string(body))
	cookies = result.Cookies()
	assert.Equal(t, 2, len(cookies))
	assert.Equal(t, authgo.SESSION_SIGN_IN_COOKIE, cookies[0].Name)
	assert.Equal(t, authgo.SESSION_ACCOUNT_PASSWORD_COOKIE, cookies[1].Name)
	values = url.Values{}
	values.Add("password", newPassword)
	values.Add("confirmation", newPassword)
	reader = strings.NewReader(values.Encode())
	request = httptest.NewRequest(http.MethodPost, "/account-password", reader)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookies[0])
	request.AddCookie(cookies[1])
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusFound, result.StatusCode)
	cookies = result.Cookies()
	assert.Equal(t, 1, len(cookies))
	assert.Equal(t, authgo.SESSION_SIGN_IN_COOKIE, cookies[0].Name)
	u, err = result.Location()
	assert.Nil(t, err)
	assert.Equal(t, "/account", u.String())

	// Account
	request = httptest.NewRequest(http.MethodGet, "/account", nil)
	request.AddCookie(cookies[0])
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	assert.Equal(t, http.StatusOK, result.StatusCode)
	body, err = io.ReadAll(result.Body)
	assert.Nil(t, err)
	assert.Equal(t, authtest.TEST_USERNAME, string(body))
}
