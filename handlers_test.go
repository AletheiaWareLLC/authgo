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
	"time"
)

func TestAccount(t *testing.T) {
	tmpl, err := template.New("account.go.html").Parse(`Hello {{.Account.Username}}`)
	assert.Nil(t, err)
	t.Run("Returns 200 When Signed In", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		authtest.NewTestAccount(t, a)
		id, session := authtest.SignIn(t, a)
		mux := http.NewServeMux()
		authgo.AttachHandlers(a, mux, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/account", nil)
		request.AddCookie(session.Cookie(id))
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, result.StatusCode)
		assert.Equal(t, "Hello "+authtest.TEST_USERNAME+"", string(body))
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

func TestSignIn(t *testing.T) {
	tmpl, err := template.New("sign-in.go.html").Parse(`{{.Error}}`)
	assert.Nil(t, err)
	t.Run("Redirects When Signed In", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		authtest.NewTestAccount(t, a)
		id, session := authtest.SignIn(t, a)
		mux := http.NewServeMux()
		authgo.AttachHandlers(a, mux, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/sign-in", nil)
		request.AddCookie(session.Cookie(id))
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
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, result.StatusCode)
		cookies := result.Cookies()
		assert.Equal(t, 1, len(cookies))
		assert.Equal(t, authgo.SESSION_SIGN_IN_COOKIE, cookies[0].Name)
		assert.Equal(t, "", string(body))
	})
	t.Run("Redirects When Credentials Are Correct", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		acc := authtest.NewTestAccount(t, a)
		a.AccountManager().SetVerified(acc.Email, true)
		mux := http.NewServeMux()
		authgo.AttachHandlers(a, mux, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/sign-in", nil)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, result.StatusCode)
		cookies := result.Cookies()
		assert.Equal(t, 1, len(cookies))
		assert.Equal(t, authgo.SESSION_SIGN_IN_COOKIE, cookies[0].Name)
		assert.Equal(t, "", string(body))
		reader := strings.NewReader("username=" + authtest.TEST_USERNAME + "&password=" + authtest.TEST_PASSWORD)
		request = httptest.NewRequest(http.MethodPost, "/sign-in", reader)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(cookies[0])
		response = httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result = response.Result()
		body, err = io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusFound, result.StatusCode)
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
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, result.StatusCode)
		cookies := result.Cookies()
		assert.Equal(t, 1, len(cookies))
		assert.Equal(t, authgo.SESSION_SIGN_IN_COOKIE, cookies[0].Name)
		assert.Equal(t, "", string(body))
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
		body, err = io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, result.StatusCode)
		assert.Equal(t, "Incorrect Credentials", string(body))
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
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, result.StatusCode)
		cookies := result.Cookies()
		assert.Equal(t, 1, len(cookies))
		assert.Equal(t, authgo.SESSION_SIGN_IN_COOKIE, cookies[0].Name)
		assert.Equal(t, "", string(body))
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
		body, err = io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, result.StatusCode)
		assert.Equal(t, "Incorrect Credentials", string(body))
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
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, result.StatusCode)
		cookies := result.Cookies()
		assert.Equal(t, 1, len(cookies))
		assert.Equal(t, authgo.SESSION_SIGN_IN_COOKIE, cookies[0].Name)
		assert.Equal(t, "", string(body))
		reader := strings.NewReader("username=" + authtest.TEST_USERNAME + "&password=" + authtest.TEST_PASSWORD)
		request = httptest.NewRequest(http.MethodPost, "/sign-in", reader)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(cookies[0])
		response = httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result = response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		cookies = result.Cookies()
		assert.Equal(t, 1, len(cookies))
		assert.Equal(t, authgo.SESSION_SIGN_UP_COOKIE, cookies[0].Name)
		assert.Equal(t, "", string(body))
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
		id, session := authtest.SignIn(t, a)
		mux := http.NewServeMux()
		authgo.AttachHandlers(a, mux, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/sign-out", nil)
		request.AddCookie(session.Cookie(id))
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Equal(t, "", string(body))
	})
	t.Run("Redirects After Sign Out", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		authtest.NewTestAccount(t, a)
		id, session := authtest.SignIn(t, a)
		mux := http.NewServeMux()
		authgo.AttachHandlers(a, mux, tmpl)
		request := httptest.NewRequest(http.MethodPost, "/sign-out", nil)
		request.AddCookie(session.Cookie(id))
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/", u.String())
		assert.Nil(t, a.SessionManager().Lookup(id))
		assert.Nil(t, session.Account())
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
		id, session := authtest.SignIn(t, a)
		mux := http.NewServeMux()
		authgo.AttachHandlers(a, mux, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/sign-up", nil)
		request.AddCookie(session.Cookie(id))
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
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, result.StatusCode)
		cookies := result.Cookies()
		assert.Equal(t, 1, len(cookies))
		assert.Equal(t, authgo.SESSION_SIGN_UP_COOKIE, cookies[0].Name)
		assert.Equal(t, "", string(body))
	})
	t.Run("Redirects After Sign Up", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		mux := http.NewServeMux()
		authgo.AttachHandlers(a, mux, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/sign-up", nil)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, result.StatusCode)
		cookies := result.Cookies()
		assert.Equal(t, 1, len(cookies))
		assert.Equal(t, authgo.SESSION_SIGN_UP_COOKIE, cookies[0].Name)
		assert.Equal(t, "", string(body))
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
		session := a.SessionManager().Lookup(cookies[0].Value)
		assert.NotNil(t, session)
		assert.Equal(t, authtest.TEST_CHALLENGE, session.Value(authgo.SESSION_SIGN_UP_CHALLENGE))
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
				_, err := a.AccountManager().New(existingEmail, existingUsername, authtest.TEST_PASSWORD)
				assert.Nil(t, err)
				mux := http.NewServeMux()
				authgo.AttachHandlers(a, mux, tmpl)
				request := httptest.NewRequest(http.MethodGet, "/sign-up", nil)
				response := httptest.NewRecorder()
				mux.ServeHTTP(response, request)
				result := response.Result()
				body, err := io.ReadAll(result.Body)
				assert.Nil(t, err)
				assert.Equal(t, http.StatusOK, result.StatusCode)
				cookies := result.Cookies()
				assert.Equal(t, 1, len(cookies))
				assert.Equal(t, authgo.SESSION_SIGN_UP_COOKIE, cookies[0].Name)
				assert.Equal(t, "", string(body))
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
				body, err = io.ReadAll(result.Body)
				assert.Nil(t, err)
				assert.Equal(t, http.StatusOK, result.StatusCode)
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
		id, session, err := a.SessionManager().New(authgo.SESSION_SIGN_UP_COOKIE, time.Minute, false)
		assert.Nil(t, err)
		mux := http.NewServeMux()
		authgo.AttachHandlers(a, mux, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/sign-up-verification", nil)
		request.AddCookie(session.Cookie(id))
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, result.StatusCode)
		assert.Equal(t, "", string(body))
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
		id, session, err := a.SessionManager().New(authgo.SESSION_SIGN_UP_COOKIE, time.Minute, false)
		assert.Nil(t, err)
		session.SetAccount(&authgo.Account{
			Email:    authtest.TEST_EMAIL,
			Username: authtest.TEST_USERNAME,
		})
		session.SetValue(authgo.SESSION_SIGN_UP_CHALLENGE, authtest.TEST_CHALLENGE)
		mux := http.NewServeMux()
		authgo.AttachHandlers(a, mux, tmpl)
		values := url.Values{}
		values.Add("verification", authtest.TEST_CHALLENGE)
		reader := strings.NewReader(values.Encode())
		request := httptest.NewRequest(http.MethodPost, "/sign-up-verification", reader)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(session.Cookie(id))
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/", u.String())
		assert.Nil(t, a.SessionManager().Lookup(id))
		assert.True(t, a.AccountManager().Verified(authtest.TEST_EMAIL))
	})
	t.Run("Redirects When Challenge Is Incorrect", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		id, session, err := a.SessionManager().New(authgo.SESSION_SIGN_UP_COOKIE, time.Minute, false)
		assert.Nil(t, err)
		cookie := session.Cookie(id)
		session.SetValue(authgo.SESSION_SIGN_UP_CHALLENGE, authtest.TEST_CHALLENGE)
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
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, result.StatusCode)
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
			Data: []byte(`Hello {{.Account.Username}}`),
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
	body, err := io.ReadAll(result.Body)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, result.StatusCode)
	cookies := result.Cookies()
	assert.Equal(t, 1, len(cookies))
	assert.Equal(t, authgo.SESSION_SIGN_UP_COOKIE, cookies[0].Name)
	assert.Equal(t, "", string(body))
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
	body, err = io.ReadAll(result.Body)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, result.StatusCode)
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
	assert.Equal(t, "", string(body))
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
	body, err = io.ReadAll(result.Body)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, result.StatusCode)
	cookies = result.Cookies()
	assert.Equal(t, 1, len(cookies))
	assert.Equal(t, authgo.SESSION_SIGN_IN_COOKIE, cookies[0].Name)
	assert.Equal(t, "", string(body))
	reader = strings.NewReader("username=" + authtest.TEST_USERNAME + "&password=" + authtest.TEST_PASSWORD)
	request = httptest.NewRequest(http.MethodPost, "/sign-in", reader)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookies[0])
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	body, err = io.ReadAll(result.Body)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusFound, result.StatusCode)
	u, err = result.Location()
	assert.Nil(t, err)
	assert.Equal(t, "/account", u.String())

	// Account
	request = httptest.NewRequest(http.MethodGet, "/account", nil)
	request.AddCookie(cookies[0])
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	result = response.Result()
	body, err = io.ReadAll(result.Body)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, result.StatusCode)
	assert.Equal(t, "Hello "+authtest.TEST_USERNAME+"", string(body))
}
