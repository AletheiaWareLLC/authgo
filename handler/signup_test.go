package handler_test

import (
	"aletheiaware.com/authgo"
	"aletheiaware.com/authgo/authtest"
	"aletheiaware.com/authgo/handler"
	"github.com/stretchr/testify/assert"
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestSignUp(t *testing.T) {
	tmpl, err := template.New("sign-up.go.html").Parse(`{{.Error}}{{.Email}}{{.Username}}`)
	assert.Nil(t, err)
	t.Run("Redirects When Signed In", func(t *testing.T) {
		a := authtest.NewAuthenticator(t)
		authtest.NewTestAccount(t, a)
		token, _ := authtest.SignIn(t, a)
		mux := http.NewServeMux()
		handler.AttachHandlers(a, mux, tmpl)
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
		handler.AttachHandlers(a, mux, tmpl)
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
		handler.AttachHandlers(a, mux, tmpl)
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
				handler.AttachHandlers(a, mux, tmpl)
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
		handler.AttachHandlers(a, mux, tmpl)
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
		handler.AttachHandlers(a, mux, tmpl)
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
		handler.AttachHandlers(a, mux, tmpl)
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
		handler.AttachHandlers(a, mux, tmpl)
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
