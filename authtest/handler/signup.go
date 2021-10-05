package handler

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

func SignUp(t *testing.T, a func(*testing.T) authgo.Authenticator) {
	tmpl, err := template.New("sign-up.go.html").Parse(`{{.Error}}{{.Email}}{{.Username}}`)
	assert.Nil(t, err)
	t.Run("Redirects When Signed In", func(t *testing.T) {
		auth := a(t)
		mux := http.NewServeMux()
		handler.AttachSignUpHandler(mux, auth, tmpl)
		authtest.NewTestAccount(t, auth)
		token, _ := authtest.SignIn(t, auth)
		request := httptest.NewRequest(http.MethodGet, "/sign-up", nil)
		request.AddCookie(auth.NewSignInSessionCookie(token))
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/account", u.String())
	})
	t.Run("Returns 200 When Not Signed In", func(t *testing.T) {
		auth := a(t)
		mux := http.NewServeMux()
		handler.AttachSignUpHandler(mux, auth, tmpl)
		request := httptest.NewRequest(http.MethodGet, "/sign-up", nil)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Empty(t, string(body))
	})
	t.Run("Redirects After Sign Up", func(t *testing.T) {
		auth := a(t)
		mux := http.NewServeMux()
		handler.AttachSignUpHandler(mux, auth, tmpl)
		values := url.Values{}
		values.Add("email", authtest.TEST_EMAIL)
		values.Add("username", authtest.TEST_USERNAME)
		values.Add("password", authtest.TEST_PASSWORD)
		values.Add("confirmation", authtest.TEST_PASSWORD)
		reader := strings.NewReader(values.Encode())
		request := httptest.NewRequest(http.MethodPost, "/sign-up", reader)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		cookies := result.Cookies()
		assert.Equal(t, 1, len(cookies))
		assert.Equal(t, authgo.COOKIE_SIGN_UP, cookies[0].Name)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/sign-up-verification", u.String())
		email, username, challenge, errmsg, ok := auth.LookupSignUpSession(cookies[0].Value)
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
				result: authgo.ErrEmailInvalid.Error(),
			},
			"Email Missing": {
				form: map[string]string{
					"username":     authtest.TEST_USERNAME,
					"password":     authtest.TEST_PASSWORD,
					"confirmation": authtest.TEST_PASSWORD,
				},
				result: authgo.ErrEmailInvalid.Error(),
			},
			"Email Invalid": {
				form: map[string]string{
					"email":        "abc",
					"username":     authtest.TEST_USERNAME,
					"password":     authtest.TEST_PASSWORD,
					"confirmation": authtest.TEST_PASSWORD,
				},
				result: authgo.ErrEmailInvalid.Error(),
			},
			// TODO Email Too Long
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
				result: authgo.ErrUsernameTooShort.Error(),
			},
			"Username Too Long": {
				form: map[string]string{
					"email":        authtest.TEST_EMAIL,
					"username":     usernameLong,
					"password":     authtest.TEST_PASSWORD,
					"confirmation": authtest.TEST_PASSWORD,
				},
				result: authgo.ErrUsernameTooLong.Error(),
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
				auth := a(t)
				mux := http.NewServeMux()
				handler.AttachSignUpHandler(mux, auth, tmpl)
				_, err := auth.NewAccount(existingEmail, existingUsername, []byte(authtest.TEST_PASSWORD))
				assert.Nil(t, err)
				values := url.Values{}
				for k, v := range tt.form {
					values.Add(k, v)
				}
				reader := strings.NewReader(values.Encode())
				request := httptest.NewRequest(http.MethodPost, "/sign-up", reader)
				request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				response := httptest.NewRecorder()
				mux.ServeHTTP(response, request)
				result := response.Result()
				assert.Equal(t, http.StatusFound, result.StatusCode)
				cookies := result.Cookies()
				assert.Equal(t, 1, len(cookies))
				assert.Equal(t, authgo.COOKIE_SIGN_UP, cookies[0].Name)
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
				body, err := io.ReadAll(result.Body)
				assert.Nil(t, err)
				assert.Equal(t, tt.result, string(body))
			})
		}
	})
}

func SignUpVerification(t *testing.T, a func(*testing.T) authgo.Authenticator) {
	tmpl, err := template.New("sign-up-verification.go.html").Parse(`{{.Error}}`)
	assert.Nil(t, err)
	t.Run("Returns 200 When Signed Up", func(t *testing.T) {
		auth := a(t)
		mux := http.NewServeMux()
		handler.AttachSignUpHandler(mux, auth, tmpl)
		authtest.NewTestAccount(t, auth)
		token, err := auth.NewSignUpSession()
		assert.Nil(t, err)
		request := httptest.NewRequest(http.MethodGet, "/sign-up-verification", nil)
		request.AddCookie(auth.NewSignUpSessionCookie(token))
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)
		body, err := io.ReadAll(result.Body)
		assert.Nil(t, err)
		assert.Empty(t, string(body))
	})
	t.Run("Redirects When Not Signed Up", func(t *testing.T) {
		auth := a(t)
		mux := http.NewServeMux()
		handler.AttachSignUpHandler(mux, auth, tmpl)
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
		auth := a(t)
		mux := http.NewServeMux()
		handler.AttachSignUpHandler(mux, auth, tmpl)
		authtest.NewTestAccount(t, auth)
		token, err := auth.NewSignUpSession()
		assert.Nil(t, err)
		err = auth.SetSignUpSessionIdentity(token, authtest.TEST_EMAIL, authtest.TEST_USERNAME)
		assert.Nil(t, err)
		err = auth.SetSignUpSessionChallenge(token, authtest.TEST_CHALLENGE)
		assert.Nil(t, err)
		values := url.Values{}
		values.Add("verification", authtest.TEST_CHALLENGE)
		reader := strings.NewReader(values.Encode())
		request := httptest.NewRequest(http.MethodPost, "/sign-up-verification", reader)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(auth.NewSignUpSessionCookie(token))
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		result := response.Result()
		assert.Equal(t, http.StatusFound, result.StatusCode)
		cookies := result.Cookies()
		assert.Equal(t, 1, len(cookies))
		assert.Equal(t, authgo.COOKIE_SIGN_IN, cookies[0].Name)
		u, err := result.Location()
		assert.Nil(t, err)
		assert.Equal(t, "/account", u.String())
		username, authenticated, _, errmsg, ok := auth.LookupSignInSession(cookies[0].Value)
		assert.Equal(t, authtest.TEST_USERNAME, username)
		assert.True(t, authenticated)
		assert.Empty(t, errmsg)
		assert.True(t, ok)
		assert.True(t, auth.IsEmailVerified(authtest.TEST_EMAIL))
	})
	t.Run("Redirects When Challenge Is Incorrect", func(t *testing.T) {
		auth := a(t)
		mux := http.NewServeMux()
		handler.AttachSignUpHandler(mux, auth, tmpl)
		token, err := auth.NewSignUpSession()
		assert.Nil(t, err)
		cookie := auth.NewSignUpSessionCookie(token)
		err = auth.SetSignUpSessionChallenge(token, authtest.TEST_CHALLENGE)
		assert.Nil(t, err)
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
		assert.Equal(t, authgo.ErrEmailVerificationIncorrect.Error(), string(body))
	})
}
