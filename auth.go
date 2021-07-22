package authgo

import (
	"aletheiaware.com/netgo"
	"log"
	"net/http"
	"os"
	"time"
)

func Secure() bool {
	https, ok := os.LookupEnv(netgo.HTTPS)
	return ok && https == "true"
}

type Authenticator interface {
	CurrentAccount(w http.ResponseWriter, r *http.Request) *Account
	NewAccount(string, string, []byte) (*Account, error)
	LookupAccount(string) (*Account, error)
	AuthenticateAccount(string, []byte) (*Account, error)
	LookupUsername(string) (string, error)
	ChangePassword(string, []byte) error

	IsEmailVerified(string) bool
	SetEmailVerified(string, bool) error
	EmailVerifier() EmailVerifier

	CurrentSignUpSession(*http.Request) (string, string, string, string, string)
	NewSignUpSession() (string, error)
	LookupSignUpSession(string) (string, string, string, string, bool)
	SetSignUpSessionIdentity(string, string, string) error
	SetSignUpSessionChallenge(string, string) error
	SetSignUpSessionError(string, string)

	CurrentSignInSession(*http.Request) (string, string, bool, string)
	NewSignInSession(string) (string, error)
	LookupSignInSession(string) (string, bool, string, bool)
	SetSignInSessionUsername(string, string) error
	SetSignInSessionAuthenticated(string, bool) error
	SetSignInSessionError(string, string)

	CurrentAccountPasswordSession(*http.Request) (string, string, string)
	NewAccountPasswordSession(string) (string, error)
	LookupAccountPasswordSession(string) (string, string, bool)
	SetAccountPasswordSessionError(string, string)

	CurrentAccountRecoverySession(*http.Request) (string, string, string, string, string)
	NewAccountRecoverySession() (string, error)
	LookupAccountRecoverySession(string) (string, string, string, string, bool)
	SetAccountRecoverySessionEmail(string, string) error
	SetAccountRecoverySessionUsername(string, string) error
	SetAccountRecoverySessionChallenge(string, string) error
	SetAccountRecoverySessionError(string, string)
}

func NewAuthenticator(db Database, ev EmailVerifier) Authenticator {
	return &authenticator{
		database: db,
		verifier: ev,
	}
}

type authenticator struct {
	database Database
	verifier EmailVerifier
}

func (a *authenticator) CurrentAccount(w http.ResponseWriter, r *http.Request) *Account {
	token, username, authenticated, _ := a.CurrentSignInSession(r)
	log.Println(token, username, authenticated)
	if token == "" || username == "" || !authenticated {
		return nil
	}
	a.SetSignInSessionAuthenticated(token, false)
	token, err := a.NewSignInSession(username)
	if err != nil {
		log.Println(err)
		return nil
	}
	http.SetCookie(w, NewSignInSessionCookie(token))
	account, err := a.LookupAccount(username)
	if err != nil {
		return nil
	}
	return account
}

func (a *authenticator) NewAccount(email, username string, password []byte) (*Account, error) {
	hash, err := GeneratePasswordHash(password)
	if err != nil {
		return nil, err
	}
	created := time.Now()
	id, err := a.database.CreateUser(email, username, hash, created)
	if err != nil {
		return nil, err
	}
	log.Println("Created Account", id)
	acc := &Account{
		Email:    email,
		Username: username,
		Created:  created,
	}
	return acc, nil
}

func (a *authenticator) LookupAccount(username string) (*Account, error) {
	email, _, created, err := a.database.SelectUser(username)
	if err != nil {
		return nil, err
	}
	return &Account{
		Email:    email,
		Username: username,
		Created:  created,
	}, nil
}

func (a *authenticator) AuthenticateAccount(username string, password []byte) (*Account, error) {
	email, hash, created, err := a.database.SelectUser(username)
	if err != nil {
		log.Println(err)
		return nil, ErrIncorrectCredentials
	}
	if !CheckPasswordHash(hash, password) {
		return nil, ErrIncorrectCredentials
	}
	return &Account{
		Email:    email,
		Username: username,
		Created:  created,
	}, nil
}

func (a *authenticator) LookupUsername(email string) (string, error) {
	return a.database.LookupUsername(email)
}

func (a *authenticator) ChangePassword(username string, password []byte) error {
	hash, err := GeneratePasswordHash(password)
	if err != nil {
		return err
	}
	_, err = a.database.ChangePassword(username, hash)
	return err
}

func (a *authenticator) IsEmailVerified(email string) bool {
	verified, err := a.database.IsEmailVerified(email)
	if err != nil {
		log.Println(err)
		return false
	}
	return verified
}

func (a *authenticator) SetEmailVerified(email string, verified bool) error {
	_, err := a.database.SetEmailVerified(email, verified)
	return err
}

func (a *authenticator) EmailVerifier() EmailVerifier {
	return a.verifier
}

func (a authenticator) CurrentSignUpSession(r *http.Request) (string, string, string, string, string) {
	c, err := r.Cookie(COOKIE_SIGN_UP)
	if err != nil {
		return "", "", "", "", ""
	}
	token := c.Value
	email, username, challenge, errmsg, ok := a.LookupSignUpSession(token)
	if !ok {
		return "", "", "", "", ""
	}
	return token, email, username, challenge, errmsg
}

func (a *authenticator) NewSignUpSession() (string, error) {
	token, err := NewSessionToken()
	if err != nil {
		return "", err
	}

	id, err := a.database.CreateSignUpSession(token, time.Now())
	if err != nil {
		return "", err
	}
	log.Println("Created Sign Up", id)

	return token, nil
}

func (a *authenticator) LookupSignUpSession(token string) (string, string, string, string, bool) {
	errmsg, email, username, challenge, created, err := a.database.SelectSignUpSession(token)
	if err != nil {
		log.Println(err)
		return "", "", "", "", false
	}
	if created.Add(SESSION_SIGN_UP_TIMEOUT).Before(time.Now()) {
		return "", "", "", "", false
	}
	return email, username, challenge, errmsg, true
}

func (a *authenticator) SetSignUpSessionError(token string, errmsg string) {
	_, err := a.database.UpdateSignUpSessionError(token, errmsg)
	log.Println(err)
}

func (a *authenticator) SetSignUpSessionIdentity(token, email, username string) error {
	_, err := a.database.UpdateSignUpSessionIdentity(token, email, username)
	return err
}

func (a *authenticator) SetSignUpSessionChallenge(token, challenge string) error {
	_, err := a.database.UpdateSignUpSessionChallenge(token, challenge)
	return err
}

func (a authenticator) CurrentSignInSession(r *http.Request) (string, string, bool, string) {
	c, err := r.Cookie(COOKIE_SIGN_IN)
	if err != nil {
		return "", "", false, ""
	}
	token := c.Value
	username, authenticated, errmsg, ok := a.LookupSignInSession(token)
	if !ok {
		return "", "", false, ""
	}
	return token, username, authenticated, errmsg
}

func (a *authenticator) NewSignInSession(username string) (string, error) {
	token, err := NewSessionToken()
	if err != nil {
		return "", err
	}

	id, err := a.database.CreateSignInSession(token, username, time.Now())
	if err != nil {
		return "", err
	}
	log.Println("Created Sign In", id)

	return token, nil
}

func (a *authenticator) LookupSignInSession(token string) (string, bool, string, bool) {
	errmsg, username, created, authenticated, err := a.database.SelectSignInSession(token)
	if err != nil {
		log.Println(err)
		return "", false, "", false
	}
	if created.Add(SESSION_SIGN_IN_TIMEOUT).Before(time.Now()) {
		return "", false, "", false
	}
	return username, authenticated, errmsg, true
}

func (a *authenticator) SetSignInSessionError(token string, errmsg string) {
	_, err := a.database.UpdateSignInSessionError(token, errmsg)
	log.Println(err)
}

func (a *authenticator) SetSignInSessionUsername(token string, username string) error {
	_, err := a.database.UpdateSignInSessionUsername(token, username)
	return err
}

func (a *authenticator) SetSignInSessionAuthenticated(token string, authenticated bool) error {
	_, err := a.database.UpdateSignInSessionAuthenticated(token, authenticated)
	return err
}

func (a authenticator) CurrentAccountPasswordSession(r *http.Request) (string, string, string) {
	c, err := r.Cookie(COOKIE_ACCOUNT_PASSWORD)
	if err != nil {
		return "", "", ""
	}
	token := c.Value
	username, errmsg, ok := a.LookupAccountPasswordSession(token)
	if !ok {
		return "", "", ""
	}
	return token, username, errmsg
}

func (a *authenticator) NewAccountPasswordSession(username string) (string, error) {
	token, err := NewSessionToken()
	if err != nil {
		return "", err
	}

	id, err := a.database.CreateAccountPasswordSession(token, username, time.Now())
	if err != nil {
		return "", err
	}
	log.Println("Created Account Password", id)

	return token, nil
}

func (a *authenticator) LookupAccountPasswordSession(token string) (string, string, bool) {
	errmsg, username, created, err := a.database.SelectAccountPasswordSession(token)
	if err != nil {
		log.Println(err)
		return "", "", false
	}
	if created.Add(SESSION_ACCOUNT_PASSWORD_TIMEOUT).Before(time.Now()) {
		return "", "", false
	}
	return username, errmsg, true
}

func (a *authenticator) SetAccountPasswordSessionError(token string, errmsg string) {
	_, err := a.database.UpdateAccountPasswordSessionError(token, errmsg)
	log.Println(err)
}

func (a authenticator) CurrentAccountRecoverySession(r *http.Request) (string, string, string, string, string) {
	c, err := r.Cookie(COOKIE_ACCOUNT_RECOVERY)
	if err != nil {
		return "", "", "", "", ""
	}
	token := c.Value
	email, username, challenge, errmsg, ok := a.LookupAccountRecoverySession(token)
	if !ok {
		return "", "", "", "", ""
	}
	return token, email, username, challenge, errmsg
}

func (a *authenticator) NewAccountRecoverySession() (string, error) {
	token, err := NewSessionToken()
	if err != nil {
		return "", err
	}

	id, err := a.database.CreateAccountRecoverySession(token, time.Now())
	if err != nil {
		return "", err
	}
	log.Println("Created Account Recovery", id)

	return token, nil
}

func (a *authenticator) LookupAccountRecoverySession(token string) (string, string, string, string, bool) {
	errmsg, email, username, challenge, created, err := a.database.SelectAccountRecoverySession(token)
	if err != nil {
		log.Println(err)
		return "", "", "", "", false
	}
	if created.Add(SESSION_ACCOUNT_RECOVERY_TIMEOUT).Before(time.Now()) {
		return "", "", "", "", false
	}
	return email, username, challenge, errmsg, true
}

func (a *authenticator) SetAccountRecoverySessionEmail(token string, email string) error {
	_, err := a.database.UpdateAccountRecoverySessionEmail(token, email)
	return err
}

func (a *authenticator) SetAccountRecoverySessionUsername(token string, username string) error {
	_, err := a.database.UpdateAccountRecoverySessionUsername(token, username)
	return err
}

func (a *authenticator) SetAccountRecoverySessionChallenge(token, challenge string) error {
	_, err := a.database.UpdateAccountRecoverySessionChallenge(token, challenge)
	return err
}

func (a *authenticator) SetAccountRecoverySessionError(token string, errmsg string) {
	_, err := a.database.UpdateAccountRecoverySessionError(token, errmsg)
	log.Println(err)
}
