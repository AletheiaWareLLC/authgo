package authgo

import (
	"aletheiaware.com/netgo"
	"log"
	"net/http"
	"os"
)

func Secure() bool {
	https, ok := os.LookupEnv(netgo.HTTPS)
	return ok && https == "true"
}

type Authenticator interface {
	CurrentAccount(w http.ResponseWriter, r *http.Request) *Account
	AccountManager() AccountManager
	SessionManager() SessionManager
	EmailVerifier() EmailVerifier
}

func NewAuthenticator(am AccountManager, sm SessionManager, ev EmailVerifier) Authenticator {
	return &authenticator{
		accounts: am,
		sessions: sm,
		verifier: ev,
	}
}

type authenticator struct {
	accounts AccountManager
	sessions SessionManager
	verifier EmailVerifier
}

func (a *authenticator) CurrentAccount(w http.ResponseWriter, r *http.Request) *Account {
	token, username, authenticated, _ := CurrentSignIn(a.sessions, r)
	log.Println(token, username, authenticated)
	if token == "" || username == "" || !authenticated {
		return nil
	}
	a.sessions.SetSignInAuthenticated(token, false)
	token, err := a.sessions.NewSignIn(username)
	if err != nil {
		log.Println(err)
		return nil
	}
	http.SetCookie(w, NewSignInCookie(token))
	account, err := a.accounts.Lookup(username)
	if err != nil {
		return nil
	}
	return account
}

func (a *authenticator) AccountManager() AccountManager {
	return a.accounts
}

func (a *authenticator) SessionManager() SessionManager {
	return a.sessions
}

func (a *authenticator) EmailVerifier() EmailVerifier {
	return a.verifier
}
