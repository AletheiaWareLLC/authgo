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
	id, session := a.sessions.Current(SESSION_SIGN_IN_COOKIE, w, r)
	if session == nil {
		return nil
	}
	a.sessions.Delete(id)
	id, err := a.sessions.Refresh(session)
	if err != nil {
		log.Println(err)
		return nil
	}
	http.SetCookie(w, session.Cookie(id))
	return session.Account()
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
