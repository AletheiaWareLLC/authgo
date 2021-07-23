package handler

import (
	"aletheiaware.com/authgo"
	"aletheiaware.com/netgo/handler"
	"html/template"
	"net/http"
)

func AttachHandlers(m *http.ServeMux, a authgo.Authenticator, ts *template.Template) {
	m.Handle("/account", handler.Log(Account(a, ts)))
	m.Handle("/account-password", handler.Log(AccountPassword(a, ts)))
	m.Handle("/account-recovery", handler.Log(AccountRecovery(a, ts)))
	m.Handle("/account-recovery-verification", handler.Log(AccountRecoveryVerification(a, ts)))
	m.Handle("/sign-in", handler.Log(SignIn(a, ts)))
	m.Handle("/sign-out", handler.Log(SignOut(a, ts)))
	m.Handle("/sign-up", handler.Log(SignUp(a, ts)))
	m.Handle("/sign-up-verification", handler.Log(SignUpVerification(a, ts)))
}
