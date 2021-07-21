package handler

import (
	"aletheiaware.com/authgo"
	"aletheiaware.com/netgo"
	"html/template"
	"net/http"
)

func AttachHandlers(a authgo.Authenticator, m *http.ServeMux, ts *template.Template) {
	m.Handle("/account", netgo.LoggingHandler(Account(a, ts)))
	m.Handle("/account-password", netgo.LoggingHandler(AccountPassword(a, ts)))
	m.Handle("/account-recovery", netgo.LoggingHandler(AccountRecovery(a, ts)))
	m.Handle("/account-recovery-verification", netgo.LoggingHandler(AccountRecoveryVerification(a, ts)))
	m.Handle("/sign-in", netgo.LoggingHandler(SignIn(a, ts)))
	m.Handle("/sign-out", netgo.LoggingHandler(SignOut(a, ts)))
	m.Handle("/sign-up", netgo.LoggingHandler(SignUp(a, ts)))
	m.Handle("/sign-up-verification", netgo.LoggingHandler(SignUpVerification(a, ts)))
}
