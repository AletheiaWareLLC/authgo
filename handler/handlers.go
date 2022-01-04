package handler

import (
	"aletheiaware.com/authgo"
	"html/template"
	"net/http"
)

func AttachAuthenticationHandlers(m *http.ServeMux, a authgo.Authenticator, ts *template.Template) {
	AttachAccountHandler(m, a, ts)
	AttachAccountPasswordHandler(m, a, ts)
	AttachAccountRecoveryHandler(m, a, ts)
	AttachAccountDeactivateHandler(m, a, ts)
	AttachSignInHandler(m, a, ts)
	AttachSignOutHandler(m, a, ts)
	AttachSignUpHandler(m, a, ts)
}
