package authgo

import (
	"net/http"
)

func RedirectAccount(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/account", http.StatusFound)
}

func RedirectAccountPassword(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/account-password", http.StatusFound)
}

func RedirectAccountRecovery(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/account-recovery", http.StatusFound)
}

func RedirectAccountRecoveryVerification(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/account-recovery-verification", http.StatusFound)
}

func RedirectIndex(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/", http.StatusFound)
}

func RedirectSignIn(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/sign-in", http.StatusFound)
}

func RedirectSignUp(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/sign-up", http.StatusFound)
}

func RedirectSignUpVerification(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/sign-up-verification", http.StatusFound)
}
