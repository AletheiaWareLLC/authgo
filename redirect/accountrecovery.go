package redirect

import (
	"net/http"
)

func AccountRecovery(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/account-recovery", http.StatusFound)
}

func AccountRecoveryVerification(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/account-recovery-verification", http.StatusFound)
}
