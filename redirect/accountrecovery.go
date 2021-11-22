package redirect

import (
	"net/http"
	"net/url"
)

func AccountRecovery(w http.ResponseWriter, r *http.Request, n string) {
	if n != "" {
		http.Redirect(w, r, "/account-recovery?next="+url.QueryEscape(n), http.StatusFound)
	} else {
		http.Redirect(w, r, "/account-recovery", http.StatusFound)
	}
}

func AccountRecoveryVerification(w http.ResponseWriter, r *http.Request, n string) {
	if n != "" {
		http.Redirect(w, r, "/account-recovery-verification?next="+url.QueryEscape(n), http.StatusFound)
	} else {
		http.Redirect(w, r, "/account-recovery-verification", http.StatusFound)
	}
}
