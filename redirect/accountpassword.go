package redirect

import (
	"net/http"
	"net/url"
)

func AccountPassword(w http.ResponseWriter, r *http.Request, n string) {
	if n != "" {
		http.Redirect(w, r, "/account-password?next="+url.QueryEscape(n), http.StatusFound)
	} else {
		http.Redirect(w, r, "/account-password", http.StatusFound)
	}
}
