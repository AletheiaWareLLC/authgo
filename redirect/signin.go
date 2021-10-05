package redirect

import (
	"net/http"
	"net/url"
)

func SignIn(w http.ResponseWriter, r *http.Request, n string) {
	if n != "" {
		http.Redirect(w, r, "/sign-in?next="+url.QueryEscape(n), http.StatusFound)
	} else {
		http.Redirect(w, r, "/sign-in", http.StatusFound)
	}
}
