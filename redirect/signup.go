package redirect

import (
	"net/http"
	"net/url"
)

func SignUp(w http.ResponseWriter, r *http.Request, n string) {
	if n != "" {
		http.Redirect(w, r, "/sign-up?next="+url.QueryEscape(n), http.StatusFound)
	} else {
		http.Redirect(w, r, "/sign-up", http.StatusFound)
	}
}

func SignUpVerification(w http.ResponseWriter, r *http.Request, n string) {
	if n != "" {
		http.Redirect(w, r, "/sign-up-verification?next="+url.QueryEscape(n), http.StatusFound)
	} else {
		http.Redirect(w, r, "/sign-up-verification", http.StatusFound)
	}
}
