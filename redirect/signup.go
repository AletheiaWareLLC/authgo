package redirect

import (
	"net/http"
)

func SignUp(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/sign-up", http.StatusFound)
}

func SignUpVerification(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/sign-up-verification", http.StatusFound)
}
