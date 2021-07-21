package redirect

import (
	"net/http"
)

func SignIn(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/sign-in", http.StatusFound)
}
