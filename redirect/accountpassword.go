package redirect

import (
	"net/http"
)

func AccountPassword(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/account-password", http.StatusFound)
}
