package redirect

import (
	"net/http"
)

func AccountDeactivate(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/account-deactivate", http.StatusFound)
}
