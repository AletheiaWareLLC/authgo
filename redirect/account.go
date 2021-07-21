package redirect

import (
	"net/http"
)

func Account(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/account", http.StatusFound)
}
