package handler

import (
	"aletheiaware.com/netgo"
	"net/http"
)

func AttachHealthHandler(m *http.ServeMux) {
	m.Handle("/health", netgo.LoggingHandler(Health()))
}

func Health() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}
