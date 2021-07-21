package handler

import (
	"aletheiaware.com/netgo"
	"io/fs"
	"net/http"
)

func AttachStaticHandler(m *http.ServeMux, fs fs.FS) {
	m.Handle("/static/", netgo.LoggingHandler(http.StripPrefix("/static/", http.FileServer(http.FS(fs)))))
}
