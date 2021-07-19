package main

import (
	"aletheiaware.com/authgo"
	"aletheiaware.com/authgo/authtest"
	"crypto/tls"
	"embed"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"path"
	"time"
)

//go:embed html
var embeddedFS embed.FS

func main() {
	// Create Multiplexer
	mux := http.NewServeMux()

	AttachHealthHandler(mux)

	// Handle Static Assets
	staticFS, err := fs.Sub(embeddedFS, path.Join("html", "static"))
	if err != nil {
		log.Fatal(err)
	}
	AttachStaticHandler(mux, staticFS)

	// Parse Templates
	templateFS, err := fs.Sub(embeddedFS, path.Join("html", "template"))
	if err != nil {
		log.Fatal(err)
	}
	templates, err := template.ParseFS(templateFS, "*.go.html")
	if err != nil {
		log.Fatal(err)
	}

	// Create Account Manager
	am := authgo.NewInMemoryAccountManager()

	// Add Demo Account
	if _, err := am.New(authtest.TEST_EMAIL, authtest.TEST_USERNAME, authtest.TEST_PASSWORD); err != nil {
		log.Fatal(err)
	}
	am.SetVerified(authtest.TEST_EMAIL, true)

	// Create a Session Manager
	sm := authgo.NewInMemorySessionManager()

	// Create Email Verifier
	ev := authtest.NewEmailVerifier()

	// Create an Authenticator
	a := authgo.NewAuthenticator(am, sm, ev)

	// Attach Authentication Handlers
	authgo.AttachHandlers(a, mux, templates)

	// Create Product Manager
	products := NewInMemoryProductManager()

	// Add Demo Products
	products.AddProduct(&Product{
		ID:   "1",
		Name: "Foo",
	})
	products.AddProduct(&Product{
		ID:   "2",
		Name: "Bar",
	})

	// Handle All Products
	AttachProductsHandler(mux, a, products, templates)

	// Handle Individual Product
	AttachProductHandler(mux, a, products, templates)

	// Handle Index
	AttachIndexHandler(mux, a, templates)

	// Start Server
	if authgo.Secure() {
		// Serve HTTPS Requests
		config := &tls.Config{MinVersion: tls.VersionTLS10}
		server := &http.Server{Addr: ":443",
			Handler:           mux,
			TLSConfig:         config,
			ReadTimeout:       5 * time.Second,
			ReadHeaderTimeout: 5 * time.Second,
			WriteTimeout:      5 * time.Second,
			IdleTimeout:       5 * time.Second,
		}
		if err := server.ListenAndServeTLS(path.Join("certificates", "fullchain.pem"), path.Join("certificates", "privkey.pem")); err != nil {
			log.Fatal(err)
		}
	} else {
		// Server HTTP Requests
		log.Println("HTTP Server Listening on :80")
		if err := http.ListenAndServe(":80", mux); err != nil {
			log.Fatal(err)
		}
	}
}
