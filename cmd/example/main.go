package main

import (
	"aletheiaware.com/authgo"
	"aletheiaware.com/authgo/account"
	"aletheiaware.com/authgo/authtest"
	"aletheiaware.com/authgo/cmd/example/handler"
	"aletheiaware.com/authgo/cmd/example/model"
	authhandler "aletheiaware.com/authgo/handler"
	"aletheiaware.com/authgo/session"
	nethandler "aletheiaware.com/netgo/handler"
	"crypto/tls"
	"embed"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"path"
	"time"
)

//go:embed assets
var embeddedFS embed.FS

func main() {
	// Create Multiplexer
	mux := http.NewServeMux()

	nethandler.AttachHealthHandler(mux)

	// Handle Static Assets
	staticFS, err := fs.Sub(embeddedFS, path.Join("assets", "html", "static"))
	if err != nil {
		log.Fatal(err)
	}
	nethandler.AttachStaticFSHandler(mux, staticFS)

	// Parse Templates
	templateFS, err := fs.Sub(embeddedFS, path.Join("assets", "html", "template"))
	if err != nil {
		log.Fatal(err)
	}
	templates, err := template.ParseFS(templateFS, "*.go.html")
	if err != nil {
		log.Fatal(err)
	}

	// Create Account Manager
	am := account.NewInMemoryManager()

	// Add Demo Account
	if _, err := am.New(authtest.TEST_EMAIL, authtest.TEST_USERNAME, []byte(authtest.TEST_PASSWORD)); err != nil {
		log.Fatal(err)
	}
	am.SetEmailVerified(authtest.TEST_EMAIL, true)

	// Create a Session Manager
	sm := session.NewInMemoryManager()

	// Create Email Verifier
	ev := authtest.NewEmailVerifier()

	// Create an Authenticator
	a := authgo.NewAuthenticator(am, sm, ev)

	// Attach Authentication Handlers
	authhandler.AttachHandlers(a, mux, templates)

	// Create Product Manager
	products := model.NewInMemoryProductManager()

	// Add Demo Products
	products.AddProduct(&model.Product{
		ID:   "1",
		Name: "Foo",
	})
	products.AddProduct(&model.Product{
		ID:   "2",
		Name: "Bar",
	})

	// Handle All Products
	handler.AttachProductsHandler(mux, a, products, templates)

	// Handle Individual Product
	handler.AttachProductHandler(mux, a, products, templates)

	// Handle Index
	handler.AttachIndexHandler(mux, a, templates)

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
