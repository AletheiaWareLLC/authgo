package main

import (
	"aletheiaware.com/authgo"
	"aletheiaware.com/authgo/authtest"
	"aletheiaware.com/authgo/cmd/example/handler"
	"aletheiaware.com/authgo/cmd/example/model"
	"aletheiaware.com/authgo/database"
	authhandler "aletheiaware.com/authgo/handler"
	"aletheiaware.com/netgo"
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
	nethandler.AttachStaticFSHandler(mux, staticFS, true)

	// Parse Templates
	templateFS, err := fs.Sub(embeddedFS, path.Join("assets", "html", "template"))
	if err != nil {
		log.Fatal(err)
	}
	templates, err := template.ParseFS(templateFS, "*.go.html")
	if err != nil {
		log.Fatal(err)
	}

	// Create Database
	db := database.NewInMemory()

	// Create Email Verifier
	ev := authtest.NewEmailVerifier()

	// Create an Authenticator
	auth := authgo.NewAuthenticator(db, ev)

	// Add Demo Account
	if _, err := auth.NewAccount(authtest.TEST_EMAIL, authtest.TEST_USERNAME, []byte(authtest.TEST_PASSWORD)); err != nil {
		log.Fatal(err)
	}
	auth.SetEmailVerified(authtest.TEST_EMAIL, true)

	// Attach Authentication Handlers
	authhandler.AttachAuthenticationHandlers(mux, auth, templates)

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
	handler.AttachProductsHandler(mux, auth, products, templates)

	// Handle Individual Product
	handler.AttachProductHandler(mux, auth, products, templates)

	// Handle Index
	handler.AttachIndexHandler(mux, auth, templates)

	// Start Server
	if netgo.IsSecure() {
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
