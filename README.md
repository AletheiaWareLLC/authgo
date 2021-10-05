authgo
======

authgo is an authentication library that makes it easy to add authentication to your webserver.

authgo is simple to setup and offers complete control of the HTML templates and stylesheets so your website can match your existing style and brand.

# Getting Started

1. Get the library
```console
go get aletheiaware.com/authgo
```

2. Create the Database.
```go
// In a test environment use an In-Memory Database.
db := database.NewInMemoryDatabase()

// In production implement the Database interface to connect to your own database.
db := NewSqlDatabase()
```

3. Create the Email Validator.
```go
// In a test environment use a mock verifier (code is always authtest.TEST_CHALLENGE)
ev := authtest.NewEmailVerifier()

// In production use an SMTP service to send the verification code.
ev := email.NewSmtpEmailVerifier("smtp-relay.gmail.com:25", "example.com", "noreply@example.com", templates.Lookup("email-verification.go.html"))
```

4. Create the Authenticator.
```go
auth := authgo.NewAuthenticator(db, ev)
```

5. Attach the HTTP Handlers with the HTML templates.
```go
handler.AttachAuthenticationHandlers(mux, auth, templates)
```

6. Add Authentication Checks to your HTTP Handlers.
```go
mux.Handle("/greeter", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    account := auth.CurrentAccount(w, r)
    if account == nil {
        redirect.SignIn(w, r, r.URL.String())
        return
    }
    // Request is authorized, greet the user
    fmt.Fprintf(w, "Hello %s!", account.Username)
}))
```
