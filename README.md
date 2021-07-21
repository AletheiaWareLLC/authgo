authgo
======

authgo is an authentication library that makes it easy to add authentication to your webserver.

authgo is simple to setup and offers complete control of the HTML templates and stylesheets so your website can match your existing style and brand.

# Getting Started

1. Get the library
```console
go get aletheiaware.com/authgo
```

2. Create the Account Manager.
```go
// In a test environment use an In-Memory Account Manager.
am := account.NewInMemoryManager()

// In production implement the Account Manager interface to connect to your database.
am := NewDatabaseAccountManager(db)
```

3. Create the Session Manager.
```go
// In a test environment use an In-Memory Session Manager.
sm := session.NewInMemoryManager()

// In production implement the Session Manager interface to connect to your database.
am := NewDatabaseSessionManager(db)
```

4. Create the Email Validator.
```go
// In a test environment use a mock verifier (code is always authtest.TEST_CHALLENGE)
ev := authtest.NewEmailVerifier()

// In production use an SMTP service to send the verification code.
ev := email.NewSmtpEmailVerifier("smtp-relay.gmail.com:25", "noreply@example.com", templates.Lookup("email-verification.go.html"))
```

5. Create the Authenticator.
```go
auth := authgo.NewAuthenticator(am, sm, ev)
```

6. Attach the HTTP Handlers with the HTML templates.
```go
handler.AttachHandlers(auth, mux, templates)
```

7. Add Authentication Checks to your HTTP Handlers.
```go
mux.Handle("/greeter", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    account := auth.CurrentAccount(w, r)
    if account == nil {
        authgo.RedirectSignIn(w, r)
        return
    }
    // Request is authorized, greet the user
    fmt.Fprintf(w, "Hello %s!", account.Username)
}))
```
