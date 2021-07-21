package authgo

import (
	"aletheiaware.com/netgo"
	"html/template"
	"log"
	"net/http"
	"strings"
)

func AttachHandlers(a Authenticator, m *http.ServeMux, ts *template.Template) {
	m.Handle("/account", netgo.LoggingHandler(AccountHandler(a, ts)))
	m.Handle("/sign-in", netgo.LoggingHandler(SignInHandler(a, ts)))
	m.Handle("/sign-out", netgo.LoggingHandler(SignOutHandler(a, ts)))
	m.Handle("/sign-up", netgo.LoggingHandler(SignUpHandler(a, ts)))
	m.Handle("/sign-up-verification", netgo.LoggingHandler(SignUpVerificationHandler(a, ts)))
}

func AccountHandler(a Authenticator, ts *template.Template) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		account := a.CurrentAccount(w, r)
		if account == nil {
			RedirectSignIn(w, r)
			return
		}
		data := struct {
			Account *Account
		}{
			Account: account,
		}
		if err := ts.ExecuteTemplate(w, "account.go.html", data); err != nil {
			log.Println(err)
			return
		}
	})
}

func SignInHandler(a Authenticator, ts *template.Template) http.Handler {
	am := a.AccountManager()
	sm := a.SessionManager()
	ev := a.EmailVerifier()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, username, authenticated, errmsg := CurrentSignIn(sm, r)
		// log.Println("CurrentSignIn", token, username, authenticated, errmsg)
		switch r.Method {
		case "GET":
			if token == "" {
				t, err := sm.NewSignIn("")
				// log.Println("NewSignIn", t, err)
				if err != nil {
					log.Println(err)
					http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
					return
				}
				token = t
				http.SetCookie(w, NewSignInCookie(token))
			}
			if authenticated {
				// Already signed in
				RedirectAccount(w, r)
				return
			}
			data := struct {
				Username string
				Error    string
			}{
				Username: username,
				Error:    errmsg,
			}
			if err := ts.ExecuteTemplate(w, "sign-in.go.html", data); err != nil {
				log.Println(err)
				return
			}
		case "POST":
			if token == "" {
				RedirectSignIn(w, r)
				return
			}
			sm.SetSignInError(token, "")

			username := strings.TrimSpace(r.FormValue("username"))
			password := []byte(strings.TrimSpace(r.FormValue("password")))

			if err := sm.SetSignInUsername(token, username); err != nil {
				log.Println(err)
				sm.SetSignInError(token, err.Error())
				RedirectSignIn(w, r)
				return
			}

			account, err := am.Authenticate(username, password)
			// log.Println("AuthenticateAccount", account, err)
			if err != nil {
				log.Println(err)
				sm.SetSignInError(token, err.Error())
				RedirectSignIn(w, r)
				return
			}

			if err := sm.SetSignInAuthenticated(token, true); err != nil {
				log.Println(err)
				sm.SetSignInError(token, err.Error())
				RedirectSignIn(w, r)
				return
			}

			if !am.IsEmailVerified(account.Email) {
				token, err := sm.NewSignUp()
				// log.Println("NewSignUp", token, err)
				if err != nil {
					log.Println(err)
					http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
					return
				}
				if err := sm.SetSignUpIdentity(token, account.Email, account.Username); err != nil {
					log.Println(err)
					http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
				}

				http.SetCookie(w, NewSignUpCookie(token))

				code, err := ev.VerifyEmail(account.Email)
				// log.Println("VerifyEmail", code, err)
				if err != nil {
					log.Println(err)
					sm.SetSignUpError(token, err.Error())
					RedirectSignIn(w, r)
					return
				}
				if err := sm.SetSignUpChallenge(token, code); err != nil {
					log.Println(err)
					sm.SetSignUpError(token, err.Error())
					RedirectSignIn(w, r)
					return
				}
				RedirectSignUpVerification(w, r)
				return
			}
			RedirectAccount(w, r)
		}
	})
}

func SignOutHandler(a Authenticator, ts *template.Template) http.Handler {
	am := a.AccountManager()
	sm := a.SessionManager()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, username, authenticated, errmsg := CurrentSignIn(sm, r)
		// log.Println("CurrentSignIn", token, username, authenticated, errmsg)
		if token == "" || username == "" || !authenticated {
			// Not signed in
			RedirectIndex(w, r)
			return
		}
		switch r.Method {
		case "GET":
			data := struct {
				Account *Account
				Error   string
			}{
				Error: errmsg,
			}
			account, err := am.Lookup(username)
			if err == nil {
				data.Account = account
			}
			if err := ts.ExecuteTemplate(w, "sign-out.go.html", data); err != nil {
				log.Println(err)
				return
			}
		case "POST":
			sm.SetSignInError(token, "")
			if err := sm.SetSignInAuthenticated(token, false); err != nil {
				log.Println(err)
			}
			RedirectIndex(w, r)
		}
	})
}

func SignUpHandler(a Authenticator, ts *template.Template) http.Handler {
	am := a.AccountManager()
	sm := a.SessionManager()
	ev := a.EmailVerifier()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a := a.CurrentAccount(w, r); a != nil {
			// Already signed in
			RedirectAccount(w, r)
			return
		}
		token, email, username, _, errmsg := CurrentSignUp(sm, r)
		// log.Println("CurrentSignUp", token, email, username, challenge, errmsg)
		switch r.Method {
		case "GET":
			if token == "" {
				t, err := sm.NewSignUp()
				// log.Println("NewSignUp", t, err)
				if err != nil {
					log.Println(err)
					http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
					return
				}
				token = t
				http.SetCookie(w, NewSignUpCookie(token))
			}
			data := struct {
				Email,
				Username,
				Error string
			}{
				Email:    email,
				Username: username,
				Error:    errmsg,
			}
			if err := ts.ExecuteTemplate(w, "sign-up.go.html", data); err != nil {
				log.Println(err)
				return
			}
		case "POST":
			if token == "" {
				RedirectSignUp(w, r)
				return
			}
			sm.SetSignUpError(token, "")

			email := strings.TrimSpace(r.FormValue("email"))
			username := strings.TrimSpace(r.FormValue("username"))
			password := []byte(strings.TrimSpace(r.FormValue("password")))
			confirmation := []byte(strings.TrimSpace(r.FormValue("confirmation")))

			if err := sm.SetSignUpIdentity(token, email, username); err != nil {
				log.Println(err)
				sm.SetSignUpError(token, err.Error())
				RedirectSignUp(w, r)
				return
			}

			// Check valid email
			if err := ValidateEmail(email); err != nil {
				log.Println(err)
				sm.SetSignUpError(token, err.Error())
				RedirectSignUp(w, r)
				return
			}

			// Check valid username
			if err := ValidateUsername(username); err != nil {
				log.Println(err)
				sm.SetSignUpError(token, err.Error())
				RedirectSignUp(w, r)
				return
			}

			// Check valid password and matching confirm
			if err := ValidatePassword(password); err != nil {
				log.Println(err)
				sm.SetSignUpError(token, err.Error())
				RedirectSignUp(w, r)
				return
			}
			if err := MatchPasswords(password, confirmation); err != nil {
				log.Println(err)
				sm.SetSignUpError(token, err.Error())
				RedirectSignUp(w, r)
				return
			}

			_, err := am.New(email, username, password)
			// log.Println("NewAccount", acc, err)
			if err != nil {
				log.Println(err)
				sm.SetSignUpError(token, err.Error())
				RedirectSignUp(w, r)
				return
			}

			code, err := ev.VerifyEmail(email)
			// log.Println("VerifyEmail", code, err)
			if err != nil {
				log.Println(err)
				sm.SetSignUpError(token, err.Error())
				RedirectSignUp(w, r)
				return
			}
			if err := sm.SetSignUpChallenge(token, code); err != nil {
				log.Println(err)
				sm.SetSignUpError(token, err.Error())
				RedirectSignUp(w, r)
				return
			}

			RedirectSignUpVerification(w, r)
		}
	})
}

func SignUpVerificationHandler(a Authenticator, ts *template.Template) http.Handler {
	am := a.AccountManager()
	sm := a.SessionManager()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, email, username, challenge, errmsg := CurrentSignUp(sm, r)
		// log.Println("CurrentSignUp", token, email, username, challenge, errmsg)
		if token == "" {
			RedirectSignUp(w, r)
			return
		}
		switch r.Method {
		case "GET":
			data := struct {
				Error string
			}{
				Error: errmsg,
			}
			if err := ts.ExecuteTemplate(w, "sign-up-verification.go.html", data); err != nil {
				log.Println(err)
				return
			}
		case "POST":
			sm.SetSignUpError(token, "")

			if strings.TrimSpace(r.FormValue("verification")) != challenge {
				sm.SetSignUpError(token, ErrIncorrectEmailVerification.Error())
				RedirectSignUpVerification(w, r)
				return
			}

			if err := am.SetEmailVerified(email, true); err != nil {
				log.Println(err)
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
				return
			}

			token, err := sm.NewSignIn(username)
			// log.Println("NewSignIn", token, err)
			if err != nil {
				log.Println(err)
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
				return
			}

			http.SetCookie(w, NewSignInCookie(token))

			RedirectIndex(w, r)
		}
	})
}
