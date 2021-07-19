package authgo

import (
	"aletheiaware.com/netgo"
	"html/template"
	"log"
	"net/http"
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
		_, session := sm.Current(SESSION_SIGN_IN_COOKIE, w, r)
		switch r.Method {
		case "GET":
			if session == nil {
				id, sess, err := sm.New(SESSION_SIGN_IN_COOKIE, SESSION_SIGN_IN_TIMEOUT, Secure())
				if err != nil {
					log.Println(err)
					http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
					return
				}
				session = sess
				http.SetCookie(w, session.Cookie(id))
			}
			if session.Account() != nil {
				// Already signed in
				RedirectAccount(w, r)
				return
			}
			data := struct {
				Error string
			}{}
			if err := session.Error(); err != nil {
				data.Error = err.Error()
			}
			if err := ts.ExecuteTemplate(w, "sign-in.go.html", data); err != nil {
				log.Println(err)
				return
			}
		case "POST":
			if session == nil {
				RedirectSignIn(w, r)
				return
			}
			username := r.FormValue("username")
			password := r.FormValue("password")
			if err := am.Authenticate(session, username, password); err != nil {
				log.Println(err)
				session.SetError(err)
				RedirectSignIn(w, r)
				return
			}
			if account := session.Account(); !am.Verified(account.Email) {
				id, sess, err := sm.New(SESSION_SIGN_UP_COOKIE, SESSION_SIGN_UP_TIMEOUT, Secure())
				if err != nil {
					log.Println(err)
					http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
					return
				}
				http.SetCookie(w, sess.Cookie(id))
				code, err := ev.VerifyEmail(account.Email)
				if err != nil {
					log.Println(err)
					session.SetError(err)
					RedirectSignIn(w, r)
					return
				}
				sess.SetAccount(account)
				sess.SetValue(SESSION_SIGN_UP_USERNAME, username)
				sess.SetValue(SESSION_SIGN_UP_EMAIL, account.Email)
				sess.SetValue(SESSION_SIGN_UP_CHALLENGE, code)
				RedirectSignUpVerification(w, r)
				return
			}
			RedirectAccount(w, r)
		}
	})
}

func SignOutHandler(a Authenticator, ts *template.Template) http.Handler {
	sm := a.SessionManager()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, session := sm.Current(SESSION_SIGN_IN_COOKIE, w, r)
		if session == nil || session.Account() == nil {
			// Not signed in
			RedirectIndex(w, r)
			return
		}
		switch r.Method {
		case "GET":
			data := struct {
				Error   string
				Account *Account
			}{}
			if a := session.Account(); a != nil {
				data.Account = a
			}
			if err := ts.ExecuteTemplate(w, "sign-out.go.html", data); err != nil {
				log.Println(err)
				return
			}
		case "POST":
			session.SetAccount(nil)
			sm.Delete(id)
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
		_, session := sm.Current(SESSION_SIGN_UP_COOKIE, w, r)
		switch r.Method {
		case "GET":
			if session == nil {
				id, sess, err := sm.New(SESSION_SIGN_UP_COOKIE, SESSION_SIGN_UP_TIMEOUT, Secure())
				if err != nil {
					log.Println(err)
					http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
					return
				}
				session = sess
				http.SetCookie(w, session.Cookie(id))
			}
			data := struct {
				Error,
				Email,
				Username string
			}{
				Email:    session.Value(SESSION_SIGN_UP_EMAIL),
				Username: session.Value(SESSION_SIGN_UP_USERNAME),
			}
			if err := session.Error(); err != nil {
				data.Error = err.Error()
			}
			if err := ts.ExecuteTemplate(w, "sign-up.go.html", data); err != nil {
				log.Println(err)
				return
			}
		case "POST":
			if session == nil {
				RedirectSignUp(w, r)
				return
			}
			email := r.FormValue("email")
			username := r.FormValue("username")
			password := r.FormValue("password")
			confirmation := r.FormValue("confirmation")
			session.SetValue(SESSION_SIGN_UP_EMAIL, email)
			session.SetValue(SESSION_SIGN_UP_USERNAME, username)
			session.SetValue(SESSION_SIGN_UP_PASSWORD, password)
			session.SetValue(SESSION_SIGN_UP_CONFIRMATION, confirmation)
			if err := ValidateSignUpSession(session); err != nil {
				log.Println(err)
				session.SetError(err)
				RedirectSignUp(w, r)
				return
			}
			acc, err := am.New(email, username, password)
			if err != nil {
				log.Println(err)
				session.SetError(err)
				RedirectSignUp(w, r)
				return
			}
			session.SetAccount(acc)
			code, err := ev.VerifyEmail(email)
			if err != nil {
				log.Println(err)
				session.SetError(err)
				RedirectSignUp(w, r)
				return
			}
			session.SetValue(SESSION_SIGN_UP_CHALLENGE, code)
			RedirectSignUpVerification(w, r)
		}
	})
}

func SignUpVerificationHandler(a Authenticator, ts *template.Template) http.Handler {
	am := a.AccountManager()
	sm := a.SessionManager()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, session := sm.Current(SESSION_SIGN_UP_COOKIE, w, r)
		if session == nil {
			RedirectSignUp(w, r)
			return
		}
		switch r.Method {
		case "GET":
			data := struct {
				Error string
			}{}
			if err := session.Error(); err != nil {
				data.Error = err.Error()
			}
			if err := ts.ExecuteTemplate(w, "sign-up-verification.go.html", data); err != nil {
				log.Println(err)
				return
			}
		case "POST":
			session.SetError(nil)
			v := r.FormValue("verification")
			session.SetValue(SESSION_SIGN_UP_VERIFICATION, v)
			if v != session.Value(SESSION_SIGN_UP_CHALLENGE) {
				session.SetError(ErrIncorrectEmailVerification)
				RedirectSignUpVerification(w, r)
				return
			}
			account := session.Account()
			am.SetVerified(account.Email, true)
			sm.Delete(id)
			id, sess, err := sm.New(SESSION_SIGN_IN_COOKIE, SESSION_SIGN_IN_TIMEOUT, Secure())
			if err != nil {
				log.Println(err)
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
				return
			}
			sess.SetAccount(account)
			http.SetCookie(w, sess.Cookie(id))
			RedirectIndex(w, r)
		}
	})
}
