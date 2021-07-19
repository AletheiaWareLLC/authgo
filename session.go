package authgo

import (
	"aletheiaware.com/cryptogo"
	"net/http"
	"sync"
	"time"
)

const (
	SESSION_SIGN_IN_COOKIE       = "sign-in-session"
	SESSION_SIGN_UP_COOKIE       = "sign-up-session"
	SESSION_ID_LENGTH            = 16
	SESSION_SIGN_IN_TIMEOUT      = 30 * time.Minute
	SESSION_SIGN_UP_TIMEOUT      = 10 * time.Minute
	SESSION_SIGN_UP_USERNAME     = "username"
	SESSION_SIGN_UP_EMAIL        = "email"
	SESSION_SIGN_UP_CHALLENGE    = "challenge"
	SESSION_SIGN_UP_VERIFICATION = "verification"
	SESSION_SIGN_UP_PASSWORD     = "password"
	SESSION_SIGN_UP_CONFIRMATION = "confirmation"
)

type Session interface {
	Name() string
	Timeout() time.Duration
	Secure() bool
	Cookie(string) *http.Cookie
	Error() error
	SetError(error)
	Account() *Account
	SetAccount(*Account)
	Value(string) string
	SetValue(string, string)
}

type SessionManager interface {
	New(string, time.Duration, bool) (string, Session, error)
	Current(string, http.ResponseWriter, *http.Request) (string, Session)
	Lookup(string) Session
	Refresh(Session) (string, error)
	Delete(string)
}

func NewSessionId() (string, error) {
	return cryptogo.RandomString(SESSION_ID_LENGTH)
}

/*
func NewSessionCookie(session string, timeout time.Duration, secure bool) *http.Cookie {
	return NewCookie(SESSION_SIGN_IN_COOKIE, session, timeout, secure)
}

func NewSessionCookie(session string, timeout time.Duration, secure bool) *http.Cookie {
	return NewCookie(SESSION_SIGN_UP_COOKIE, session, timeout, secure)
}

func SessionCookies(r *http.Request) []*http.Cookie {
	return Cookies(SESSION_SIGN_IN_COOKIE, r)
}

func SessionCookies(r *http.Request) []*http.Cookie {
	return Cookies(SESSION_SIGN_UP_COOKIE, r)
}
*/

type session struct {
	name    string
	timeout time.Duration
	secure  bool
	error   error
	account *Account
	values  map[string]string
}

func (s *session) Name() string {
	return s.name
}

func (s *session) Timeout() time.Duration {
	return s.timeout
}

func (s *session) Secure() bool {
	return s.secure
}

func (s *session) Cookie(id string) *http.Cookie {
	return NewCookie(s.name, id, s.timeout, s.secure)
}

func (s *session) Error() error {
	return s.error
}

func (s *session) SetError(error error) {
	s.error = error
}

func (s *session) Account() *Account {
	return s.account
}

func (s *session) SetAccount(a *Account) {
	s.account = a
}

func (s *session) Value(key string) string {
	return s.values[key]
}

func (s *session) SetValue(key string, value string) {
	s.values[key] = value
}

func ValidateSignUpSession(s Session) error {
	// Check valid email
	if err := ValidateEmail(s.Value(SESSION_SIGN_UP_EMAIL)); err != nil {
		return err
	}
	// Check valid username
	if err := ValidateUsername(s.Value(SESSION_SIGN_UP_USERNAME)); err != nil {
		return err
	}
	// Check valid password and matching confirm
	if err := ValidatePassword(s.Value(SESSION_SIGN_UP_PASSWORD)); err != nil {
		return err
	}
	if err := MatchPasswords(s.Value(SESSION_SIGN_UP_PASSWORD), s.Value(SESSION_SIGN_UP_CONFIRMATION)); err != nil {
		return err
	}
	return nil
}

func NewInMemorySessionManager() SessionManager {
	return &inMemorySessionManager{
		sessions: make(map[string]Session),
	}
}

type inMemorySessionManager struct {
	sync.RWMutex
	sessions map[string]Session
}

func (m *inMemorySessionManager) Current(name string, w http.ResponseWriter, r *http.Request) (id string, session Session) {
	cookies := Cookies(name, r)
	count := len(cookies)
	for i := 0; i < count && session == nil; i++ {
		id = cookies[i].Value
		session = m.Lookup(id)
	}
	return
}

func (m *inMemorySessionManager) Lookup(id string) Session {
	m.RLock()
	defer m.RUnlock()
	return m.sessions[id]
}

func (m *inMemorySessionManager) New(name string, timeout time.Duration, secure bool) (string, Session, error) {
	s := &session{
		name:    name,
		timeout: timeout,
		secure:  secure,
		values:  make(map[string]string),
	}
	id, err := m.Refresh(s)
	if err != nil {
		return "", nil, err
	}
	return id, s, nil
}

func (m *inMemorySessionManager) Refresh(s Session) (string, error) {
	id, err := NewSessionId()
	if err != nil {
		return "", err
	}

	m.Lock()
	m.sessions[id] = s
	m.Unlock()

	go func() {
		// Delete session after timeout
		time.Sleep(s.Timeout())
		m.Delete(id)
	}()

	return id, nil
}

func (m *inMemorySessionManager) Delete(id string) {
	m.Lock()
	defer m.Unlock()
	delete(m.sessions, id)
}
