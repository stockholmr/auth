package auth

import (
	"context"
	"net/http"

	"github.com/gorilla/sessions"
)

type Key string

const UserKey Key = "user"
const SessionKey Key = "session"


func (c *authController) SessionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Retrieve session from store
		session, err := c.sessionStore.Get(r, "USERAUTH")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Add the session to the request context
		request := r.Clone(context.WithValue(r.Context(), SessionKey, session))
		next.ServeHTTP(w, request)
	})
}

func (c *authController) AuthenticateMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Retrieve session from context
		session := r.Context().Value(SessionKey).(*sessions.Session)
		userid := session.Values["userid"]
		if userid == nil {
			c.log.Warn("session does not exist")
			c.Redirect(w, r, "login")
			return
		}

		user, err := c.userRepo.Select(r.Context(), userid.(int))
		if err != nil {
			c.log.Warn("user does not exist")
			c.Redirect(w, r, "logout")
			return
		}

		/*if !user.Active {
			c.log.Warn("user is disabled; session deleted")
			redirect(w, r, "/logout")
			return
		}*/

		// Add the current userid to the request context
		request := r.Clone(context.WithValue(r.Context(), UserKey, user.ID))
		next.ServeHTTP(w, request)
	})
}
