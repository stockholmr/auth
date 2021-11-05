package auth

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/jcelliott/lumber"
	"github.com/jmoiron/sqlx"
	"github.com/justinas/alice"
	"golang.org/x/crypto/bcrypt"
)

type authController struct {
	log              lumber.Logger
	sessionStore     sessions.Store
	router           *mux.Router
	userRepo         UserRepository
	authSuccessRoute string
}

type AuthController interface {
	Login(w http.ResponseWriter, r *http.Request)
}

func NewAuthController(db *sqlx.DB, log lumber.Logger, router *mux.Router, sessionStore sessions.Store, authSuccessRouteName string, middleware ...alice.Constructor) AuthController {
	c := &authController{
		log:              log,
		router:           router,
		sessionStore:     sessionStore,
		authSuccessRoute: authSuccessRouteName,
		userRepo:         NewUserRepository(db),
	}

	m := []alice.Constructor{
		c.SessionMiddleware,
	}
	m = append(m, middleware...)

	c.router.Handle("/login", alice.New(m...).ThenFunc(c.Login)).Methods("GET", "POST").Name("login")
	c.router.Handle("/logout", alice.New(m...).ThenFunc(c.Logout)).Methods("GET").Name("logout")
	c.router.Handle("/register", alice.New(m...).ThenFunc(c.Register)).Methods("GET", "POST").Name("register")

	return c
}

func (c *authController) Redirect(w http.ResponseWriter, r *http.Request, routeName string) {
	url, err := c.router.Get(routeName).URL()
	if err != nil {
		c.log.Error("%s", err)
		http.Error(w, "", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	http.Redirect(w, r, url.String(), http.StatusSeeOther)
}

func (c *authController) Login(w http.ResponseWriter, r *http.Request) {

	data := struct {
		Title string
		Error string
	}{
		Title: "Login | FPS Monitor",
		Error: "",
	}

	session := r.Context().Value(SessionKey).(*sessions.Session)

	if r.Method == "POST" {

		username := r.PostFormValue("username")
		password := r.PostFormValue("password")
		remember := r.PostFormValue("remember")

		user, err := c.userRepo.SelectWithUsername(r.Context(), username)
		if err != nil {
			c.log.Debug("%s", err)
			login().ExecuteTemplate(w, "page", data)
			return

			/*a.Templates.ExecuteTemplate(w, "error", &templates.Data{
				"title": "Internal Server Error",
			})*/
		}

		if bcrypt.CompareHashAndPassword([]byte(user.Password.String), []byte(password)) != nil {
			data.Error = "Invalid Username or Password"
			w.WriteHeader(400)
			login().ExecuteTemplate(w, "page", data)
			return
		}

		session.Values["userid"] = user.ID.Int64
		session.Options.MaxAge = 0
		if remember != "" {
			// remember session for 1 week
			session.Options.MaxAge = 604800
		}

		err = session.Save(r, w)
		if err != nil {
			c.log.Warn("failed to save session")
		}

		c.userRepo.Update(r.Context(), user)
		c.Redirect(w, r, c.authSuccessRoute)

	} // end if POST

	if r.Method == "GET" {

		username := session.Values["username"]
		if username == nil {
			login().ExecuteTemplate(w, "page", data)
			return
		}

		_, err := c.userRepo.SelectWithUsername(r.Context(), username.(string))
		if err != nil {
			c.log.Debug("%s", err)
			login().ExecuteTemplate(w, "page", data)
			return

			/*a.Templates.ExecuteTemplate(w, "error", &templates.Data{
				"title": "Internal Server Error",
			})*/
		}

		/*if !user.Active {
			c.log.Warn("user disabled")
			login().ExecuteTemplate(w, "page", data)
			return

			/*log.Printf("[REQUEST] GET|login|Disabled Account Login Attempt|%s", username)
			a.Templates.ExecuteTemplate(w, "error", &templates.Data{
				"title":   "User Restricted",
				"message": "Please contact IT Services",
			})

			// user is not active send to error page
		}*/

	} // end if GET

	login().ExecuteTemplate(w, "page", nil)
}

func (c *authController) Logout(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value(SessionKey).(*sessions.Session)
	session.Options.MaxAge = -1
	if session.Save(r, w) == nil {
		c.Redirect(w, r, "login")
		return
	} else {
		c.log.Debug("failed to save session", "")
	}
}

func (c *authController) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {

	}

	register().ExecuteTemplate(w, "page", nil)
}
