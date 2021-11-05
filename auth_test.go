package auth

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"testing"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/jcelliott/lumber"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"gopkg.in/guregu/null.v3"
)

var (
	dbCtx context.Context
)

// assert fails the test if the condition is false.
func assert(tb testing.TB, condition bool, msg string, v ...interface{}) {
	if !condition {
		_, file, line, _ := runtime.Caller(1)
		fmt.Printf("%s:%d: "+msg+"\n\n", append([]interface{}{filepath.Base(file), line}, v...)...)
		tb.FailNow()
	}
}

// ok fails the test if an err is not nil.
func ok(tb testing.TB, err error) {
	if err != nil {
		_, file, line, _ := runtime.Caller(1)
		fmt.Printf("%s:%d: unexpected error: %s\n\n", filepath.Base(file), line, err.Error())
		tb.FailNow()
	}
}

// equals fails the test if exp is not equal to act.
func equals(tb testing.TB, exp, act interface{}) {
	if !reflect.DeepEqual(exp, act) {
		_, file, line, _ := runtime.Caller(1)
		fmt.Printf("%s:%d:\n\n\texp: %#v\n\n\tgot: %#v\n\n", filepath.Base(file), line, exp, act)
		tb.FailNow()
	}
}

func dbSetup() (*sqlx.DB, error) {
	db, err := sqlx.Open("sqlite3", ":memory:")
	if err != nil {
		return nil, err
	}
	dbCtx = context.Background()
	return db, nil
}

func TestUserRepositoryInstall(t *testing.T) {
	fmt.Print("Testing User Repository Install")
	db, err := dbSetup()
	ok(t, err)
	defer db.Close()

	repo := NewUserRepository(db)
	err = repo.Install()
	ok(t, err)

	var data null.String
	row := db.QueryRowContext(dbCtx, "SELECT sql FROM sqlite_master WHERE name='users'")
	err = row.Scan(&data)
	ok(t, err)

	schemaPattern := `CREATE TABLE users`

	matched, err := regexp.MatchString(schemaPattern, data.String)
	ok(t, err)
	assert(t, matched, "invalid table schema", nil)
}

func TestLoginGetHandler(t *testing.T) {
	db, err := dbSetup()
	ok(t, err)
	defer db.Close()

	router := mux.NewRouter()

	sessionStore := sessions.NewCookieStore([]byte("eifepfljjtkvutqycoaqkeckmvpugfqh"))

	repo := NewUserRepository(db)
	err = repo.Install()
	ok(t, err)

	_ = NewAuthController(
		db,
		lumber.NewConsoleLogger(lumber.INFO),
		router,
		sessionStore,
		"",
	)

	req, err := http.NewRequest("GET", "/login", nil)
	ok(t, err)

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	router.GetRoute("login").GetHandler().ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		equals(t, http.StatusOK, status)
	}
}

func TestLoginPostHandler(t *testing.T) {
	db, err := dbSetup()
	ok(t, err)
	defer db.Close()

	router := mux.NewRouter()

	router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		testResponse := `{"success": true}`
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(testResponse)))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(testResponse))
	}).Name("test")

	sessionStore := sessions.NewCookieStore([]byte("eifepfljjtkvutqycoaqkeckmvpugfqh"))

	repo := NewUserRepository(db)
	err = repo.Install()
	ok(t, err)

	testUser := User{
		Username: null.StringFrom("test"),
		Password: null.StringFrom("test"),
	}

	_, err = repo.Create(dbCtx, &testUser)
	ok(t, err)

	_ = NewAuthController(
		db,
		lumber.NewConsoleLogger(lumber.INFO),
		router,
		sessionStore,
		"test",
	)

	formData := "username=test&password=test"

	req, err := http.NewRequest("POST", "/login", bytes.NewReader([]byte(formData)))
	ok(t, err)

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := router.GetRoute("login")

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.GetHandler().ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		equals(t, http.StatusSeeOther, status)
	}

	redirectLocation := rr.Result().Header.Get("Location")
	equals(t, "/test", redirectLocation)
}

func TestFailedLoginPostHandler(t *testing.T) {
	db, err := dbSetup()
	ok(t, err)
	defer db.Close()

	router := mux.NewRouter()

	router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		testResponse := `{"success": true}`
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(testResponse)))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(testResponse))
	}).Name("test")

	sessionStore := sessions.NewCookieStore([]byte("eifepfljjtkvutqycoaqkeckmvpugfqh"))

	repo := NewUserRepository(db)
	err = repo.Install()
	ok(t, err)

	testUser := User{
		Username: null.StringFrom("test"),
		Password: null.StringFrom("test"),
	}

	_, err = repo.Create(dbCtx, &testUser)
	ok(t, err)

	_ = NewAuthController(
		db,
		lumber.NewConsoleLogger(lumber.INFO),
		router,
		sessionStore,
		"test",
	)

	formData := "username=test&password=wrongtest"

	req, err := http.NewRequest("POST", "/login", bytes.NewReader([]byte(formData)))
	ok(t, err)

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := router.GetRoute("login")

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.GetHandler().ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		equals(t, http.StatusBadRequest, status)
	}

	data, err := ioutil.ReadAll(rr.Result().Body)
	ok(t, err)

	matched, err := regexp.Match("Invalid Username or Password", data)
	ok(t, err)
	assert(t, matched, "wrong html page data")
}
