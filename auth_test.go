package auth

import (
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"testing"
)

var db *sqlx.DB

func setup() error {
	db = sqlx.MustConnect("sqlite3", ":memory:")

	err := SetupDatabase(db)
	if err != nil {
		return err
	}

	return nil
}

func TestRegister(t *testing.T) {
	err := setup()
	if err != nil {
		t.Error(err)
	}

	err = Register(db, "j.doe@hotmail.com", "password123")
	if err != nil {
		t.Error(err)
	}

	user, err := dbGetUserByEmail(db, "j.doe@hotmail.com")
	if err != nil {
		t.Error(err)
	}

	if !verifyHash(user.Password.String, "password123") {
		t.FailNow()
	}

	_ = db.Close()
}
func TestRegisterInvalidEmail(t *testing.T) {
	err := setup()
	if err != nil {
		t.Error(err)
	}

	err = Register(db, "j.doehotmail.com", "password123")
	if err != nil {
		if err.Error() != ERROR_INVALIDEMAIL {
			t.Error(err)
		}
	}

	_ = db.Close()
}
func TestRegisterDuplicateEmail(t *testing.T) {
	err := setup()
	if err != nil {
		t.Error(err)
	}

	err = Register(db, "j.doe@hotmail.com", "password123")
	if err != nil {
		t.Error(err)
	}

	err = Register(db, "j.doe@hotmail.com", "password123")
	if err == nil {
		t.FailNow()
	}

	_ = db.Close()
}
func TestRegisterWithConfirmation(t *testing.T) {
	err := setup()
	if err != nil {
		t.Error(err)
	}

	err = RegisterWithConfirmation(
		db,
		"j.doe@hotmail.com",
		"password123",
		func(selector string, token string) error {
			err := ConfirmEmail(db, selector, token)
			return err
		},
	)
	if err != nil {
		t.Error(err)
	}

	user, err := dbGetUserByEmail(db, "j.doe@hotmail.com")
	if err != nil {
		t.Error(err)
	}

	confirm, err := dbGetUserConfirmationByUserID(db, user.GetID())
	if err != nil {
		t.Error(err)
	}

	if len(confirm) != 0 {
		t.FailNow()
	}

	if !user.IsVerified() {
		t.FailNow()
	}

	_ = db.Close()
}
func TestLogin(t *testing.T) {
	err := setup()
	if err != nil {
		t.Error(err)
	}

	err = Register(db, "j.doe@hotmail.com", "password123")
	if err != nil {
		t.Error(err)
	}

	user, err := dbGetUserByEmail(db, "j.doe@hotmail.com")
	if err != nil {
		t.Error(err)
	}

	_ = user

	_, err = Login(db, "j.doe@hotmail.com", "password123")
	if err != nil {
		t.Error(err)
	}

	user, err = dbGetUserByEmail(db, "j.doe@hotmail.com")
	if err != nil {
		t.Error(err)
	}

	if !user.LastLogin.Valid {
		t.FailNow()
	}

	_ = db.Close()
}
func TestFailedLogin(t *testing.T) {
	err := setup()
	if err != nil {
		t.Error(err)
	}

	err = Register(db, "j.doe@hotmail.com", "password123")
	if err != nil {
		t.Error(err)
	}

	_, err = Login(db, "j.doe@hotmail.co", "password123655")
	if err == nil {
		t.FailNow()
	}

	_ = db.Close()
}
func TestGetUserByEmail(t *testing.T) {
	err := setup()
	if err != nil {
		t.Error(err)
	}

	err = Register(db, "j.doe@hotmail.com", "password123")
	if err != nil {
		t.Error(err)
	}

	_, err = dbGetUserByEmail(db, "j.doe@hotmail.com")
	if err != nil {
		t.Error(err)
	}
}
func TestGetOpenResets(t *testing.T) {
	err := setup()
	if err != nil {
		t.Error(err)
	}

	for i := 1; i <= 5; i++ {
		reset := NewUserReset(1, getUserResetExpiry())
		_, err := dbCreateUserReset(db, reset)
		if err != nil {
			t.Error(err)
		}
	}

	count, err := dbGetUserResetCount(db, 1)
	if err != nil {
		t.Error(err)
	}
	if count != 5 {
		t.FailNow()
	}
}
func TestForgotPassword(t *testing.T) {
	err := setup()
	if err != nil {
		t.Error(err)
	}

	err = Register(db, "j.doe@hotmail.com", "password123")
	if err != nil {
		t.Error(err)
	}

	err = ResetPasswordWithConfirmation(
		db,
		"j.doe@hotmail.com",
		func(selector string, token string) error {
			_, err = ConfirmReset(db, selector, token)
			return err
		},
	)

}
func TestResetPassword(t *testing.T) {
	err := setup()
	if err != nil {
		t.Error(err)
	}

	err = Register(db, "j.doe@hotmail.com", "password123")
	if err != nil {
		t.Error(err)
	}

	err = ResetPassword(db, "j.doe@hotmail.com", "password12375846747456")
	if err != nil {
		t.Error(err)
	}

	err = ReconfirmPassword(db, "j.doe@hotmail.com", "password12375846747456")
	if err != nil {
		t.Error(err)
	}

	_ = db.Close()
}
func TestReconfirmPassword(t *testing.T) {
	err := setup()
	if err != nil {
		t.Error(err)
	}

	err = Register(db, "j.doe@hotmail.com", "password123")
	if err != nil {
		t.Error(err)
	}

	err = ReconfirmPassword(db, "j.doe@hotmail.com", "password123")
	if err != nil {
		t.Error(err)
	}

	_ = db.Close()
}
