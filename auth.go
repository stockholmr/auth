package auth

import (
	"errors"
	"github.com/jmoiron/sqlx"
	"github.com/stockholmr/database"
	"time"
)

func Register(db *sqlx.DB, email string, password string) error {
	if err := checkDatabase(db); err != nil {
		return err
	}

	if !validateEmail(email) {
		return errors.New(ERROR_INVALIDEMAIL)
	}

	user := NewUser(email, hashPassword(password), time.Now().Unix())

	id, err := dbCreateUser(db, user)
	if err != nil {
		return err
	}

	err = dbUpdateUser(
		db,
		id,
		database.NewFieldValuePairCollection(
			database.NewFieldValuePair("verified", 1),
		),
	)
	if err != nil {
		return err
	}

	return nil
}
func RegisterWithConfirmation(db *sqlx.DB, email string, password string, confirmEmail SelectorTokenCallBack) error {
	if err := checkDatabase(db); err != nil {
		return err
	}

	if !validateEmail(email) {
		return errors.New(ERROR_INVALIDEMAIL)
	}

	user := NewUser(email, hashPassword(password), time.Now().Unix())

	id, err := dbCreateUser(db, user)
	if err != nil {
		return err
	}

	confirm := NewUserConfirmation(id, email, getUserConfirmationExpiry())

	_, err = dbCreateUserConfirmation(db, confirm)
	if err != nil {
		return err
	}

	err = confirmEmail(confirm.GetSelector(), confirm.GetToken())
	if err != nil {
		return err
	}

	return nil
}
func ConfirmEmail(db *sqlx.DB, selector string, token string) error {
	if err := checkDatabase(db); err != nil {
		return err
	}

	confirm, err := dbGetUserConfirmationBySelector(db, selector)
	if err != nil {
		return err
	}

	if !verifyHash(confirm.Token.String, token) {
		return errors.New(ERROR_INVALIDTOKEN)
	}

	if confirm.HasExpired() {
		return errors.New(ERROR_TOKENEXPIRED)
	}

	user, err := dbGetUserByID(db, confirm.UserID.Int64)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return errors.New(ERROR_INVALIDUSERID)
		}
		return err
	}

	err = dbUpdateUser(
		db,
		user.GetID(),
		database.NewFieldValuePairCollection(
			database.NewFieldValuePair("email", confirm.Email.String),
			database.NewFieldValuePair("verified", 1),
		),
	)
	if err != nil {
		return err
	}

	err = dbDeleteUserConfirmation(db, selector)
	if err != nil {
		return err
	}

	return nil
}
func Login(db *sqlx.DB, email string, password string) (int64, error) {
	if err := checkDatabase(db); err != nil {
		return -999, err
	}

	if !validateEmail(email) {
		return -999, errors.New(ERROR_INVALIDEMAIL)
	}

	user, err := dbGetUserByEmail(db, email)
	if err != nil {
		return -999, err
	}

	if !user.IsVerified() {
		return -999, errors.New(ERROR_EMAILNOTVERIFIED)
	}

	if user.Status.Int64 != STATUS_NORMAL {
		return -999, errors.New(ERROR_USERBLOCKED)
	}

	if !verifyHash(user.Password.String, password) {
		return -999, errors.New(ERROR_INVALIDPASSWORD)
	}

	err = dbUpdateUser(
		db,
		user.GetID(),
		database.NewFieldValuePairCollection(
			database.NewFieldValuePair("last_login", time.Now().Unix()),
		),
	)
	if err != nil {
		return -999, err
	}

	return user.GetID(), nil
}
func Remember(db *sqlx.DB, userID int64, expires int64, setCookie SelectorTokenCallBack) error {
	if err := checkDatabase(db); err != nil {
		return err
	}

	remember := NewUserRemember(userID, expires)

	_, err := dbCreateUserRemember(db, remember)
	if err != nil {
		return err
	}

	err = setCookie(remember.GetSelector(), remember.GetToken())
	if err != nil {
		return err
	}

	return nil
}
func DeleteRemember(db *sqlx.DB, selector string) error {
	if err := checkDatabase(db); err != nil {
		return err
	}

	err := dbDeleteUserRemember(db, selector)
	if err != nil {
		return err
	}
	return nil
}
func ConfirmRemember(db *sqlx.DB, selector string, token string) error {
	if err := checkDatabase(db); err != nil {
		return err
	}

	remember, err := dbGetUserRememberBySelector(db, selector)
	if err != nil {
		return err
	}

	if !verifyHash(remember.Token.String, token) {

		err = dbDeleteUserRemember(db, selector)
		if err != nil {
			return err
		}

		return errors.New(ERROR_INVALIDTOKEN)
	}

	if remember.HasExpired() {

		err = dbDeleteUserRemember(db, selector)
		if err != nil {
			return err
		}

		return errors.New(ERROR_TOKENEXPIRED)
	}

	return nil
}
func ResetPasswordWithConfirmation(db *sqlx.DB, email string, confirmEmail SelectorTokenCallBack) error {
	if err := checkDatabase(db); err != nil {
		return err
	}

	if !validateEmail(email) {
		return errors.New(ERROR_INVALIDEMAIL)
	}

	user, err := dbGetUserByEmail(db, email)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return errors.New(ERROR_INVALIDEMAIL)
		}
		return err
	}

	if !user.IsVerified() {
		return errors.New(ERROR_EMAILNOTVERIFIED)
	}

	if !user.IsResettable() {
		return errors.New(ERROR_RESETDISABLED)
	}

	resetCount, err := dbGetUserResetCount(db, user.GetID())
	if err != nil {
		return err
	}

	if resetCount >= getMaxUserResetRequests() {
		return errors.New(ERROR_TOOMANYREQUESTS)
	}

	reset := NewUserReset(user.GetID(), getUserResetExpiry())

	_, err = dbCreateUserReset(db, reset)
	if err != nil {
		return err
	}

	err = confirmEmail(reset.GetSelector(), reset.GetToken())
	if err != nil {
		return err
	}

	return nil
}
func ConfirmReset(db *sqlx.DB, selector string, token string) (int64, error) {
	if err := checkDatabase(db); err != nil {
		return -999, err
	}

	reset, err := dbGetUserResetBySelector(db, selector)
	if err != nil {
		return -999, err
	}

	if !verifyHash(reset.Token.String, token) {
		return -999, errors.New(ERROR_INVALIDTOKEN)
	}

	if reset.HasExpired() {
		return -999, errors.New(ERROR_TOKENEXPIRED)
	}

	return reset.UserID.Int64, nil
}
func DeleteReset(db *sqlx.DB, selector string) error {
	if err := checkDatabase(db); err != nil {
		return err
	}

	err := dbDeleteUserReset(db, selector)
	if err != nil {
		return err
	}
	return nil
}
func ResetPassword(db *sqlx.DB, email string, password string) error {
	if err := checkDatabase(db); err != nil {
		return err
	}

	user, err := dbGetUserByEmail(db, email)
	if err != nil {
		return err
	}

	if !user.IsVerified() {
		return errors.New(ERROR_EMAILNOTVERIFIED)
	}

	if !user.IsResettable() {
		return errors.New(ERROR_RESETDISABLED)
	}

	if !user.Status.Valid && user.Status.Int64 != STATUS_NORMAL {
		return errors.New(ERROR_USERBLOCKED)
	}

	err = dbUpdateUser(
		db,
		user.GetID(),
		database.NewFieldValuePairCollection(
			database.NewFieldValuePair("password", hashPassword(password)),
		),
	)
	if err != nil {
		return err
	}

	return nil
}
func ResetPasswordWithID(db *sqlx.DB, userID int64, password string) error {
	if err := checkDatabase(db); err != nil {
		return err
	}

	user, err := dbGetUserByID(db, userID)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return errors.New(ERROR_INVALIDUSERID)
		}
		return err
	}

	if !user.IsVerified() {
		return errors.New(ERROR_EMAILNOTVERIFIED)
	}

	if !user.IsResettable() {
		return errors.New(ERROR_RESETDISABLED)
	}

	if !user.Status.Valid && user.Status.Int64 != STATUS_NORMAL {
		return errors.New(ERROR_USERBLOCKED)
	}

	err = dbUpdateUser(
		db,
		user.GetID(),
		database.NewFieldValuePairCollection(
			database.NewFieldValuePair("password", hashPassword(password)),
		),
	)
	if err != nil {
		return err
	}

	return nil
}
func ReconfirmPassword(db *sqlx.DB, email string, password string) error {
	if err := checkDatabase(db); err != nil {
		return err
	}

	user, err := dbGetUserByEmail(db, email)
	if err != nil {
		return err
	}

	if !verifyHash(user.Password.String, password) {
		return errors.New(ERROR_INVALIDPASSWORD)
	}

	return nil
}
