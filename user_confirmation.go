package auth

import (
	"database/sql"
	"fmt"
	"github.com/jmoiron/sqlx"
	"github.com/stockholmr/database"
	"time"
)

type UserConfirmation struct {
	ID       *sql.NullInt64  `db:"id"`
	UserID   *sql.NullInt64  `db:"user_id"`
	Email    *sql.NullString `db:"email"`
	Selector *sql.NullString `db:"selector"`
	Token    *sql.NullString `db:"token"`
	Expires  *sql.NullInt64  `db:"expires"`
	_token   string
}

func NewUserConfirmation(userID int64, email string, expires int64) *UserConfirmation {
	selector, token, hash := createTokenAuthenticator()
	return &UserConfirmation{
		UserID:   newNullInt64(userID),
		Email:    newNullString(email),
		Selector: newNullString(selector),
		Token:    newNullString(hash),
		Expires:  newNullInt64(expires),
		_token:   token,
	}
}

func (c *UserConfirmation) GetToken() string {
	return c._token
}
func (c *UserConfirmation) GetSelector() string {
	return c.Selector.String
}
func (c *UserConfirmation) HasExpired() bool {
	return time.Now().Unix() >= c.Expires.Int64
}

func dbCreateUserConfirmation(db *sqlx.DB, r *UserConfirmation) (int64, error) {
	id, err := database.Insert(
		db,
		getTable("users_confirmations"),
		database.NewFieldValuePairCollection(
			database.NewFieldValuePair("email", r.Email),
			database.NewFieldValuePair("user_id", r.UserID),
			database.NewFieldValuePair("selector", r.Selector),
			database.NewFieldValuePair("token", r.Token),
			database.NewFieldValuePair("expires", r.Expires),
		),
	)
	if err != nil {
		return -999, err
	}

	return id.Int64, nil
}
func dbDeleteUserConfirmation(db *sqlx.DB, selector string) error {
	err := database.Delete(
		db,
		getTable("users_confirmations"),
		database.NewFieldValuePair("selector", selector),
	)
	return err
}
func dbDeleteUserConfirmationAllByUserID(db *sqlx.DB, userID int64) error {
	err := database.Delete(
		db,
		getTable("users_confirmations"),
		database.NewFieldValuePair("user_id", userID),
	)
	return err
}
func dbGetUserConfirmationBySelector(db *sqlx.DB, selector string) (*UserConfirmation, error) {
	cmd := fmt.Sprintf("SELECT * FROM `%s` WHERE selector=?", getTable("users_confirmations"))

	stmt, err := db.Preparex(cmd)
	if err != nil {
		return nil, err
	}

	result := stmt.QueryRowx(selector)

	str := new(UserConfirmation)
	err = result.StructScan(str)

	if err != nil {
		return nil, err
	}

	err = stmt.Close()
	if err != nil {
		return nil, err
	}

	return str, nil
}
func dbGetUserConfirmationByUserID(db *sqlx.DB, userID int64) ([]*UserConfirmation, error) {
	cmd := fmt.Sprintf("SELECT * FROM `%s` WHERE user_id=?", getTable("users_confirmations"))

	stmt, err := db.Preparex(cmd)
	if err != nil {
		return nil, err
	}

	rows, err := stmt.Queryx(userID)
	if err != nil {
		return nil, err
	}

	strArr := make([]*UserConfirmation, 0)
	for rows.Next() {
		str := new(UserConfirmation)
		err = rows.StructScan(str)
		if err != nil {
			return nil, err
		}
		strArr = append(strArr, str)
	}

	err = rows.Close()
	if err != nil {
		return nil, err
	}

	err = stmt.Close()
	if err != nil {
		return nil, err
	}

	return strArr, nil
}
