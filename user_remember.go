package auth

import (
	"database/sql"
	"fmt"
	"github.com/jmoiron/sqlx"
	"server/internal/database"
	"time"
)

type UserRemember struct {
	ID       *sql.NullInt64  `db:"id"`
	UserID   *sql.NullInt64  `db:"user_id"`
	Selector *sql.NullString `db:"selector"`
	Token    *sql.NullString `db:"token"`
	Expires  *sql.NullInt64  `db:"expires"`

	_token string
}

func NewUserRemember(userID int64, expires int64) *UserRemember {
	selector, token, hash := createTokenAuthenticator()
	return &UserRemember{
		UserID:   newNullInt64(userID),
		Selector: newNullString(selector),
		Token:    newNullString(hash),
		Expires:  newNullInt64(expires),
		_token:   token,
	}
}

func (r *UserRemember) GetToken() string {
	return r._token
}
func (r *UserRemember) GetSelector() string {
	return r.Selector.String
}
func (r *UserRemember) HasExpired() bool {
	return time.Now().Unix() > r.Expires.Int64
}

func dbCreateUserRemember(db *sqlx.DB, r *UserRemember) (int64, error) {
	id, err := database.Insert(
		db,
		getTable("users_remembered"),
		database.NewFieldValuePairCollection(
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
func dbDeleteUserRemember(db *sqlx.DB, selector string) error {
	err := database.Delete(
		db,
		getTable("users_remembered"),
		database.NewFieldValuePair("selector", selector),
	)
	return err
}
func dbDeleteAllUserRememberedByUserID(db *sqlx.DB, userID int64) error {
	err := database.Delete(
		db,
		getTable("users_remembered"),
		database.NewFieldValuePair("user_id", userID),
	)
	return err
}
func dbGetUserRememberBySelector(db *sqlx.DB, selector string) (*UserRemember, error) {
	cmd := fmt.Sprintf("SELECT * FROM `%s` WHERE selector=?", getTable("users_remembered"))

	stmt, err := db.Preparex(cmd)
	if err != nil {
		return nil, err
	}

	result := stmt.QueryRowx(selector)

	str := new(UserRemember)
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
func dbGetUserRememberByUserID(db *sqlx.DB, userID int64) ([]*UserRemember, error) {
	cmd := fmt.Sprintf("SELECT * FROM `%s` WHERE user_id=?", getTable("users_remembered"))

	stmt, err := db.Preparex(cmd)
	if err != nil {
		return nil, err
	}

	rows, err := stmt.Queryx(userID)
	if err != nil {
		return nil, err
	}

	strArr := make([]*UserRemember, 0)
	for rows.Next() {
		str := new(UserRemember)
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
