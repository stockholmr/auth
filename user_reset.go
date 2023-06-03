package auth

import (
	"database/sql"
	"fmt"
	"github.com/jmoiron/sqlx"
	"github.com/stockholmr/database"
	"time"
)

type UserReset struct {
	ID       *sql.NullInt64  `db:"id"`
	UserID   *sql.NullInt64  `db:"user_id"`
	Selector *sql.NullString `db:"selector"`
	Token    *sql.NullString `db:"token"`
	Expires  *sql.NullInt64  `db:"expires"`

	_token string
}

func NewUserReset(userID int64, expires int64) *UserReset {
	selector, token, hash := createTokenAuthenticator()
	return &UserReset{
		UserID:   newNullInt64(userID),
		Selector: newNullString(selector),
		Token:    newNullString(hash),
		Expires:  newNullInt64(expires),
		_token:   token,
	}
}

func (r *UserReset) GetToken() string {
	return r._token
}
func (r *UserReset) GetSelector() string {
	return r.Selector.String
}
func (r *UserReset) HasExpired() bool {
	return time.Now().Unix() > r.Expires.Int64
}

func dbCreateUserReset(db *sqlx.DB, r *UserReset) (int64, error) {
	id, err := database.Insert(
		db,
		getTable("users_resets"),
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
func dbDeleteUserReset(db *sqlx.DB, selector string) error {
	err := database.Delete(
		db,
		getTable("users_resets"),
		database.NewFieldValuePair("selector", selector),
	)
	return err
}
func dbDeleteUserResetByUserID(db *sqlx.DB, userID int64) error {
	err := database.Delete(
		db,
		getTable("users_resets"),
		database.NewFieldValuePair("user_id", userID),
	)
	return err
}
func dbGetUserResetCount(db *sqlx.DB, userID int64) (int64, error) {
	cmd := fmt.Sprintf("SELECT COUNT(*) as COUNT FROM `%s` WHERE user_id=?", getTable("users_resets"))

	stmt, err := db.Preparex(cmd)
	if err != nil {
		return -999, err
	}
	result := stmt.QueryRowx(userID)
	str := make(map[string]interface{}, 0)
	err = result.MapScan(str)

	if err != nil {
		return -999, err
	}

	err = stmt.Close()
	if err != nil {
		return -999, err
	}

	count := str["COUNT"].(int64)

	return count, nil
}
func dbGetUserResetBySelector(db *sqlx.DB, selector string) (*UserReset, error) {
	cmd := fmt.Sprintf("SELECT * FROM `%s` WHERE selector=?", getTable("users_resets"))

	stmt, err := db.Preparex(cmd)
	if err != nil {
		return nil, err
	}

	result := stmt.QueryRowx(selector)

	str := new(UserReset)
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
func dbGetUserResetByUserID(db *sqlx.DB, userID int64) ([]*UserReset, error) {
	cmd := fmt.Sprintf("SELECT * FROM `%s` WHERE user_id=?", getTable("users_resets"))

	stmt, err := db.Preparex(cmd)
	if err != nil {
		return nil, err
	}

	rows, err := stmt.Queryx(userID)
	if err != nil {
		return nil, err
	}

	strArr := make([]*UserReset, 0)
	for rows.Next() {
		str := new(UserReset)
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
