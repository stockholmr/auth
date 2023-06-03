package auth

import (
	"database/sql"
	"fmt"
	"github.com/jmoiron/sqlx"
	"server/internal/database"
)

type User struct {
	ID          *sql.NullInt64  `db:"id"`
	Email       *sql.NullString `db:"email"`
	Password    *sql.NullString `db:"password"`
	Status      *sql.NullInt64  `db:"status"`
	Verified    *sql.NullInt64  `db:"verified"`
	Resettable  *sql.NullInt64  `db:"resettable"`
	Roles       *sql.NullInt64  `db:"roles_mask"`
	Registered  *sql.NullInt64  `db:"registered"`
	LastLogin   *sql.NullInt64  `db:"last_login"`
	ForceLogout *sql.NullInt64  `db:"force_logout"`
}

func NewUser(email string, password string, registered int64) *User {
	return &User{
		Email:      newNullString(email),
		Password:   newNullString(password),
		Registered: newNullInt64(registered),
	}
}

func (u *User) ShallowClone() *User {
	c := *u
	return &c
}

func (u *User) IsVerified() bool {
	return u.Verified.Valid && u.Verified.Int64 == 1
}
func (u *User) IsResettable() bool {
	return u.Resettable.Valid && u.Resettable.Int64 == 1
}
func (u *User) IsRegistered() bool {
	return u.Registered.Valid && u.Registered.Int64 == 1
}

func (u *User) GetID() int64 {
	return u.ID.Int64
}

func (u *User) SetEmail(v string) {
	u.Email = &sql.NullString{String: v, Valid: true}
}
func (u *User) SetPassword(v string) {
	u.Password = &sql.NullString{String: v, Valid: true}
}
func (u *User) SetStatus(v int64) {
	u.Status = &sql.NullInt64{Int64: v, Valid: true}
}
func (u *User) SetRoles(v int64) {
	u.Roles = &sql.NullInt64{Int64: v, Valid: true}
}
func (u *User) SetLastLogin(v int64) {
	u.LastLogin = &sql.NullInt64{Int64: v, Valid: true}
}
func (u *User) SetRegistered(v int64) {
	u.Registered = &sql.NullInt64{Int64: v, Valid: true}
}
func (u *User) SetVerified(v bool) {
	if v {
		u.Verified = &sql.NullInt64{Int64: 1, Valid: true}
		return
	}
	u.Verified = &sql.NullInt64{Int64: 0, Valid: true}
}
func (u *User) SetResettable(v bool) {
	if v {
		u.Resettable = &sql.NullInt64{Int64: 1, Valid: true}
		return
	}
	u.Resettable = &sql.NullInt64{Int64: 0, Valid: true}
}
func (u *User) SetForceLogout(v bool) {
	if v {
		u.ForceLogout = &sql.NullInt64{Int64: 1, Valid: true}
		return
	}
	u.ForceLogout = &sql.NullInt64{Int64: 0, Valid: true}
}

func dbCreateUser(db *sqlx.DB, user *User) (int64, error) {
	id, err := database.Insert(
		db,
		getTable("users"),
		database.NewFieldValuePairCollection(
			database.NewFieldValuePair("email", user.Email),
			database.NewFieldValuePair("password", user.Password),
			database.NewFieldValuePair("registered", user.Registered),
		),
	)
	if err != nil {
		return -999, err
	}
	return id.Int64, err
}
func dbDeleteUser(db *sqlx.DB, user *User) error {
	err := database.Update(
		db,
		getTable("users"),
		database.NewFieldValuePairCollection(
			database.NewFieldValuePair("status", STATUS_ARCHIVED),
			database.NewFieldValuePair("resettable", 1),
		),
		database.NewFieldValuePair("id", user.ID),
	)
	return err
}
func dbHardDeleteUser(db *sqlx.DB, user *User) error {
	err := database.Delete(
		db,
		getTable("users"),
		database.NewFieldValuePair("id", user.ID),
	)
	return err
}
func dbGetUserByEmail(db *sqlx.DB, email string) (*User, error) {
	cmd := fmt.Sprintf("SELECT * FROM `%s` WHERE email=? AND status=?", getTable("users"))

	stmt, err := db.Preparex(cmd)
	if err != nil {
		return nil, err
	}

	result := stmt.QueryRowx(email, STATUS_NORMAL)

	str := new(User)
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
func dbGetUserByID(db *sqlx.DB, id int64) (*User, error) {
	cmd := fmt.Sprintf("SELECT * FROM `%s` WHERE id=? AND status=?", getTable("users"))

	stmt, err := db.Preparex(cmd)
	if err != nil {
		return nil, err
	}

	result := stmt.QueryRowx(id, STATUS_NORMAL)

	str := new(User)
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
func dbUpdateUser(db *sqlx.DB, userID int64, fields []*database.FieldValuePair) error {
	err := database.Update(
		db,
		getTable("users"),
		fields,
		database.NewFieldValuePair("id", userID),
	)
	return err
}

func dbUpdateUserEmail(db *sqlx.DB, user *User) error {
	err := database.Update(
		db,
		getTable("users"),
		database.NewFieldValuePairCollection(
			database.NewFieldValuePair("email", user.Email),
		),
		database.NewFieldValuePair("id", user.ID),
	)
	return err
}
func dbUpdateUserPassword(db *sqlx.DB, user *User) error {
	err := database.Update(
		db,
		getTable("users"),
		database.NewFieldValuePairCollection(
			database.NewFieldValuePair("password", user.Password),
		),
		database.NewFieldValuePair("id", user.ID),
	)
	return err
}
func dbUpdateUserStatus(db *sqlx.DB, user *User) error {
	err := database.Update(
		db,
		getTable("users"),
		database.NewFieldValuePairCollection(
			database.NewFieldValuePair("last_login", user.Status),
		),
		database.NewFieldValuePair("id", user.ID),
	)
	return err
}
func dbUpdateUserVerified(db *sqlx.DB, user *User) error {
	err := database.Update(
		db,
		getTable("users"),
		database.NewFieldValuePairCollection(
			database.NewFieldValuePair("verified", user.Verified),
		),
		database.NewFieldValuePair("id", user.ID),
	)
	return err
}
func dbUpdateUserResettable(db *sqlx.DB, user *User) error {
	err := database.Update(
		db,
		getTable("users"),
		database.NewFieldValuePairCollection(
			database.NewFieldValuePair("resettable", user.Resettable),
		),
		database.NewFieldValuePair("id", user.ID),
	)
	return err
}
func dbUpdateUserRoles(db *sqlx.DB, user *User) error {
	err := database.Update(
		db,
		getTable("users"),
		database.NewFieldValuePairCollection(
			database.NewFieldValuePair("roles", user.Roles),
		),
		database.NewFieldValuePair("id", user.ID),
	)
	return err
}
func dbUpdateUserRegistered(db *sqlx.DB, user *User) error {
	err := database.Update(
		db,
		getTable("users"),
		database.NewFieldValuePairCollection(
			database.NewFieldValuePair("registered", user.Registered),
		),
		database.NewFieldValuePair("id", user.ID),
	)
	return err
}
func dbUpdateUserLastLogin(db *sqlx.DB, user *User) error {
	err := database.Update(
		db,
		getTable("users"),
		database.NewFieldValuePairCollection(
			database.NewFieldValuePair("last_login", user.LastLogin),
		),
		database.NewFieldValuePair("id", user.ID),
	)
	return err
}
func dbUpdateUserForceLogout(db *sqlx.DB, user *User) error {
	err := database.Update(
		db,
		getTable("users"),
		database.NewFieldValuePairCollection(
			database.NewFieldValuePair("force_logout", user.ForceLogout),
		),
		database.NewFieldValuePair("id", user.ID),
	)
	return err
}
