package auth

import (
	"context"
	"database/sql"
	"time"

	"github.com/jmoiron/sqlx"
	migrate "github.com/rubenv/sql-migrate"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/guregu/null.v3"
)

type User struct {
	ID       null.Int    `db:"id" json:"id"`
	Created  null.String `db:"created" json:"created"`
	Updated  null.String `db:"updated" json:"updated"`
	Deleted  null.String `db:"deleted" json:"deleted"`
	Username null.String `db:"username" json:"username"`
	Password null.String `db:"password" json:"password"`
}

type UserRepository interface {
	Install() error
	Select(context.Context, int) (*User, error)
	SelectWithUsername(context.Context, string) (*User, error)
	Create(context.Context, *User) (int64, error)
	Update(context.Context, *User) error
	Delete(context.Context, int) error
	List(context.Context, int, int) ([]User, error)
}

type userRepository struct {
	db *sqlx.DB
}

func NewUserRepository(db *sqlx.DB) UserRepository {
	return &userRepository{
		db: db,
	}
}

func (r *userRepository) Install() error {
	migrations := &migrate.MemoryMigrationSource{
		Migrations: []*migrate.Migration{
			{
				Id: "users",
				Up: []string{
					`CREATE TABLE users (
						id INTEGER PRIMARY KEY AUTOINCREMENT,
						created TEXT,
						updated TEXT,
						deleted TEXT,
						username TEXT,
						password TEXT
					)`,
				},
				Down: []string{"DROP TABLE users"},
			},
		},
	}

	_, err := migrate.Exec(r.db.DB, "sqlite3", migrations, migrate.Up)

	if err != nil {
		return &ErrorEx{
			ErrorMsg: err,
			Func:     "auth.userRepository.Install --> migrate.Exec",
		}
	}

	return nil
}

func (r *userRepository) Select(ctx context.Context, id int) (*User, error) {
	data := User{}

	stmt, err := r.db.PreparexContext(
		ctx,
		`SELECT *
        FROM users
        WHERE id=?`,
	)

	if err != nil {
		return nil, &ErrorEx{
			ErrorMsg: err,
			Func:     "auth.userRepository.Select() --> DB.PreparexContext",
		}
	}

	err = stmt.GetContext(
		ctx,
		&data,
		id,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, &ErrorEx{
			ErrorMsg: err,
			Func:     "auth.userRepository.Select() --> DB.GetContext",
		}
	}

	return &data, nil
}

func (r *userRepository) SelectWithUsername(ctx context.Context, username string) (*User, error) {
	data := User{}

	stmt, err := r.db.PreparexContext(
		ctx,
		`SELECT *
        FROM users
        WHERE username=?`,
	)

	if err != nil {
		return nil, &ErrorEx{
			ErrorMsg: err,
			Func:     "auth.userRepository.SelectWithUsername() --> DB.PreparexContext",
		}
	}

	err = stmt.GetContext(
		ctx,
		&data,
		username,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, &ErrorEx{
			ErrorMsg: err,
			Func:     "auth.userRepository.SelectWithUsername() --> DB.GetContext",
		}
	}

	return &data, nil
}

func (r *userRepository) Create(ctx context.Context, data *User) (int64, error) {
	tx, err := r.db.BeginTxx(ctx, nil)

	if err != nil {
		return -1, &ErrorEx{
			ErrorMsg: err,
			Func:     "auth.userRepository.Create() --> DB.BeginTxx",
		}
	}

	stmt, err := tx.PreparexContext(
		ctx,
		`INSERT INTO users (
            created,
            username,
            password
        ) VALUES (?,?,?)`,
	)

	if err != nil {
		return -1, &ErrorEx{
			ErrorMsg: err,
			Func:     "auth.userRepository.Create() --> DB.PreparexContext",
		}
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(data.Password.String), 4)
	data.Password.String = string(hashedPassword)

	result, err := stmt.ExecContext(
		ctx,
		time.Now().Format("2006-01-02 15:04:05"),
		data.Username,
		string(hashedPassword),
	)

	if err != nil {
		tx.Rollback()
		return -1, &ErrorEx{
			ErrorMsg: err,
			Func:     "auth.userRepository.Create() --> DB.ExecContext",
		}
	}

	tx.Commit()
	id, _ := result.LastInsertId()
	return id, nil
}

func (r *userRepository) Update(ctx context.Context, data *User) error {
	tx, err := r.db.BeginTxx(ctx, nil)

	if err != nil {
		return &ErrorEx{
			ErrorMsg: err,
			Func:     "auth.userRepository.Update() --> DB.BeginTxx",
		}
	}

	stmt, err := tx.PreparexContext(
		ctx,
		`UPDATE users SET
            updated=?
        WHERE id=?`,
	)

	if err != nil {
		return &ErrorEx{
			ErrorMsg: err,
			Func:     "auth.userRepository.Update() --> DB.PreparexContext",
		}
	}

	_, err = stmt.ExecContext(
		ctx,
		time.Now().Format("2006-01-02 15:04:05"),
	)

	if err != nil {
		tx.Rollback()
		return &ErrorEx{
			ErrorMsg: err,
			Func:     "auth.userRepository.Update() --> DB.ExecContext",
		}
	}

	tx.Commit()
	return nil
}

func (r *userRepository) UpdatePassword(ctx context.Context, data *User) error {
	tx, err := r.db.BeginTxx(ctx, nil)

	if err != nil {
		return &ErrorEx{
			ErrorMsg: err,
			Func:     "auth.userRepository.UpdatePassword() --> DB.BeginTxx",
		}
	}

	stmt, err := tx.PreparexContext(
		ctx,
		`UPDATE users SET
            updated=?,
            password=?
        WHERE id=?`,
	)

	if err != nil {
		return &ErrorEx{
			ErrorMsg: err,
			Func:     "auth.userRepository.UpdatePassword() --> DB.PreparexContext",
		}
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(data.Password.String), 4)
	data.Password.String = string(hashedPassword)

	_, err = stmt.ExecContext(
		ctx,
		time.Now().Format("2006-01-02 15:04:05"),
		string(hashedPassword),
		data.ID,
	)

	if err != nil {
		tx.Rollback()
		return &ErrorEx{
			ErrorMsg: err,
			Func:     "auth.userRepository.UpdatePassword() --> DB.ExecContext",
		}
	}

	tx.Commit()
	return nil
}

func (r *userRepository) Delete(ctx context.Context, id int) error {
	tx, err := r.db.BeginTxx(ctx, nil)

	if err != nil {
		return &ErrorEx{
			ErrorMsg: err,
			Func:     "auth.userRepository.Delete() --> DB.BeginTxx",
		}
	}

	stmt, err := tx.PreparexContext(
		ctx,
		`UPDATE users SET
            deleted=?
        WHERE id=?`,
	)

	if err != nil {
		return &ErrorEx{
			ErrorMsg: err,
			Func:     "auth.userRepository.Delete() --> DB.PreparexContext",
		}
	}

	_, err = stmt.ExecContext(
		ctx,
		time.Now().Format("2006-01-02 15:04:05"),
		id,
	)

	if err != nil {
		tx.Rollback()
		return &ErrorEx{
			ErrorMsg: err,
			Func:     "auth.userRepository.Delete() --> DB.ExecContext",
		}
	}

	tx.Commit()
	return nil
}

func (r *userRepository) List(ctx context.Context, start int, count int) ([]User, error) {
	data := []User{}

	stmt, err := r.db.PreparexContext(
		ctx,
		`SELECT
            id,
            created,
            updated,
            deleted
        FROM users
        LIMIT ? OFFSET ?`,
	)

	if err != nil {
		return nil, &ErrorEx{
			ErrorMsg: err,
			Func:     "auth.userRepository.List() --> DB.PreparexContext",
		}
	}

	err = stmt.SelectContext(
		ctx,
		&data,
		start,
		count,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, &ErrorEx{
			ErrorMsg: err,
			Func:     "auth.userRepository.List() --> DB.SelectContext",
		}
	}

	return data, nil
}
