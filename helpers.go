package auth

import (
	"database/sql"
	"errors"
	"github.com/jmoiron/sqlx"
	"golang.org/x/crypto/bcrypt"
	"math/rand"
	"net/mail"
	"regexp"
	"time"
)

func ValidateAlphanumericString(s string) bool {
	matched, err := regexp.Match("^[a-zA-Z0-9]*$", []byte(s))
	if err != nil {
		return false
	}
	return matched
}

func hashPassword(pw string) string {
	hash, _ := bcrypt.GenerateFromPassword([]byte(pw), 4)
	return string(hash)
}
func verifyHash(hash string, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}
func validateEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}
func randomString(length int64) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	random := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[random.Intn(len(charset))]
	}
	return string(b)
}
func SetupDatabase(db *sqlx.DB) error {
	cmd := `
PRAGMA foreign_keys = OFF;
CREATE TABLE "users" (
	"id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL CHECK ("id" >= 0),
	"email" VARCHAR(249) NOT NULL,
	"password" VARCHAR(255) NOT NULL,
	"status" INTEGER NOT NULL CHECK ("status" >= 0) DEFAULT "0",
	"verified" INTEGER NOT NULL CHECK ("verified" >= 0) DEFAULT "0",
	"resettable" INTEGER NOT NULL CHECK ("resettable" >= 0) DEFAULT "1",
	"roles_mask" INTEGER NOT NULL CHECK ("roles_mask" >= 0) DEFAULT "1",
	"registered" INTEGER NOT NULL CHECK ("registered" >= 0),
	"last_login" INTEGER CHECK ("last_login" >= 0) DEFAULT NULL,
	"force_logout" INTEGER NOT NULL CHECK ("force_logout" >= 0) DEFAULT "0",
	CONSTRAINT "email" UNIQUE ("email")
);
CREATE TABLE "users_confirmations" (
	"id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL CHECK ("id" >= 0),
	"user_id" INTEGER NOT NULL CHECK ("user_id" >= 0),
	"email" VARCHAR(249) NOT NULL,
	"selector" VARCHAR(16) NOT NULL,
	"token" VARCHAR(255) NOT NULL,
	"expires" INTEGER NOT NULL CHECK ("expires" >= 0),
	CONSTRAINT "selector" UNIQUE ("selector")
);
CREATE INDEX "users_confirmations.email_expires" ON "users_confirmations" ("email", "expires");
CREATE INDEX "users_confirmations.user_id" ON "users_confirmations" ("user_id");

CREATE TABLE "users_remembered" (
	"id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL CHECK ("id" >= 0),
	"user_id" INTEGER NOT NULL CHECK ("user_id" >= 0),
	"selector" VARCHAR(24) NOT NULL,
	"token" VARCHAR(255) NOT NULL,
	"expires" INTEGER NOT NULL CHECK ("expires" >= 0),
	CONSTRAINT "selector" UNIQUE ("selector")
);
CREATE INDEX "users_remembered.user" ON "users_remembered" ("user");

CREATE TABLE "users_resets" (
	"id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL CHECK ("id" >= 0),
	"user_id" INTEGER NOT NULL CHECK ("user_id" >= 0),
	"selector" VARCHAR(20) NOT NULL,
	"token" VARCHAR(255) NOT NULL,
	"expires" INTEGER NOT NULL CHECK ("expires" >= 0),
	CONSTRAINT "selector" UNIQUE ("selector")
);
CREATE INDEX "users_resets.user_expires" ON "users_resets" ("user", "expires");
`
	_, err := db.Exec(cmd)
	if err != nil {
		return err
	}

	return nil

}
func checkDatabase(db *sqlx.DB) error {
	if db == nil {
		return errors.New(ERROR_NODATABASECONN)
	}
	if err := db.Ping(); err != nil {
		return err
	}

	return nil
}
func createTokenAuthenticator() (string, string, string) {
	selector := randomString(16)
	token := randomString(16)
	tokenHash := hashPassword(token)

	return selector, token, tokenHash
}

func newNullString(v string) *sql.NullString {
	return &sql.NullString{String: v, Valid: true}
}
func newNullInt64(v int64) *sql.NullInt64 {
	return &sql.NullInt64{Int64: v, Valid: true}
}

func ValidateSelector(selector string) bool {
	return len(selector) == 16 && ValidateAlphanumericString(selector) == true
}
func ValidateToken(token string) bool {
	return len(token) == 16 && ValidateAlphanumericString(token) == true
}
