package auth

import "time"

const (
	ERROR_TOKENEXPIRED     string = "token expired"
	ERROR_INVALIDPASSWORD  string = "invalid password"
	ERROR_INVALIDEMAIL     string = "invalid email"
	ERROR_TOOMANYREQUESTS  string = "too many requests"
	ERROR_EMAILNOTVERIFIED string = "email is not verified"
	ERROR_RESETDISABLED    string = "reset disabled"
	ERROR_USERBLOCKED      string = "user blocked"
	ERROR_INVALIDSELECTOR  string = "invalid selector"
	ERROR_INVALIDTOKEN     string = "invalid token"
	ERROR_SENDCONFIRM      string = "failed to send confirmation email"
	ERROR_SETCOOKIE        string = "failed to set remember cookie"
	ERROR_NODATABASECONN   string = "no database connection"
	ERROR_INVALIDUSERID    string = "invalid user id"
)

const (
	ROLE_USER       int64 = 1
	ROLE_ADMIN      int64 = 1000
	ROLE_SUPERADMIN int64 = 65536
	ROLE_DEVELOPER  int64 = 256
)

const (
	STATUS_NORMAL         int64 = 0
	STATUS_ARCHIVED       int64 = 1
	STATUS_BANNED         int64 = 2
	STATUS_LOCKED         int64 = 3
	STATUS_PENDING_REVIEW int64 = 4
	STATUS_SUSPENDED      int64 = 5
)

type SelectorTokenCallBack func(selector string, token string) error

func getTable(id string) string {
	switch id {
	case "users":
		return "users"
	case "users_confirmations":
		return "users_confirmations"
	case "users_remembered":
		return "users_remembered"
	case "users_resets":
		return "users_resets"
	default:
		panic("invalid table name")
	}
}
func getUserConfirmationExpiry() int64 {
	return time.Now().Add(time.Duration(time.Hour)).Unix()
}
func getUserRememberedExpiry() int64 {
	// 672 Hours = 28 days
	return time.Now().Add(time.Duration(time.Hour * 672)).Unix()
}
func getUserResetExpiry() int64 {
	return time.Now().Add(time.Duration(time.Hour * 24)).Unix()
}
func getMaxUserResetRequests() int64 {
	return 2
}
