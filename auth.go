package auth

import "os/user"

type Authenticator struct {
	User user.User
}
