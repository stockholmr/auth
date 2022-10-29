package auth

import (
	"github.com/gookit/event"
	"github.com/stockholmr/auth/user"
)

type Authenticator struct {
	User user.User
	Events event.Manager
}
