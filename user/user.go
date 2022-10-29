package user

import "gopkg.in/guregu/null.v3"

type User struct {
	UUID       null.String
	Email      null.String
	Password   null.String
	Attributes UserAttributes
}

type UserAttributes struct {
	Created  null.String
	Deleted  null.String
	Role     null.String
	Verified null.Int
	Status   null.Int
}
