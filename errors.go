package auth

type ErrorEx struct {
	ErrorMsg error
	Func     string
}

func (e *ErrorEx) Error() string {
	return e.ErrorMsg.Error()
}
