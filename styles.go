package auth

func (c *authController) Stylesheet() string {
	return `
	#login{margin:0 auto;width:30%;background-color:rgba(0,0,0,0.6);border:1px solid #000000 !important;padding:1em}#login #username{margin-bottom:-1px;border-bottom-right-radius:0;border-bottom-left-radius:0}#login #password{margin-bottom:10px;border-top-left-radius:0;border-top-right-radius:0}#login #remember{color:#fff}#register{margin:0 auto;width:30%;background-color:rgba(0,0,0,0.6);border:1px solid #000000 !important;padding:1em}#register #username{margin-bottom:-1px;border-bottom-right-radius:0;border-bottom-left-radius:0}#register #password{margin-bottom:10px;border-top-left-radius:0;border-top-right-radius:0}
	`
}
