package authgo

import (
	"aletheiaware.com/cryptogo"
	"bytes"
	"errors"
	"html/template"
	"log"
	"net/smtp"
	"regexp"
)

const VERIFICATION_CODE_LENGTH = 8

var (
	ErrInvalidEmail               = errors.New("Invalid Email Address")
	ErrIncorrectEmailVerification = errors.New("Incorrect Verification Code")
)

// This is not intended to validate every possible email address, instead a verification code will be sent to ensure the email works
var emails = regexp.MustCompile(`^.+@.+$`)

func ValidateEmail(email string) error {
	if email == "" || !emails.MatchString(email) {
		return ErrInvalidEmail
	}
	return nil
}

type EmailVerifier interface {
	VerifyEmail(email string) (string, error)
}

func SetEmail(server, from, to string, template *template.Template, data interface{}) error {
	var buffer bytes.Buffer
	if err := template.Execute(&buffer, data); err != nil {
		log.Println(err)
		return err
	}
	return smtp.SendMail(server, nil, from, []string{to}, buffer.Bytes())
}

type SmtpEmailVerifier struct {
	Server   string
	Sender   string
	Template *template.Template
}

func NewSmtpEmailVerifier(server, sender string, template *template.Template) *SmtpEmailVerifier {
	return &SmtpEmailVerifier{
		Server:   server,
		Sender:   sender,
		Template: template,
	}
}

func (v SmtpEmailVerifier) VerifyEmail(email string) (string, error) {
	log.Println("Verifying Email", email)
	code, err := cryptogo.RandomString(VERIFICATION_CODE_LENGTH)
	if err != nil {
		return "", err
	}
	log.Println("Verification Code", code)
	data := struct {
		From string
		To   string
		Code string
	}{
		From: v.Sender,
		To:   email,
		Code: code,
	}
	if err := SetEmail(v.Server, v.Sender, email, v.Template, data); err != nil {
		return "", err
	}
	return code, nil
}
