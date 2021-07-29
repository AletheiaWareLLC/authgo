package email

import (
	"aletheiaware.com/authgo"
	"aletheiaware.com/cryptogo"
	"bytes"
	"html/template"
	"log"
	"net/smtp"
)

type SmtpEmailVerifier struct {
	Server   string
	Identity string
	Sender   string
	Template *template.Template
}

func NewSmtpEmailVerifier(server, identity, sender string, template *template.Template) *SmtpEmailVerifier {
	return &SmtpEmailVerifier{
		Server:   server,
		Identity: identity,
		Sender:   sender,
		Template: template,
	}
}

func (v SmtpEmailVerifier) VerifyEmail(email string) (string, error) {
	code, err := cryptogo.RandomString(authgo.VERIFICATION_CODE_LENGTH)
	if err != nil {
		return "", err
	}
	code = code[:authgo.VERIFICATION_CODE_LENGTH]
	log.Println("Verifying Email:", email, "Code:", code)
	data := struct {
		From string
		To   string
		Code string
	}{
		From: v.Sender,
		To:   email,
		Code: code,
	}
	var buffer bytes.Buffer
	if err := v.Template.Execute(&buffer, data); err != nil {
		return "", err
	}
	c, err := smtp.Dial(v.Server)
	if err != nil {
		return "", err
	}
	defer c.Close()
	if err := c.Hello(v.Identity); err != nil {
		return "", err
	}
	if err := c.Mail(v.Sender); err != nil {
		return "", err
	}
	if err := c.Rcpt(email); err != nil {
		return "", err
	}
	wc, err := c.Data()
	if err != nil {
		return "", err
	}
	defer wc.Close()
	if _, err := buffer.WriteTo(wc); err != nil {
		return "", err
	}
	return code, nil
}
