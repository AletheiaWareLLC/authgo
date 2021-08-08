package email

import (
	"aletheiaware.com/authgo"
	"aletheiaware.com/cryptogo"
	"bytes"
	"html/template"
	"log"
	"net/smtp"
)

func SendEmail(server, identity, sender, recipient string, body *template.Template, data interface{}) error {
	var buffer bytes.Buffer
	if err := body.Execute(&buffer, data); err != nil {
		return err
	}
	c, err := smtp.Dial(server)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Hello(identity); err != nil {
		return err
	}
	if err := c.Mail(sender); err != nil {
		return err
	}
	if err := c.Rcpt(recipient); err != nil {
		return err
	}
	wc, err := c.Data()
	if err != nil {
		return err
	}
	defer wc.Close()
	if _, err := buffer.WriteTo(wc); err != nil {
		return err
	}
	return nil
}

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
	if err := SendEmail(v.Server, v.Identity, v.Sender, email, v.Template, data); err != nil {
		return "", err
	}
	return code, nil
}
