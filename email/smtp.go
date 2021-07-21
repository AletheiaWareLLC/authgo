package email

import (
	"aletheiaware.com/authgo"
	"aletheiaware.com/cryptogo"
	"bytes"
	"html/template"
	"log"
	"net/smtp"
)

func SendEmail(server, from, to string, template *template.Template, data interface{}) error {
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
	code, err := cryptogo.RandomString(authgo.VERIFICATION_CODE_LENGTH)
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
	if err := SendEmail(v.Server, v.Sender, email, v.Template, data); err != nil {
		return "", err
	}
	return code, nil
}
