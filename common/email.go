package common

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/smtp"
	"strings"
	"time"

	"github.com/microcosm-cc/bluemonday"
)

// SanitizeSubject removes newlines and carriage returns from the subject
func SanitizeSubject(subject string) string {
	// Replace CR and LF characters with space
	subject = strings.Replace(subject, "\r", " ", -1)
	subject = strings.Replace(subject, "\n", " ", -1)
	return subject
}

func SendEmail(subject string, receiver string, content string) error {
	if SMTPFrom == "" { // for compatibility
		SMTPFrom = SMTPAccount
	}
	// Sanitize the subject to prevent header injection
	sanitizedSubject := SanitizeSubject(subject)
	encodedSubject := fmt.Sprintf("=?UTF-8?B?%s?=", base64.StdEncoding.EncodeToString([]byte(sanitizedSubject)))

	// Sanitize the content to prevent HTML/JS injection
	p := bluemonday.UGCPolicy()
	safeContent := p.Sanitize(content)

	// Extract domain from SMTPFrom
	parts := strings.Split(SMTPFrom, "@")
	var domain string
	if len(parts) > 1 {
		domain = parts[1]
	}
	// Generate a unique Message-ID
	buf := make([]byte, 16)
	_, err := rand.Read(buf)
	if err != nil {
		return err
	}
	messageId := fmt.Sprintf("<%x@%s>", buf, domain)

	mail := []byte(fmt.Sprintf("To: %s\r\n"+
		"From: %s<%s>\r\n"+
		"Subject: %s\r\n"+
		"Message-ID: %s\r\n"+ // add Message-ID header to avoid being treated as spam, RFC 5322
		"Date: %s\r\n"+
		"Content-Type: text/html; charset=UTF-8\r\n\r\n%s\r\n",
		receiver, SystemName, SMTPFrom, encodedSubject, messageId, time.Now().Format(time.RFC1123Z), safeContent))
	auth := smtp.PlainAuth("", SMTPAccount, SMTPToken, SMTPServer)
	addr := fmt.Sprintf("%s:%d", SMTPServer, SMTPPort)
	to := strings.Split(receiver, ";")

	if SMTPPort == 465 {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: false,
			ServerName:         SMTPServer,
		}
		conn, err := tls.Dial("tcp", addr, tlsConfig)
		if err != nil {
			return err
		}
		client, err := smtp.NewClient(conn, SMTPServer)
		if err != nil {
			conn.Close()
			return err
		}
		defer client.Close()
		if err = client.Auth(auth); err != nil {
			return err
		}
		if err = client.Mail(SMTPFrom); err != nil {
			return err
		}
		for _, email := range to {
			if err = client.Rcpt(email); err != nil {
				return err
			}
		}
		w, err := client.Data()
		if err != nil {
			return err
		}
		_, err = w.Write(mail)
		if err != nil {
			w.Close()
			return err
		}
		err = w.Close()
		if err != nil {
			return err
		}
	} else {
		err = smtp.SendMail(addr, auth, SMTPFrom, to, mail)
	}
	return err
}
