package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

type EmailRequest struct {
	To      string `json:"to"`
	Subject string `json:"subject"`
	Body    string `json:"body"`
}

type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	Sender   string
}

var (
	smtpConfig   SMTPConfig
	validAPIKeys map[string]bool // Use a map for efficient key lookups
)

func init() {
	// 1. Load from config.properties file first.
	// This will set the base configuration.
	godotenv.Load("/etc/mailrestapi.conf")
	godotenv.Load("/usr/local/etc/mailrestapi.conf")
	godotenv.Load("mailrestapi.conf")

	// 2. Load from .env file.
	// godotenv.Load() will NOT override existing environment variables.
	godotenv.Load()

	// Read SMTP configuration
	smtpConfig.Host = os.Getenv("SMTP_HOST")
	smtpConfig.Username = os.Getenv("SMTP_USERNAME")
	smtpConfig.Password = os.Getenv("SMTP_PASSWORD")
	smtpConfig.Sender = os.Getenv("SENDER_EMAIL")

	portStr := os.Getenv("SMTP_PORT")
	if portStr == "" {
		log.Fatalf("SMTP_PORT environment variable not set.")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		log.Fatalf("Invalid SMTP_PORT: %v", err)
	}
	smtpConfig.Port = port

	// Basic validation for SMTP config
	if smtpConfig.Host == "" || smtpConfig.Username == "" || smtpConfig.Password == "" || smtpConfig.Sender == "" {
		log.Fatalf("One or more required SMTP environment variables are not set. Check SMTP_HOST, SMTP_USERNAME, SMTP_PASSWORD, SENDER_EMAIL.")
	}

	log.Printf("SMTP configuration loaded successfully for host: %s", smtpConfig.Host)

	// Load and parse API keys
	apiKeysStr := os.Getenv("API_KEYS")
	if apiKeysStr == "" {
		log.Fatalf("API_KEYS environment variable is not set. Service cannot start without authorization keys.")
	}
	keys := strings.Split(apiKeysStr, ",")
	validAPIKeys = make(map[string]bool)
	for _, key := range keys {
		trimmedKey := strings.TrimSpace(key)
		if trimmedKey != "" {
			validAPIKeys[trimmedKey] = true
		}
	}
	log.Printf("Loaded %d API key(s).", len(validAPIKeys))
}

// authMiddleware checks for a valid API key in the Authorization header
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		// The header should be in the format "Bearer <token>"
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			http.Error(w, "Authorization header must be in the format 'Bearer <token>'", http.StatusUnauthorized)
			return
		}

		apiKey := parts[1]
		if _, ok := validAPIKeys[apiKey]; !ok {
			http.Error(w, "Invalid API Key", http.StatusUnauthorized)
			return
		}

		// If the key is valid, call the next handler
		next.ServeHTTP(w, r)
	})
}

// sendEmail handles the sending of an email
func sendEmail(w http.ResponseWriter, r *http.Request) {
	var emailReq EmailRequest
	if err := json.NewDecoder(r.Body).Decode(&emailReq); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if emailReq.To == "" || emailReq.Subject == "" || emailReq.Body == "" {
		http.Error(w, "Missing 'to', 'subject', or 'body' in request", http.StatusBadRequest)
		return
	}

	// Prepare the email message
	msg := []byte("To: " + emailReq.To + "\r\n" +
		"From: " + smtpConfig.Sender + "\r\n" +
		"Subject: " + emailReq.Subject + "\r\n" +
		"MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\r\n" +
		"\r\n" +
		emailReq.Body + "\r\n")

	// Authenticate with the SMTP server
	auth := smtp.PlainAuth("", smtpConfig.Username, smtpConfig.Password, smtpConfig.Host)

	// Send the email
	addr := fmt.Sprintf("%s:%d", smtpConfig.Host, smtpConfig.Port)
	err := smtp.SendMail(addr, auth, smtpConfig.Sender, []string{emailReq.To}, msg)
	if err != nil {
		log.Printf("Error sending email to %s: %v", emailReq.To, err)
		http.Error(w, "Failed to send email", http.StatusInternalServerError)
		return
	}

	log.Printf("Email sent successfully to %s", emailReq.To)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Email sent successfully"})
}

func main() {
	router := mux.NewRouter()

	// Create a subrouter to apply middleware to
	api := router.PathPrefix("/").Subrouter()
	api.Use(authMiddleware)

	// The send-email route is  protected by the authMiddleware
	api.HandleFunc("/send-email", sendEmail).Methods("POST")

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // Default port if not specified
	}

	log.Printf("Server starting on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, router))
}
