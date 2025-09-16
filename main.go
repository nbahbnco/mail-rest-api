package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

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

type QueuedEmail struct {
	To      string
	Subject string
	Body    string
	ID      string
}

var (
	smtpConfig   SMTPConfig
	validAPIKeys map[string]bool // Use a map for efficient key lookups
	emailQueue   chan QueuedEmail
	emailWorker  sync.WaitGroup
	quitChan     chan bool
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

	// Initialize email queue and channels
	emailQueue = make(chan QueuedEmail, 1000) // Buffer for 1000 emails
	quitChan = make(chan bool, 1)

	// Start the email worker
	emailWorker.Add(1)
	go emailWorkerProcess()
}

// emailWorkerProcess processes emails from the queue at a rate of 1 per second
func emailWorkerProcess() {
	defer emailWorker.Done()
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case email := <-emailQueue:
			// Send the email
			err := sendQueuedEmail(email)
			if err != nil {
				log.Printf("Error sending queued email to %s: %v", email.To, err)
			}
			// Wait for the ticker before processing the next email
			<-ticker.C

		case <-quitChan:
			return
		}
	}
}

// sendQueuedEmail handles the actual sending of a queued email
func sendQueuedEmail(email QueuedEmail) error {
	// Prepare the email message
	msg := []byte("To: " + email.To + "\r\n" +
		"From: " + smtpConfig.Sender + "\r\n" +
		"Subject: " + email.Subject + "\r\n" +
		"MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\r\n" +
		"\r\n" +
		email.Body + "\r\n")

	// Authenticate with the SMTP server
	auth := smtp.PlainAuth("", smtpConfig.Username, smtpConfig.Password, smtpConfig.Host)

	// Send the email
	addr := fmt.Sprintf("%s:%d", smtpConfig.Host, smtpConfig.Port)
	return smtp.SendMail(addr, auth, smtpConfig.Sender, []string{email.To}, msg)
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

// sendEmail handles the queuing of an email
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

	// Generate unique ID for this email

	queuedEmail := QueuedEmail{
		To:      emailReq.To,
		Subject: emailReq.Subject,
		Body:    emailReq.Body,
	}

	// Try to queue the email (non-blocking)
	select {
	case emailQueue <- queuedEmail:
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Email queued successfully",
			"status":  "queued",
		})
	default:
		log.Printf("Email queue is full, rejecting email to %s", emailReq.To)
		http.Error(w, "Email queue is full, please try again later", http.StatusServiceUnavailable)
		return
	}
}

func main() {
	router := mux.NewRouter()

	api := router.PathPrefix("/").Subrouter()
	api.Use(authMiddleware)

	// The send-email route is  protected by the authMiddleware
	api.HandleFunc("/send-email", sendEmail).Methods("POST")

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // Default port if not specified
	}

	log.Printf("Server starting on :%s", port)

	// Create server with graceful shutdown
	server := &http.Server{
		Addr:    ":" + port,
		Handler: router,
	}

	// Start server in a goroutine
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")
	quitChan <- true
	emailWorker.Wait()
	_, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

}
