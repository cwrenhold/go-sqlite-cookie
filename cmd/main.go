package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"text/template"

	"github.com/joho/godotenv"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var templates *template.Template
var db *sql.DB

type contextKey string

const (
	CookieName     = "user_id"
	UserContextKey = contextKey("user")
)

type User struct {
	ID       int
	Username string
	Password string
}

func initialiseDatabase() *sql.DB {
	dbPath := fmt.Sprintf("./%s", os.Getenv("DATABASE_NAME"))

	// If the database file does not exist, notifiy the logger
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		log.Println("Database file does not exist")
	}

	// Open the database file
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatal(err)
	}

	// Create the users table
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL
	)`)

	if err != nil {
		log.Fatal(err)
	}

	// Check if there are any users in the table
	var count int
	err = db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count)
	if err != nil {
		log.Fatal(err)
	}

	// Insert a user into the table if there are no users
	if count == 0 {
		hashedPassword, err := hashPassword("password")
		if err != nil {
			log.Fatal(err)
		}

		_, err = db.Exec(`INSERT INTO users (username, password) VALUES ('admin', ?)`, hashedPassword)
		if err != nil {
			log.Fatal(err)
		}

		log.Println("Inserted user into database")
	}

	// Log that we're connected to the database
	log.Println("Connected to database")

	// Return the database
	return db
}

// Load the HTML templates from the templates directory
func loadTemplates() {
	tmpl, err := template.ParseGlob("templates/*.html")
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Loaded templates")

	templates = tmpl
}

// Encrypt a string value using AES encryption
func encrypt(value string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(value), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt a string value using AES encryption
func decrypt(value string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	log.Printf("Hashed value: %s to %s", password, string(hash))

	return string(hash), nil
}

func comparePasswords(hashedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

func loginPage(w http.ResponseWriter, r *http.Request) {
	templates.ExecuteTemplate(w, "login.html", nil)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	// If no username or password was provided, display the login page again
	if username == "" || password == "" {
		templates.ExecuteTemplate(w, "login.html", nil)
		return
	}

	var user User
	err := db.QueryRow(`SELECT * FROM users WHERE username = ?`, username).Scan(&user.ID, &user.Username, &user.Password)

	if err != nil {
		templates.ExecuteTemplate(w, "login.html", struct{ Error string }{Error: "Invalid username or password"})
		return
	}

	// if the user was found and the password matches, create a cookie with the user's id and redirect to the welcome page
	value := fmt.Sprintf("%d", user.ID)
	encryptedValue, err := encrypt(value, []byte(os.Getenv("COOKIE_KEY")))
	if err != nil {
		log.Println(err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if comparePasswords(user.Password, password) {
		http.SetCookie(w, &http.Cookie{
			Name:     "user_id",
			Value:    encryptedValue,
			Path:     "/",
			HttpOnly: true,
			MaxAge:   15, // 15 seconds for testing
		})

		http.Redirect(w, r, "/welcome", http.StatusSeeOther)
		return
	}

	// if the password does not match, display the login page again, with an error message
	templates.ExecuteTemplate(w, "login.html", struct{ Error string }{Error: "Invalid username or password"})
}

func welcomePage(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value(UserContextKey).(User)
	templates.ExecuteTemplate(w, "welcome.html", user)
}

func logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:   CookieName,
		Value:  "",
		MaxAge: -1,
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// middleware function to check if the user is logged in
func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("user_id")
		if err != nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		// decrypt the cookie userId to get the user id
		userId, err := decrypt(cookie.Value, []byte(os.Getenv("COOKIE_KEY")))
		if err != nil {
			http.SetCookie(w, &http.Cookie{
				Name:   CookieName,
				Value:  "",
				MaxAge: -1,
			})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		var user User
		err = db.QueryRow(`SELECT * FROM users WHERE id = ?`, userId).Scan(&user.ID, &user.Username, &user.Password)
		if err != nil {
			http.SetCookie(w, &http.Cookie{
				Name:   CookieName,
				Value:  "",
				MaxAge: -1,
			})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		log.Printf("User %s is logged in", user.Username)

		// if the user is logged in, attach the user to the request context and call the next handler
		ctx := context.WithValue(r.Context(), UserContextKey, user)
		next(w, r.WithContext(ctx))
	}
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	db = initialiseDatabase()

	// If the database does not exist, log the error and exit
	if db == nil {
		log.Fatal("Database not initialised")
	}

	// Defer the closing of the database
	defer db.Close()

	// Load the HTML templates
	loadTemplates()

	// Handle the login page
	http.HandleFunc("GET /", loginPage)
	http.HandleFunc("POST /", handleLogin)
	http.HandleFunc("GET /welcome", requireAuth(welcomePage))
	http.HandleFunc("GET /logout", requireAuth(logout))

	// Start the server
	log.Println("Starting server on port 3000")
	err = http.ListenAndServe(":3000", nil)

	if err != nil {
		log.Fatal(err)
	}
}
