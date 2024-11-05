package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/go-chi/httprate"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/joho/godotenv"
	"github.com/pkg/errors"
	"github.com/redis/go-redis/v9"
)

var (
	firebaseApp  *firebase.App
	firebaseAuth *auth.Client
	redisClient  *redis.Client
)

func authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		bearerToken := req.Header.Get("Authorization")
		if bearerToken == "" || strings.Contains(bearerToken, "Bearer") == false {
			err := errors.New("invalid authorization header")
			http.Error(res, err.Error(), http.StatusUnauthorized)
			return
		}

		token, err := firebaseAuth.VerifyIDToken(context.Background(), strings.TrimPrefix(bearerToken, "Bearer "))
		if err != nil {
			err = errors.Wrap(err, "invalid id token")
			http.Error(res, err.Error(), http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(req.Context(), "userID", token.UID)
		next.ServeHTTP(res, req.WithContext(ctx))
	})
}

type TicketClaims struct {
	ClientIP string `json:"clientIP"`
	jwt.RegisteredClaims
}

func createTicketJWT(claims *TicketClaims) (string, error) {
	JWT_SECRET := os.Getenv("JWT_SECRET")
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, err := token.SignedString([]byte(JWT_SECRET))
	if err != nil {
		return "", errors.Wrap(err, "signing ticket failed")
	}

	return signedToken, nil
}

type Ticket struct {
	UserID   string `json:"userID"`
	ClientIP string `json:"clientIP"`
}

func setTicket(key string, value *Ticket, expiration time.Duration) error {
	ticketJSON, err := json.Marshal(value)
	if err != nil {
		return errors.Wrap(err, "encode ticket to JSON failed")
	}

	ctx := context.Background()
	err = redisClient.Set(ctx, key, ticketJSON, expiration).Err()
	if err != nil {
		return errors.Wrap(err, "set ticket to redis failed")
	}

	return nil
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v\n", err)
	}

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatalf("error connecting pgx driver: %v\n", err)
	}
	defer conn.Close(ctx)

	firebaseApp, err = firebase.NewApp(ctx, nil)
	if err != nil {
		log.Fatalf("error initializing app: %v\n", err)
	}

	firebaseAuth, err = firebaseApp.Auth(ctx)
	if err != nil {
		log.Fatalf("error getting Auth client: %v\n", err)
	}

	redisClient = redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0,
	})

	router := chi.NewRouter()
	router.Use(middleware.CleanPath)
	router.Use(middleware.RealIP)
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)
	router.Use(httprate.LimitByIP(100, 1*time.Minute))
	options := cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "PUT", "POST", "DELETE", "HEAD", "OPTION"},
		AllowedHeaders:   []string{"User-Agent", "Content-Type", "Accept", "Accept-Encoding", "Accept-Language", "Cache-Control", "Connection", "Host", "Origin", "Referer"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}
	router.Use(cors.Handler(options))
	router.Use(middleware.AllowContentType("application/json"))
	router.Use(middleware.Heartbeat("/ping"))

	router.Post("/api/login", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello Login"))
	})

	router.Group(func(r chi.Router) {
		r.Use(authenticate)

		r.Get("/ws/ticket", func(res http.ResponseWriter, req *http.Request) {
			userID := fmt.Sprintf("%v", req.Context().Value("userID"))
			clientIP := req.RemoteAddr
			hostname, err := os.Hostname()
			if err != nil {
				err = errors.Wrap(err, "get hostname failed")
				http.Error(res, err.Error(), http.StatusInternalServerError)
				return
			}

			ticketDuration := time.Minute * 3
			issuedAt := time.Now()
			expiresAt := issuedAt.Add(ticketDuration)
			claims := TicketClaims{
				clientIP,
				jwt.RegisteredClaims{
					IssuedAt:  jwt.NewNumericDate(issuedAt),
					ExpiresAt: jwt.NewNumericDate(expiresAt),
					Issuer:    hostname,
					Subject:   userID,
				},
			}

			signedToken, err := createTicketJWT(&claims)
			if err != nil {
				http.Error(res, err.Error(), http.StatusInternalServerError)
				return
			}

			ticket := Ticket{
				UserID:   userID,
				ClientIP: clientIP,
			}

			err = setTicket(signedToken, &ticket, ticketDuration)
			if err != nil {
				http.Error(res, err.Error(), http.StatusInternalServerError)
				return
			}

			resBody := struct {
				Ticket string `json:"ticket"`
			}{
				Ticket: signedToken,
			}

			resBodyJSON, err := json.Marshal(resBody)
			if err != nil {
				err = errors.Wrap(err, "encode res body to JSON failed")
				http.Error(res, err.Error(), http.StatusInternalServerError)
				return
			}

			res.Header().Set("Content-Type", "application/json")
			res.Write(resBodyJSON)
		})
	})

	http.ListenAndServe(":3000", router)
}
