package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	firebase "firebase.google.com/go/v4"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/go-chi/httprate"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
)

var WS_Ticket_Duration = time.Duration(5) * time.Minute
var JWT_Sign_Method = jwt.SigningMethodHS256

func getClientIP(req *http.Request) string {
	forwarded := req.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		ips := strings.Split(forwarded, ",")
		clientIP := strings.TrimSpace(ips[0])
		return clientIP
	}

	clientIP := req.Header.Get("X-Real-IP")
	if clientIP != "" {
		return clientIP
	}

	clientIP, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return ""
	}
	return clientIP
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

	firebaseApp, err := firebase.NewApp(ctx, nil)
	if err != nil {
		log.Fatalf("error initializing app: %v\n", err)
	}

	firebaseAuth, err := firebaseApp.Auth(ctx)
	if err != nil {
		log.Fatalf("error getting Auth client: %v\n", err)
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0,
	})

	router := chi.NewRouter()
	router.Use(middleware.CleanPath)
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
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				bearerToken := r.Header.Get("Authorization")
				if bearerToken == "" || strings.Contains(bearerToken, "Bearer") == false {
					w.WriteHeader(http.StatusUnauthorized)
					log.Println("invalid authorization header")
					return
				}

				token, err := firebaseAuth.VerifyIDToken(context.Background(), strings.TrimPrefix(bearerToken, "Bearer "))
				if err != nil {
					w.WriteHeader(http.StatusUnauthorized)
					log.Println("invalid id token")
					return
				}

				ctx := context.WithValue(r.Context(), "userID", token.UID)
				next.ServeHTTP(w, r.WithContext(ctx))
			})
		})

		r.Get("/ws/ticket", func(res http.ResponseWriter, req *http.Request) {
			userID := fmt.Sprintf("%v", req.Context().Value("userID"))
			clientIP := getClientIP(req)
			hostname, err := os.Hostname()
			if err != nil {
				res.WriteHeader(http.StatusInternalServerError)
				log.Println("get hostname failed", err)
				return
			}

			ticketDuration := time.Minute * 3
			issuedAt := time.Now()
			expiresAt := issuedAt.Add(ticketDuration)
			claims := struct {
				ClientIP string `json:"clientIP"`
				jwt.RegisteredClaims
			}{
				clientIP,
				jwt.RegisteredClaims{
					IssuedAt:  jwt.NewNumericDate(issuedAt),
					ExpiresAt: jwt.NewNumericDate(expiresAt),
					Issuer:    hostname,
					Subject:   userID,
				},
			}

			token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			signedToken, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
			if err != nil {
				res.WriteHeader(http.StatusInternalServerError)
				log.Println("sign jwt failed", err)
				return
			}

			ticket := struct {
				UserID   string `json:"userID"`
				ClientIP string `json:"clientIP"`
			}{
				UserID:   userID,
				ClientIP: clientIP,
			}

			ticketJSON, err := json.Marshal(ticket)
			if err != nil {
				res.WriteHeader(http.StatusInternalServerError)
				log.Println("marshal ticket failed", err)
				return
			}

			err = rdb.Set(context.Background(), signedToken, ticketJSON, ticketDuration).Err()
			if err != nil {
				res.WriteHeader(http.StatusInternalServerError)
				log.Println("set ticket to redis failed", err)
				return
			}

			resBody := struct {
				Ticket string `json:"ticket"`
			}{
				Ticket: signedToken,
			}
			resBodyJSON, err := json.Marshal(resBody)
			if err != nil {
				res.WriteHeader(http.StatusInternalServerError)
				log.Println("marshal res body failed", err)
				return
			}

			res.Header().Set("Content-Type", "application/json")
			res.Write(resBodyJSON)
		})
	})

	http.ListenAndServe(":3000", router)
}
