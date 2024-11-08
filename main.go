package main

import (
	"context"
	"encoding/json"
	"fmt"
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
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/joho/godotenv"
	"github.com/pkg/errors"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/rs/zerolog/pkgerrors"
	"gopkg.in/natefinch/lumberjack.v2"
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
			err := errors.New("authenticate(): invalid authorization header")
			log.Ctx(req.Context()).Error().Err(err).Msg("")
			http.Error(res, err.Error(), http.StatusUnauthorized)
			return
		}

		token, err := firebaseAuth.VerifyIDToken(context.Background(), strings.TrimPrefix(bearerToken, "Bearer "))
		if err != nil {
			log.Ctx(req.Context()).Error().Err(errors.Wrap(err, "authenticate()")).Msg("invalid id token")
			http.Error(res, err.Error(), http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(req.Context(), "userID", token.UID)
		next.ServeHTTP(res, req.WithContext(ctx))
	})
}

type loggerResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (res *loggerResponseWriter) WriteHeader(statusCode int) {
	res.statusCode = statusCode
	res.ResponseWriter.WriteHeader(statusCode)
}

func logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		lres := loggerResponseWriter{res, http.StatusOK}
		start := time.Now()

		log := log.With().Str("req_id", uuid.New().String()).Logger()
		ctx := log.WithContext(req.Context())

		hostname, err := os.Hostname()
		if err != nil {
			hostname = req.Host
			log.Error().Err(errors.Wrap(err, "logger()")).Msg("failed to get hostname for logger")
		}

		log.Info().
			Str("method", req.Method).
			Str("path", req.URL.Path).
			Str("query", req.URL.RawQuery).
			Str("client_ip", req.RemoteAddr).
			Str("user_agent", req.UserAgent()).
			Str("hostname", hostname).
			Msg("request received")

		defer func() {
			log.Info().
				Int("status_code", lres.statusCode).
				Dur("res_time", time.Since(start)).
				Msg("request completed")
		}()

		next.ServeHTTP(&lres, req.WithContext(ctx))
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
		return "", errors.Wrap(err, "createTicketJWT()")
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
		return errors.Wrap(err, "setTicket()")
	}

	ctx := context.Background()
	err = redisClient.Set(ctx, key, ticketJSON, expiration).Err()
	if err != nil {
		return errors.Wrap(err, "setTicket()")
	}

	return nil
}

func websocketTicketHandler(res http.ResponseWriter, req *http.Request) {
	userID := fmt.Sprintf("%v", req.Context().Value("userID"))
	clientIP := req.RemoteAddr

	hostname, err := os.Hostname()
	if err != nil {
		hostname = req.Host
		log.Ctx(req.Context()).Error().Err(errors.Wrap(err, "websocketTicketHandler()")).Msg("failed to get hostname for websocket ticket")
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
		log.Ctx(req.Context()).Error().Err(errors.Wrap(err, "websocketTicketHandler()")).Msg("failed to create websocket ticket")
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Ctx(req.Context()).Info().Str("user_id", userID).Msg("successfully created websocket ticket")

	ticket := Ticket{
		UserID:   userID,
		ClientIP: clientIP,
	}

	err = setTicket(signedToken, &ticket, ticketDuration)
	if err != nil {
		log.Ctx(req.Context()).Error().Err(errors.Wrap(err, "websocketTicketHandler()")).Msg("failed to set websocket ticket to redis")
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Ctx(req.Context()).Info().Str("user_id", userID).Msg("successfully set websocket ticket to redis")

	resBody := struct {
		Ticket string `json:"ticket"`
	}{
		Ticket: signedToken,
	}

	resBodyJSON, err := json.Marshal(resBody)
	if err != nil {
		log.Ctx(req.Context()).Error().Err(errors.Wrap(err, "websocketTicketHandler()")).Msg("failed to marshal response body")
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	res.Header().Set("Content-Type", "application/json")
	res.Write(resBodyJSON)
}

func setupLogger(logOutput string) zerolog.Logger {
	switch logOutput {
	case "stdout":
		return zerolog.New(os.Stdout).With().Timestamp().Logger()

	case "file":
		lumberjackLogger := lumberjack.Logger{
			Filename:   "./logs/squeak.log",
			MaxSize:    10,
			MaxBackups: 3,
			MaxAge:     28,
			Compress:   true,
		}
		return zerolog.New(&lumberjackLogger).With().Timestamp().Logger()

	case "both":
		lumberjackLogger := lumberjack.Logger{
			Filename:   "./logs/squeak.log",
			MaxSize:    10,
			MaxBackups: 3,
			MaxAge:     28,
			Compress:   true,
		}
		multiWriters := zerolog.MultiLevelWriter(os.Stdout, &lumberjackLogger)
		return zerolog.New(multiWriters).With().Timestamp().Logger()

	default:
		return zerolog.New(os.Stdout).With().Timestamp().Logger()
	}
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal().Stack().Err(err).Msgf("failed to load %s file", ".env")
	}

	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack

	logOutput := os.Getenv("LOG_OUTPUT")
	log.Logger = setupLogger(logOutput)

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("failed to establish a connection to a PostgreSQL server with a connection string")
	}
	defer conn.Close(ctx)

	firebaseApp, err = firebase.NewApp(ctx, nil)
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("failed to initialize firebase app")
	}

	firebaseAuth, err = firebaseApp.Auth(ctx)
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("failed to initialize firebase auth")
	}

	redisClient = redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0,
	})

	router := chi.NewRouter()
	router.Use(middleware.CleanPath)
	router.Use(middleware.RealIP)
	router.Use(logger)
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

	router.Group(func(r chi.Router) {
		r.Use(authenticate)
		r.Get("/ws/ticket", websocketTicketHandler)
	})

	http.ListenAndServe(":3000", router)
}
