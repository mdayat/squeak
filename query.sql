-- name: GetUser :one
SELECT * FROM "user" WHERE id = $1;

-- name: GetUsers :many
SELECT * FROM "user";

-- name: CreateUser :exec
INSERT INTO "user" (email, name, avatar_url) VALUES ($1, $2, $3);