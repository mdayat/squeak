# syntax=docker/dockerfile:1
FROM golang:1.23.3-alpine AS base

FROM base AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -o ./squeak

FROM base AS final
WORKDIR /app
COPY --from=build /app/squeak ./
COPY .env service-account-file.json ./
EXPOSE 80
ENTRYPOINT ["/app/squeak"]