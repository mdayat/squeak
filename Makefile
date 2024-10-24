run:
	go run .

build:
	go fmt . && go vet && go build -o ./dist/