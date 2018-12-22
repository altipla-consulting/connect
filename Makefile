
FILES = $(shell find . -type f -name '*.go')

gofmt:
	@gofmt -w $(FILES)
	@gofmt -r '&α{} -> new(α)' -w $(FILES)

deps:
	go get -u github.com/mgechev/revive

test:
	revive -formatter friendly
	go install .
	go test ./...

update-deps:
	go get -u
	go mod download
	go mod tidy
