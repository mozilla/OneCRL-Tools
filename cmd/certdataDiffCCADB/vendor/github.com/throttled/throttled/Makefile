

.PHONY: test test-cover bench lint get-deps .go-test .go-test-cover

test: .go-test bench lint

test-cover: .go-test-cover bench lint

bench:
	go test -race -bench=. -cpu=1,2,4

lint:
	gofmt -l .
	go vet ./...
	which golint # Fail if golint doesn't exist
	-golint . # Don't fail on golint warnings themselves
	-golint store # Don't fail on golint warnings themselves

get-deps:
	go get github.com/garyburd/redigo/redis
	go get github.com/hashicorp/golang-lru
	go get github.com/golang/lint/golint

.go-test:
	go test ./...

.go-test-cover:
	go test -coverprofile=throttled.coverage.out .
	go test -coverprofile=store.coverage.out ./store
