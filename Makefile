OUT=multitalk

all: $(OUT)

.PHONY: multitalk
multitalk: cmd/multitalk.go
	go build -o $@ $^

.PHONY: test
test:
	go test ./...

.PHONY: clean
clean:
	rm -f $(OUT)
