OUT=multitalk

all: $(OUT)

.PHONY: multitalk
multitalk: cmd/multitalk/multitalk.go
	go build $^

.PHONY: test
test:
	go test ./...

.PHONY: clean
clean:
	rm -f $(OUT)

.PHONY: drone
drone:
	drone exec
