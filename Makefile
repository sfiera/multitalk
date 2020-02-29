CC=gcc
SRCS=toofar.c kwai.c
OBJS=$(subst .c,.o,$(SRCS))
EXES=$(subst .c,,$(SRCS))
#CFLAGS=-DDEBUG=1

all: $(EXES)

clean:
	rm -f $(OBJS) $(EXES)

toofar: toofar.go
	go build -o $@ $^

kwai: kwai.o
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $<
