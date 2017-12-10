LIBS += -lpcap -lpthread
LDFLAGS += $(LIBS)
all: toofar kwai
clean:
	rm -f *.o toofar kwai
