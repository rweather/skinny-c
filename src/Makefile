
.PHONY: all clean check

CFLAGS += -Wall -O3 -std=c99 -I../include

LIBRARY = libskinny.a

OBJS = skinny128-cipher.o

all: $(LIBRARY)

$(LIBRARY): $(OBJS)
	rm -f $(LIBRARY)
	$(AR) rc $(LIBRARY) $(OBJS)

clean:
	rm -f $(OBJS) $(LIBRARY)

check: all

skinny128-cipher.o: ../include/skinny128-cipher.h
