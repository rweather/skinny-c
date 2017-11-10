
.PHONY: all clean check

CFLAGS += -Wall -O3 -std=c99 -I../include

LIBRARY = libskinny.a

OBJS = \
	skinny128-cipher.o \
	skinny128-ctr.o \
	skinny64-cipher.o \
	skinny64-ctr.o \
	mantis-cipher.o \
	mantis-ctr.o

all: $(LIBRARY)

$(LIBRARY): $(OBJS)
	rm -f $(LIBRARY)
	$(AR) rc $(LIBRARY) $(OBJS)

clean:
	rm -f $(OBJS) $(LIBRARY)

check: all

skinny128-cipher.o: ../include/skinny128-cipher.h skinny-internal.h
skinny128-ctr.o: ../include/skinny128-cipher.h skinny-internal.h
skinny64-cipher.o: ../include/skinny64-cipher.h skinny-internal.h
skinny64-ctr.o: ../include/skinny64-cipher.h skinny-internal.h
mantis-cipher.o: ../include/mantis-cipher.h skinny-internal.h
mantis-ctr.o: ../include/mantis-cipher.h skinny-internal.h
