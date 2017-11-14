
include ../options.mak

.PHONY: all clean check

CFLAGS += $(COMMON_CFLAGS) $(STDC_CFLAGS) -I../include
LDFLAGS += -L../src -lskinny

TARGET1 = skinny-ctr
TARGET2 = skinny-tweak

OBJS1 = skinny-ctr.o options.o
OBJS2 = skinny-tweak.o options.o

DEPS = ../src/libskinny.a

all: $(TARGET1) $(TARGET2)

$(TARGET1): $(OBJS1) $(DEPS)
	$(CC) -o $(TARGET1) $(OBJS1) $(LDFLAGS)

$(TARGET2): $(OBJS2) $(DEPS)
	$(CC) -o $(TARGET2) $(OBJS2) $(LDFLAGS)

clean:
	rm -f $(TARGET1) $(TARGET2) $(OBJS1) $(OBJS2)

check:

skinny-ctr.o: ../include/skinny128-cipher.h ../include/skinny64-cipher.h options.h
skinny-tweak.o: ../include/skinny128-cipher.h ../include/skinny64-cipher.h options.h
options.o: ../include/skinny128-cipher.h ../include/skinny64-cipher.h options.h
