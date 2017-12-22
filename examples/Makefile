
include ../options.mak

.PHONY: all clean check

CFLAGS += $(COMMON_CFLAGS) $(STDC_CFLAGS) -I../include
LDFLAGS += $(COMMON_LDFLAGS) -L../src -lskinny

TARGET1 = skinny-ctr
TARGET2 = skinny-tweak
TARGET3 = skinny-ecb

OBJS1 = skinny-ctr.o options.o
OBJS2 = skinny-tweak.o options.o
OBJS3 = skinny-ecb.o options.o

DEPS = ../src/libskinny.a

all: $(TARGET1) $(TARGET2) $(TARGET3)

$(TARGET1): $(OBJS1) $(DEPS)
	$(CC) -o $(TARGET1) $(OBJS1) $(LDFLAGS)

$(TARGET2): $(OBJS2) $(DEPS)
	$(CC) -o $(TARGET2) $(OBJS2) $(LDFLAGS)

$(TARGET3): $(OBJS3) $(DEPS)
	$(CC) -o $(TARGET3) $(OBJS3) $(LDFLAGS)

clean:
	rm -f $(TARGET1) $(TARGET2) $(TARGET3)
	rm -f $(OBJS1) $(OBJS2) $(OBJS3)

check:

skinny-ctr.o: ../include/skinny128-cipher.h ../include/skinny64-cipher.h options.h
skinny-tweak.o: ../include/skinny128-cipher.h ../include/skinny64-cipher.h options.h
skinny-ecb.o: ../include/skinny128-cipher.h ../include/skinny64-cipher.h options.h
options.o: ../include/skinny128-cipher.h ../include/skinny64-cipher.h options.h
