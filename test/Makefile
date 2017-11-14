
include ../options.mak

.PHONY: all clean check perf

CFLAGS += $(COMMON_CFLAGS) -Wno-unused-parameter -I../include
LDFLAGS += $(COMMON_LDFLAGS) -L../src -lskinny

TARGET1 = test-skinny
TARGET2 = test-perf

OBJS1 = test-skinny.o
OBJS2 = test-perf.o

DEPS = ../src/libskinny.a

all: $(TARGET1) $(TARGET2)

$(TARGET1): $(OBJS1) $(DEPS)
	$(CC) -o $(TARGET1) $(OBJS1) $(LDFLAGS)

$(TARGET2): $(OBJS2) $(DEPS)
	$(CC) -o $(TARGET2) $(OBJS2) $(LDFLAGS)

clean:
	rm -f $(TARGET1) $(TARGET2) $(OBJS1) $(OBJS2)

check: $(TARGET1)
	./$(TARGET1)

perf: $(TARGET2)
	./$(TARGET2)

test-skinny.o: ../include/skinny128-cipher.h ../include/skinny64-cipher.h ../include/mantis-cipher.h
test-perf.o: ../include/skinny128-cipher.h ../include/skinny64-cipher.h ../include/mantis-cipher.h
