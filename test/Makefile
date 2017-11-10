
.PHONY: all clean check

CFLAGS += -Wall -Wextra -Wno-unused-parameter -O3 -std=c99 -I../include
LDFLAGS += -L../src -lskinny

TARGET = test-skinny

OBJS = test-skinny.o
DEPS = ../src/libskinny.a

all: $(TARGET)

$(TARGET): $(OBJS) $(DEPS)
	$(CC) -o $(TARGET) $(OBJS) $(LDFLAGS)

clean:
	rm -f $(TARGET) $(OBJS)

check: all
	./$(TARGET)

test-skinny.o: ../include/skinny128-cipher.h ../include/skinny64-cipher.h ../include/mantis-cipher.h
