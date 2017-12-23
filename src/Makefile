
include ../options.mak

.PHONY: all clean check

CFLAGS += $(VECTOR_CFLAGS) $(COMMON_CFLAGS) $(STDC_CFLAGS) -I../include

LIBRARY = libskinny.a

OBJS = \
	skinny-internal.o \
	skinny128-cipher.o \
	skinny128-ctr.o \
	skinny128-ctr-vec128.o \
	skinny128-ctr-vec256.o \
	skinny128-parallel.o \
	skinny128-parallel-vec128.o \
	skinny128-parallel-vec256.o \
	skinny64-cipher.o \
	skinny64-ctr.o \
	skinny64-ctr-vec128.o \
	skinny64-parallel.o \
	skinny64-parallel-vec128.o \
	mantis-cipher.o \
	mantis-ctr.o \
	mantis-ctr-vec128.o \
	mantis-parallel.o \
	mantis-parallel-vec128.o

all: $(LIBRARY)

$(LIBRARY): $(OBJS)
	rm -f $(LIBRARY)
	$(AR) rc $(LIBRARY) $(OBJS)

clean:
	rm -f $(OBJS) $(LIBRARY)

check: all

# Plain C core source files.
skinny128-cipher.o: ../include/skinny128-cipher.h skinny-internal.h
skinny128-ctr.o: ../include/skinny128-cipher.h skinny-internal.h \
                    skinny128-ctr-internal.h
skinny128-parallel.o: ../include/skinny128-cipher.h \
                    ../include/skinny128-parallel.h skinny-internal.h
skinny64-cipher.o: ../include/skinny64-cipher.h skinny-internal.h
skinny64-ctr.o: ../include/skinny64-cipher.h skinny-internal.h \
                    skinny64-ctr-internal.h
skinny64-parallel.o: ../include/skinny64-cipher.h \
                    ../include/skinny64-parallel.h skinny-internal.h
mantis-cipher.o: ../include/mantis-cipher.h skinny-internal.h
mantis-ctr.o: ../include/mantis-cipher.h skinny-internal.h \
                    mantis-ctr-internal.h
mantis-parallel.o: ../include/mantis-cipher.h ../include/mantis-parallel.h \
                   skinny-internal.h

# Source files that use 128-bit SIMD vector instructions.
skinny128-ctr-vec128.o: skinny128-ctr-vec128.c ../include/skinny128-cipher.h \
                    skinny-internal.h skinny128-ctr-internal.h
	$(CC) $(VEC128_CFLAGS) $(CFLAGS) -c -o $@ $<

skinny128-parallel-vec128.o: skinny128-parallel-vec128.c \
                    ../include/skinny128-cipher.h \
                    ../include/skinny128-parallel.h \
                    skinny-internal.h
	$(CC) $(VEC128_CFLAGS) $(CFLAGS) -c -o $@ $<

skinny64-ctr-vec128.o: skinny64-ctr-vec128.c ../include/skinny64-cipher.h \
                    skinny-internal.h skinny64-ctr-internal.h
	$(CC) $(VEC128_CFLAGS) $(CFLAGS) -c -o $@ $<

skinny64-parallel-vec128.o: skinny64-parallel-vec128.c \
                    ../include/skinny64-cipher.h \
                    ../include/skinny64-parallel.h \
                    skinny-internal.h
	$(CC) $(VEC128_CFLAGS) $(CFLAGS) -c -o $@ $<

mantis-ctr-vec128.o: mantis-ctr-vec128.c ../include/mantis-cipher.h \
                    skinny-internal.h mantis-ctr-internal.h
	$(CC) $(VEC128_CFLAGS) $(CFLAGS) -c -o $@ $<

mantis-parallel-vec128.o: mantis-parallel-vec128.c ../include/mantis-cipher.h \
                    skinny-internal.h ../include/mantis-parallel.h
	$(CC) $(VEC128_CFLAGS) $(CFLAGS) -c -o $@ $<

skinny-internal.o: skinny-internal.c skinny-internal.h
	$(CC) $(VEC128_CFLAGS) $(VEC256_CFLAGS) $(CFLAGS) -c -o $@ $<

# Source files that use 256-bit SIMD vector instructions.
skinny128-ctr-vec256.o: skinny128-ctr-vec256.c ../include/skinny128-cipher.h \
                    skinny-internal.h skinny128-ctr-internal.h
	$(CC) $(VEC256_CFLAGS) $(CFLAGS) -c -o $@ $<

skinny128-parallel-vec256.o: skinny128-parallel-vec256.c \
                    ../include/skinny128-cipher.h \
                    ../include/skinny128-parallel.h \
                    skinny-internal.h
	$(CC) $(VEC256_CFLAGS) $(CFLAGS) -c -o $@ $<
