CC = gcc
CFLAGS = -Wall -Wextra -g
LDFLAGS = -lpcap

SRCS = src/main.c src/capture.c src/policy.c src/ffi_interface.c
OBJS = $(SRCS:.c=.o)
TARGET = zerotrust

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

clean:
	rm -f $(TARGET) *.o src/*.o
