CC = gcc
CFLAGS = -Wall -Wextra -g
LDFLAGS = -lpcap

SRCS = src/main.c src/capture.c src/policy.c
OBJS = $(SRCS:.c=.o)
TARGET = zerotrust

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDFLAGS)

clean:
	rm -f $(TARGET) *.o src/*.o
