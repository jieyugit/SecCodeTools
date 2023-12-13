CC=gcc

CFLAGS=-Wall -lnetfilter_queue

TARGET=libnetfilter_queue_icmp

all: $(TARGET)

$(TARGET): libnetfilter_queue_icmp.c
	$(CC)  libnetfilter_queue_icmp.c -o $(TARGET) $(CFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean

