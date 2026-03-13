# DISCLAIMER: This Makefile was generated with AI assistance.

CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2
TARGET = fuzzer
SRCS = main.c fuzzer.c executor.c utils.c
OBJS = $(SRCS:.c=.o)

# Default rule to build the executable
all: $(TARGET)

# Rule to link the object files into the final executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

# Rule to compile C source files into object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Rule to clean the workspace
clean:
	rm -f $(OBJS) $(TARGET) archive.tar success*

# Phony targets
.PHONY: all clean