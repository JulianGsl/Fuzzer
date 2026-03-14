# DISCLAIMER: This Makefile was generated with AI assistance.

CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2 -Isrc
TARGET = fuzzer

# Dossier des sources
SRC_DIR = src

# On définit les chemins complets vers les fichiers sources
SRCS = $(SRC_DIR)/main.c $(SRC_DIR)/fuzzer.c $(SRC_DIR)/executor.c $(SRC_DIR)/utils.c
# Les fichiers objets seront créés dans le même dossier que les sources
OBJS = $(SRCS:.c=.o)

# Règle par défaut pour construire l'exécutable
all: $(TARGET)

# Règle pour lier les fichiers objets et créer l'exécutable final [cite: 53]
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

# Règle pour compiler les fichiers C en fichiers objets dans le dossier src
$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Règle pour nettoyer l'espace de travail
clean:
	rm -f $(OBJS) $(TARGET) archive.tar success*

# Cibles factices
.PHONY: all clean