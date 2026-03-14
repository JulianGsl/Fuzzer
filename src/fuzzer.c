#include <stdio.h>
#include <string.h>
#include "utils.h"
#include "tar.h"
#include "executor.h"
#include <stdlib.h>

// Naughty strings for text fields (name, linkname, uname, gname)
const char* naughty_strings[] = {
    "",                                     // Empty
    "%s%n%s%n%s%n%s%n",                     // Format string vulnerability
    ".././/////////../../../../../etc/passwd", // Path traversal
    "A",                                    // Very short
    // We will dynamically generate a string of exactly 100 'A's without a \0
};
#define NUM_NAUGHTY_STRINGS 4

// Naughty octal strings for numeric fields (mode, uid, gid, size, mtime)
const char* naughty_octals[] = {
    "",
    "0000000",
    "77777777777777777777", // Waaaaay too large
    "-1",                   // Negative
    "9999999",              // Invalid octal (contains 9)
    "%s%x%n",               // Format string just in case
    "A",                    // Not a number at all
};
#define NUM_NAUGHTY_OCTALS 7

// Create the TAR file
void create_tar(struct tar_t *header) {
    calculate_checksum(header);

    FILE *tar = fopen("archive.tar", "wb");
    if (tar == NULL) {
        perror("Error while trying to create the tar file");
        return;
    }
    fwrite(header, sizeof(struct tar_t), 1, tar);

    char padding[1024] = {0};
    fwrite(padding, 1, 1024, tar);

    fclose(tar);
}

// Create a TAR file with multiple headers
void create_multi_tar(struct tar_t *headers, int num_headers) {
    FILE *tar = fopen("archive.tar", "wb");
    if (tar == NULL) {
        perror("Error while trying to create the tar file");
        return;
    }

    for(int i = 0; i < num_headers; i++) {
        calculate_checksum(&headers[i]); 
        fwrite(&headers[i], sizeof(struct tar_t), 1, tar);
    }

    char padding[1024] = {0};
    fwrite(padding, 1, 1024, tar);

    fclose(tar);
}

// Create a baseline header with valid values and checksum
void baseline_header(struct tar_t* entry) {
    memset(entry, 0, sizeof(struct tar_t));

    strncpy(entry->name, "A", 100);
    strncpy(entry->mode, "0000644", 8);
    strncpy(entry->uid, "0000000", 8);
    strncpy(entry->gid, "0000000", 8);
    strncpy(entry->size, "00000000000", 12);
    strncpy(entry->mtime, "00000000000", 12);
    entry->typeflag = '0';
    strncpy(entry->magic, "ustar", 6);
    strncpy(entry->version, "00", 2);
    strncpy(entry->uname, "fuzzer", 32);
    strncpy(entry->gname, "fuzzer", 32);

    calculate_checksum(entry);
}




void generate_random_bytes(char* buf, size_t size) {
    for (size_t i = 0; i < size; i++) {
        
        buf[i] = rand() % 256; // Completely random byte
        
    }
}

void fill_naughty_string(char *dest, size_t size) {
    int choice = rand() % (NUM_NAUGHTY_STRINGS + 1);
    if (choice < NUM_NAUGHTY_STRINGS) {
        strncpy(dest, naughty_strings[choice], size);
    } else {
        // Create an unterminated string (fill entirely with 'A's)
        memset(dest, 'A', size);
    }
}

void fill_naughty_octal(char *dest, size_t size) {
    int choice = rand() % NUM_NAUGHTY_OCTALS;
    strncpy(dest, naughty_octals[choice], size);
}

// Generation-based approach
//regarder ici pour trouver des façons de crash les extracteurs
void generate_header(struct tar_t* entry) {
    //comprendre la structure du header
    memset(entry, 0, sizeof(struct tar_t));

    // Smart-fuzzing text fields
    fill_naughty_string(entry->name, sizeof(entry->name));
    fill_naughty_string(entry->linkname, sizeof(entry->linkname));
    fill_naughty_string(entry->uname, sizeof(entry->uname));
    fill_naughty_string(entry->gname, sizeof(entry->gname));

    // Smart-fuzzing octal/numeric fields
    fill_naughty_octal(entry->mode, sizeof(entry->mode));
    fill_naughty_octal(entry->uid, sizeof(entry->uid));
    fill_naughty_octal(entry->gid, sizeof(entry->gid));
    // Size is special - if it's too big, our fuzzer might try to write a huge file later.
    // For now, keep it to a naught octal or reasonable size
    fill_naughty_octal(entry->size, sizeof(entry->size)); 
    fill_naughty_octal(entry->mtime, sizeof(entry->mtime));

    // Typeflag (common values are '0' for normal file, '5' for directory, etc.)
    char flags[] = {'0', '1', '2', '3', '4', '5', '6', '7', 'A', '\0', (char)255};
    entry->typeflag = flags[rand() % 11];

    // Magic and Version
    if (rand() % 2 == 0) {
        strncpy(entry->magic, "ustar", 6); // Valid magic
        strncpy(entry->version, "00", 2);
    } else {
        fill_naughty_string(entry->magic, sizeof(entry->magic));
    }

    // Explicitly ignore devmajor, devminor, prefix as instructed
    // (they remain 0 because of the memset)

    calculate_checksum(entry);
}