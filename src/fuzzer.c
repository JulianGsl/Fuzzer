#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "utils.h"
#include "tar.h"
#include "executor.h"
#include "fuzzer.h"

static void write_body(FILE *tar);
static void generate_random_bytes(char* buf, size_t size);
static void fill_naughty_string(char *dest, size_t size);
static void fill_naughty_octal(char *dest, size_t size);

const char* naughty_strings[] = {
    "",
    "%s%n%s%n%x%x",
    "%n%n%n%n",
    "../../../../../../etc/passwd",
    "../../../tmp/pwned",
    "/etc/shadow",
    "A",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "\x00hidden",
    "normal\x00hidden",
};
#define NUM_NAUGHTY_STRINGS 10

const char* naughty_octals[] = {
    "",
    "0000000",
    "77777777777",
    "37777777777",
    "777777777777777777",
    "-1",
    "-99999999",
    "9999999",
    "%s%x%n",
    "A",
    "\x00\x00\x00\x00",
    "0000001",
};
#define NUM_NAUGHTY_OCTALS 12

void create_tar(struct tar_t *headers, int num_headers) {
    FILE *tar = fopen("archive.tar", "wb");
    if (tar == NULL) {
        perror("Error while trying to create the tar file");
        return;
    }

    int truncate_at = -1;
    if (rand() % 8 == 0 && num_headers > 0) {
        truncate_at = rand() % num_headers;
    }

    for (int i = 0; i < num_headers; i++) {
        calculate_checksum(&headers[i]);
        fwrite(&headers[i], sizeof(struct tar_t), 1, tar);

        if (truncate_at == i) {
            fclose(tar);
            return;
        }

        write_body(tar);
    }

    int ending = rand() % 5;
    if (ending == 0) {
        char padding[1024] = {0};
        fwrite(padding, 1, 1024, tar);
    }
    else if (ending == 1) {
        struct tar_t ghost;
        baseline_header(&ghost);
        strncpy(ghost.name, "ghost.txt", 100);
        strncpy(ghost.size, "00000077777", 12);
        calculate_checksum(&ghost);
        fwrite(&ghost, sizeof(struct tar_t), 1, tar);
        char pad[512] = {0};
        fwrite(pad, 1, 512, tar);
    }
    else if (ending == 2) {
        char garbage[256];
        for (int i = 0; i < 256; i++)
            garbage[i] = rand() % 256;
        fwrite(garbage, 1, 256, tar);
    }

    fclose(tar);
}

static void write_body(FILE *tar) {
    int choice = rand() % 6;

    if (choice == 0 || choice == 1) {
        return;
    }

    if (choice == 2) {
        int data_size = (rand() % 2048) + 1;
        char *body = malloc(data_size);
        if (body) {
            generate_random_bytes(body, data_size);
            fwrite(body, 1, data_size, tar);
            free(body);
            int rem = data_size % 512;
            if (rem > 0) {
                char pad[512] = {0};
                fwrite(pad, 1, 512 - rem, tar);
            }
        }
    }
    else if (choice == 3) {
        int data_size = (rand() % 1024) + 512;
        char *body = malloc(data_size);
        if (body) {
            generate_random_bytes(body, data_size);
            fwrite(body, 1, data_size, tar);
            free(body);
        }
    }
    else if (choice == 4) {
        char small[64];
        generate_random_bytes(small, 64);
        fwrite(small, 1, 64, tar);
    }
    else {
        int huge = 10000 + (rand() % 5000);
        char *body = malloc(huge);
        if (body) {
            generate_random_bytes(body, huge);
            fwrite(body, 1, huge, tar);
            free(body);
        }
    }
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
    memcpy(entry->version, "00", 2);
    strncpy(entry->uname, "fuzzer", 32);
    strncpy(entry->gname, "fuzzer", 32);

    calculate_checksum(entry);
}

static void generate_random_bytes(char* buf, size_t size) {
    for (size_t i = 0; i < size; i++) {
        
        buf[i] = rand() % 256; // Completely random byte
        
    }
}

static void fill_naughty_string(char *dest, size_t size) {
    int choice = rand() % (NUM_NAUGHTY_STRINGS + 2);

    if (choice < NUM_NAUGHTY_STRINGS) {
        strncpy(dest, naughty_strings[choice], size);
    } else if (choice == NUM_NAUGHTY_STRINGS) {
        memset(dest, 'A', size);
        return; // pas de null terminator !
    } else {
        for (size_t i = 0; i < size; i++)
            dest[i] = 'A' + (rand() % 26);
        return; // pas de null terminator non plus
    }

    if (rand() % 3 == 0 && size > 0)
        dest[size - 1] = '\0';
}

static void fill_naughty_octal(char *dest, size_t size) {
    int choice = rand() % NUM_NAUGHTY_OCTALS;
    size_t len = strlen(naughty_octals[choice]);
    if (len > size) len = size;
    memcpy(dest, naughty_octals[choice], len);
}

void generate_header(struct tar_t* entry) {
    memset(entry, 0, sizeof(struct tar_t));

    int strategy = rand() % 10;

    if (strategy == 0) {
        fill_naughty_string(entry->name, sizeof(entry->name));
        strncpy(entry->mode, "0000644", 8);
        strncpy(entry->uid, "0000000", 8);
        strncpy(entry->gid, "0000000", 8);
        strncpy(entry->size, "00000000000", 12);
        strncpy(entry->mtime, "00000000000", 12);
        entry->typeflag = '0';
        strncpy(entry->magic, "ustar", 6);
        memcpy(entry->version, "00", 2);
    }
    else if (strategy == 1) {
        strncpy(entry->name, "overflow_test.txt", 100);
        strncpy(entry->mode, "0000644", 8);
        strncpy(entry->uid, "0000000", 8);
        strncpy(entry->gid, "0000000", 8);

        const char* big_sizes[] = {"37777777777", "77777777777", "999999999999", "-0000000001"};
        memcpy(entry->size, big_sizes[rand() % 4], 12);

        strncpy(entry->mtime, "00000000000", 12);
        entry->typeflag = '0';
        strncpy(entry->magic, "ustar", 6);
        memcpy(entry->version, "00", 2);
    }
    else if (strategy == 2) {
        strncpy(entry->name, "../../../../../../tmp/escape", 100);
        strncpy(entry->linkname, "/etc/passwd", 100);
        strncpy(entry->mode, "0000777", 8);
        strncpy(entry->uid, "0000000", 8);
        strncpy(entry->gid, "0000000", 8);
        strncpy(entry->size, "00000000000", 12);
        strncpy(entry->mtime, "00000000000", 12);
        entry->typeflag = (rand() % 2) ? '1' : '2';
        strncpy(entry->magic, "ustar", 6);
        memcpy(entry->version, "00", 2);
    }
    else if (strategy == 3) {
        memset(entry->name, 'X', 100);
        memset(entry->linkname, 'Y', 100);
        memset(entry->uname, 'Z', 32);
        memset(entry->gname, 'W', 32);
        strncpy(entry->mode, "0000644", 8);
        strncpy(entry->uid, "0000000", 8);
        strncpy(entry->gid, "0000000", 8);
        strncpy(entry->size, "00000000000", 12);
        strncpy(entry->mtime, "00000000000", 12);
        entry->typeflag = '0';
        strncpy(entry->magic, "ustar", 6);
        memcpy(entry->version, "00", 2);
    }
    else if (strategy == 4) {
        entry->name[0] = '\0';
        strncpy(entry->mode, "0000644", 8);
        strncpy(entry->uid, "0000000", 8);
        strncpy(entry->gid, "0000000", 8);
        strncpy(entry->size, "00000000000", 12);
        strncpy(entry->mtime, "00000000000", 12);
        entry->typeflag = '0';
        strncpy(entry->magic, "ustar", 6);
        memcpy(entry->version, "00", 2);
    }
    else if (strategy == 5) {
        strncpy(entry->name, "weird_dir", 100);
        strncpy(entry->mode, "0000755", 8);
        strncpy(entry->uid, "0000000", 8);
        strncpy(entry->gid, "0000000", 8);
        strncpy(entry->size, "00000001000", 12);
        strncpy(entry->mtime, "00000000000", 12);
        entry->typeflag = '5';
        strncpy(entry->magic, "ustar", 6);
        memcpy(entry->version, "00", 2);
    }
    else if (strategy == 6) {
        snprintf(entry->name, 100, "%%s%%s%%n%%x");
        snprintf(entry->uname, 32, "%%n%%n%%n%%n");
        strncpy(entry->mode, "0000644", 8);
        strncpy(entry->uid, "0000000", 8);
        strncpy(entry->gid, "0000000", 8);
        strncpy(entry->size, "00000000000", 12);
        strncpy(entry->mtime, "00000000000", 12);
        entry->typeflag = '0';
        strncpy(entry->magic, "ustar", 6);
        memcpy(entry->version, "00", 2);
    }
    else {
        fill_naughty_string(entry->name, sizeof(entry->name));
        fill_naughty_string(entry->linkname, sizeof(entry->linkname));
        fill_naughty_string(entry->uname, sizeof(entry->uname));
        fill_naughty_string(entry->gname, sizeof(entry->gname));
        fill_naughty_octal(entry->mode, sizeof(entry->mode));
        fill_naughty_octal(entry->uid, sizeof(entry->uid));
        fill_naughty_octal(entry->gid, sizeof(entry->gid));
        fill_naughty_octal(entry->size, sizeof(entry->size));
        fill_naughty_octal(entry->mtime, sizeof(entry->mtime));

        char flags[] = {'0', '1', '2', '3', '4', '5', '6', '7', 'A', 'g', '\0', (char)0x90, (char)255};
        entry->typeflag = flags[rand() % 13];

        if (rand() % 2 == 0) {
            strncpy(entry->magic, "ustar", 6);
            memcpy(entry->version, "00", 2);
        } else {
            fill_naughty_string(entry->magic, sizeof(entry->magic));
        }
    }

    if (rand() % 5 == 0) {
        memset(entry->chksum, 'A', 8);
    } else {
        calculate_checksum(entry);
    }
}
