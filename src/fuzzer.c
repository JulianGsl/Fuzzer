#include <stdio.h>
#include <string.h>
#include "utils.h"
#include "tar.h"
#include "executor.h"

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

// Create a baseline header with valid values and checksum
void baseline_header(struct tar_t* entry) {
    memset(entry, 0, sizeof(struct tar_t));

    strncpy(entry->name, "test.txt", 100);
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