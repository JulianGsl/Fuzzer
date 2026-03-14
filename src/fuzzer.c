#include <stdio.h>
#include <string.h>
#include "utils.h"
#include "tar.h"
#include "executor.h"
#include <stdlib.h>

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

// Generation-based approach
//regarder ici pour trouver des façons de crash les extracteurs
void generate_header(struct tar_t* entry) {
    //comprendre la structure du header
    // 1. Zero out the memory first
    memset(entry, 0, sizeof(struct tar_t));

    // 2. Generate fields from scratch
    generate_random_bytes(entry->name, sizeof(entry->name));
    generate_random_bytes(entry->mode, sizeof(entry->mode));
    generate_random_bytes(entry->uid, sizeof(entry->uid));
    generate_random_bytes(entry->gid, sizeof(entry->gid));
    generate_random_bytes(entry->size, sizeof(entry->size));
    generate_random_bytes(entry->mtime, sizeof(entry->mtime));
    
    entry->typeflag = (rand() % 2 == 0) ? '0' : (rand() % 256); // '0' is a normal file, or test a random flag

    generate_random_bytes(entry->linkname, sizeof(entry->linkname));
    
    // For magic, a lot of parsers check if it equals "ustar".
    // 50% of the time give it valid magic to bypass initial checks, 50% of the time give random bytes.
    if (rand() % 2 == 0) {
        strncpy(entry->magic, "ustar", 6);
        strncpy(entry->version, "00", 2);
    } else {
        generate_random_bytes(entry->magic, sizeof(entry->magic));
        generate_random_bytes(entry->version, sizeof(entry->version));
    }

    generate_random_bytes(entry->uname, sizeof(entry->uname));
    generate_random_bytes(entry->gname, sizeof(entry->gname));
    generate_random_bytes(entry->devmajor, sizeof(entry->devmajor));
    generate_random_bytes(entry->devminor, sizeof(entry->devminor));
    generate_random_bytes(entry->prefix, sizeof(entry->prefix));

    // 3. We STILL want to calculate a valid checksum! 
    calculate_checksum(entry);
}