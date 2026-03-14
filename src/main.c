#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "tar.h"
#include "fuzzer.h"
#include "executor.h"

int main(int argc, char* argv[])
{
    if (argc < 2) {
        printf("Usage: %s <path_to_target>\n", argv[0]);
        return -1;
    }

    // Initialize random seed based on clock
    srand((unsigned int)time(NULL));

    struct tar_t header;
    int crash_found = 0;
    int attempts = 0;

    printf("Starting Generation-Based Fuzzing on %s...\n", argv[1]);

    while (!crash_found) {
        attempts++;
        if (attempts % 500 == 0) {
            printf("Ran %d generated test cases...\n", attempts);
        }

        // 1. Generer un nouveau header malicieux
        generate_header(&header);

        // 2. l'écrire dans le tar
        create_tar(&header);

        // 3. executer l'extracteur dessus
        int result = extractor(argv[1]);

        if (result == 1) {
            printf("\n*** Success! Crash triggered after %d generations! ***\n", attempts);
            crash_found = 1;
        } else if (result == -1) {
            printf("\nExtractor failed (target program error). Stopping.\n");
            break;
        }
    }

    return 0;
}