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

    int crash_found = 0;
    int attempts = 0;

    printf("Starting Hybrid Generation-Based Fuzzing on %s...\n", argv[1]);

    while (!crash_found) {
        attempts++;
        if (attempts % 500 == 0) {
            printf("Ran %d generated test cases...\n", attempts);
        }

        // Tableau pouvant contenir jusqu'à 2 headers
        struct tar_t headers[2];
        
        // Tirage au sort : 1 ou 2 headers (50% de chance chacun)
        int num_headers = (rand() % 2) + 1; 

        if (num_headers == 1) {
            // Stratégie 1 : Un seul fichier (fuzzed)
            generate_header(&headers[0]);
        } else {
            // Stratégie 2 : Deux fichiers (1 appât sain + 1 piège fuzzed)
            baseline_header(&headers[0]);
            strncpy(headers[0].name, "appat.txt", 100); 
            generate_header(&headers[1]);
        }

        // On génère l'archive avec le bon nombre de fichiers
        create_multi_tar(headers, num_headers);

        // On exécute l'extracteur dessus
        int result = extractor(argv[1]);

        if (result == 1) {
            printf("\n*** Success! Crash triggered after %d generations! ***\n", attempts);
            
            char filename[256];
            snprintf(filename, sizeof(filename), "success_%d.tar", attempts);
            
            char sys_cmd[512];
            snprintf(sys_cmd, sizeof(sys_cmd), "cp archive.tar %s", filename);
            int sys_ret = system(sys_cmd);
            (void)sys_ret; // suppress warning
            printf("Saved crashing payload to %s\n", filename);
            
            crash_found = 1;
        } else if (result == -1) {
            printf("\nExtractor failed (target program error). Stopping.\n");
            break;
        }
    }

    return 0;
}