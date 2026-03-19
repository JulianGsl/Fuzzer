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

        // On alloue un grand tableau de 100 headers
        struct tar_t headers[100];
        int num_headers = 0;
        
        // Tirage au sort stratégique (Probabilités)
        int chance = rand() % 100; 

        if (chance < 10) {
            // 10% de chance : 0 header ! Juste une archive vide.
            num_headers = 0; 
        } 
        else if (chance < 40) {
            // 30% de chance : 1 seul header
            num_headers = 1;
            generate_header(&headers[0]);
        } 
        else if (chance < 70) {
            // 30% de chance : 2 headers (L'attaque de l'appât)
            num_headers = 2;
            baseline_header(&headers[0]);
            strncpy(headers[0].name, "appat.txt", 100); 
            generate_header(&headers[1]);
        } 
        else {
            // 30% de chance : L'INVASION MASSIVE (entre 10 et 100 headers)
            num_headers = (rand() % 91) + 10; 
            for (int i = 0; i < num_headers; i++) {
                if (i % 2 == 0) {
                    baseline_header(&headers[i]); // On alterne le chaud...
                    snprintf(headers[i].name, 100, "appat_%d.txt", i);
                } else {
                    generate_header(&headers[i]); // ... et le froid !
                }
            }
        }

        // On génère l'archive
        create_tar(headers, num_headers);

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