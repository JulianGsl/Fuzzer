#ifndef FUZZER_H
#define FUZZER_H

#include "tar.h"

void create_tar(struct tar_t *headers, int num_headers);
void baseline_header(struct tar_t* entry);
void generate_header(struct tar_t* entry);

#endif
