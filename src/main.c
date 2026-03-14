#include <stdio.h>
#include <stdlib.h>
#include "tar.h"
#include "fuzzer.h"
#include "executor.h"

int main(int argc, char* argv[])
{
    if (argc < 2)
        return -1;

    struct tar_t header;
    baseline_header(&header);
    create_tar(&header);
    return extractor(argv[1]);
}