void create_tar(struct tar_t *header);
void create_multi_tar(struct tar_t *headers, int num_headers);
void baseline_header(struct tar_t* entry);
void generate_header(struct tar_t* entry);
