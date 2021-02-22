#ifndef COMMON_TMPFS_H
#define COMMON_TMPFS_H

#include "common.h"

void copy_file_tmpfs(const char* input_path, const char* output_path);

void copy_file_tmpfs(const char* input_path, const char* output_path) {
    int fi = open_input_fd(input_path);
    size_t size;

    struct stat st;
    if (fstat(fi, &st) < 0)
        fatal_error("Failed to stat file %s: %s\n", input_path, strerror(errno));
    size = st.st_size;

    int fo = open_output_fd(output_path, false);

    if (fstat(fo, &st) < 0)
        fatal_error("Failed to stat file %s: %s\n", output_path, strerror(errno));
    if (st.st_size != 0)
        fatal_error("Size mismatch: expected 0, got %zu\n", st.st_size);

    void* data = alloc_buffer(size);
    read_fd(input_path, fi, data, size);
    printf("read_fd(%zu) input OK\n", size);
    write_fd(output_path, fo, data, size);
    printf("write_fd(%zu) output OK\n", size);
    free(data);

    if (fstat(fo, &st) < 0)
        fatal_error("Failed to stat file %s: %s\n", output_path, strerror(errno));
    if (st.st_size != size)
        fatal_error("Size mismatch: expected %zu, got %zu\n", size, st.st_size);
    printf("fstat(%zu) output 2 OK\n", size);

    close_fd(input_path, fi);
    printf("close(%zu) input OK\n", size);
    close_fd(output_path, fo);
    printf("close(%zu) output OK\n", size);
}

#endif
