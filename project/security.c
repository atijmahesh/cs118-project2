#include "consts.h"
#include "io.h"
#include "libsecurity.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void init_sec(int type, char* host) {
    init_io();
}

ssize_t input_sec(uint8_t* buf, size_t max_length) {
    return input_io(buf, max_length);
}

void output_sec(uint8_t* buf, size_t length) {
    output_io(buf, length);
}
