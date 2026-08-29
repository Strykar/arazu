/* SPDX-License-Identifier: Apache-2.0 */

/* Reads a PNG from memory and reports how libpng parsed its iCCP chunk.
 * The discriminator is the diagnostic libpng emits: a variant that
 * mis-parses the keyword complains about the keyword, one that parses it
 * correctly gets as far as complaining about the profile. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <png.h>

struct buf { unsigned char *p; size_t len, off; };
static void rd(png_structp png, png_bytep out, size_t n) {
    struct buf *b = (struct buf *)png_get_io_ptr(png);
    if (b->off + n > b->len) png_error(png, "short read");
    memcpy(out, b->p + b->off, n); b->off += n;
}
static void on_warn(png_structp png, png_const_charp msg) {
    (void)png; printf("  WARN  %s\n", msg);
}
static void on_err(png_structp png, png_const_charp msg) {
    printf("  ERROR %s\n", msg);
    longjmp(png_jmpbuf(png), 1);
}

int main(int argc, char **argv) {
    FILE *f = fopen(argv[1], "rb");
    if (!f) { printf("RESULT open-failed\n"); return 2; }
    static unsigned char data[1 << 16];
    struct buf b = { data, fread(data, 1, sizeof data, f), 0 };
    fclose(f);

    png_structp p = png_create_read_struct(PNG_LIBPNG_VER_STRING, 0, on_err, on_warn);
    png_infop i = png_create_info_struct(p);
    if (setjmp(png_jmpbuf(p))) { printf("RESULT aborted\n"); return 3; }
    png_set_read_fn(p, &b, rd);
    png_read_info(p, i);

    png_charp name = 0; int comp = 0; png_bytep prof = 0; png_uint_32 plen = 0;
    if (png_get_iCCP(p, i, &name, &comp, &prof, &plen) & PNG_INFO_iCCP)
        printf("RESULT iccp-accepted keyword=\"%s\" len=%u\n", name ? name : "(null)", plen);
    else
        printf("RESULT iccp-rejected\n");
    return 0;
}
