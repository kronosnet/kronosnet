/* Transform the binary into dependencies like:
 * dpkg-shlibdeps -pcompress -dSuggests -xlibc6 -elibknet/compress_canary
 */

#include "config.h"

char BZ2_bzBuffToBuffCompress(void);
char LZ4_compress_HC(void);
char lzma_easy_buffer_encode(void);
char lzo1x_1_compress(void);
char compress2(void);

int main (void)
{
  return
#ifdef BUILDCOMPBZIP2
    BZ2_bzBuffToBuffCompress() +
#endif
#ifdef BUILDCOMPLZ4
    LZ4_compress_HC() +
#endif
#ifdef BUILDCOMPLZMA
    lzma_easy_buffer_encode() +
#endif
#ifdef BUILDCOMPLZO2
    lzo1x_1_compress() +
#endif
#ifdef BUILDCOMPZLIB
    compress2() +
#endif
    0;
}
