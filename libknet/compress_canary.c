/* Transform the binary into dependencies like:
 * dpkg-shlibdeps -pcompress -dSuggests -xlibc6 -elibknet/compress_canary
 */

#include "config.h"

#define CANARY

#include "compress_bzip2_remap.h"
#include "compress_lz4_remap.h"
#include "compress_lzma_remap.h"
#include "compress_lzo2_remap.h"
#include "compress_zlib_remap.h"

#define CANARY_CALL

int main (void)
{
  return
#ifdef BUILDCOMPBZIP2
#include "compress_bzip2_remap.h"
#endif
#ifdef BUILDCOMPLZ4
#include "compress_lz4_remap.h"
#endif
#ifdef BUILDCOMPLZMA
#include "compress_lzma_remap.h"
#endif
#ifdef BUILDCOMPLZO2
#include "compress_lzo2_remap.h"
#endif
#ifdef BUILDCOMPZLIB
#include "compress_zlib_remap.h"
#endif
    0;
}
