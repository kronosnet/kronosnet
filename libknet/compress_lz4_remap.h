#include "remap.h"

REMAP_PROTO(int,LZ4_compress_HC,
	    (const char* src, char* dst,
	     int srcSize, int dstCapacity,
	     int compressionLevel))
REMAP_PROTO(int,LZ4_compress_fast,
	    (const char* source, char* dest,
	     int sourceSize, int maxDestSize,
	     int acceleration))
REMAP_PROTO(int,LZ4_decompress_safe,
	    (const char* source, char* dest,
	     int compressedSize, int maxDecompressedSize))
