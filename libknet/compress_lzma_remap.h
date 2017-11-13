#include "remap.h"

REMAP_PROTO(LZMA_API(lzma_ret),lzma_easy_buffer_encode,
	    (uint32_t preset, lzma_check check,
	     const lzma_allocator *allocator,
	     const uint8_t *in, size_t in_size,
	     uint8_t *out, size_t *out_pos, size_t out_size))
REMAP_PROTO(LZMA_API(lzma_ret),lzma_stream_buffer_decode,
	    (uint64_t *memlimit, uint32_t flags,
	     const lzma_allocator *allocator,
	     const uint8_t *in, size_t *in_pos, size_t in_size,
	     uint8_t *out, size_t *out_pos, size_t out_size))
