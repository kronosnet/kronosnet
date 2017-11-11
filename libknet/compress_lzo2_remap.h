#include "remap.h"

REMAP_PROTO(int,lzo1x_decompress,
	    (const lzo_bytep src, lzo_uint src_len,
	     lzo_bytep dst, lzo_uintp dst_len,
	     lzo_voidp wrkmem /* NOT USED */ ))
REMAP_PROTO(int,lzo1x_1_compress,
	    (const lzo_bytep src, lzo_uint src_len,
	     lzo_bytep dst, lzo_uintp dst_len,
	     lzo_voidp wrkmem))
REMAP_PROTO(int,lzo1x_1_11_compress,
	    (const lzo_bytep src, lzo_uint src_len,
	     lzo_bytep dst, lzo_uintp dst_len,
	     lzo_voidp wrkmem))
REMAP_PROTO(int,lzo1x_1_12_compress,
	    (const lzo_bytep src, lzo_uint src_len,
	     lzo_bytep dst, lzo_uintp dst_len,
	     lzo_voidp wrkmem))
REMAP_PROTO(int,lzo1x_1_15_compress,
	    (const lzo_bytep src, lzo_uint src_len,
	     lzo_bytep dst, lzo_uintp dst_len,
	     lzo_voidp wrkmem))
REMAP_PROTO(int,lzo1x_999_compress,
	    (const lzo_bytep src, lzo_uint src_len,
	     lzo_bytep dst, lzo_uintp dst_len,
	     lzo_voidp wrkmem))
