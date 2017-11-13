#include "remap.h"

REMAP_PROTO(int,uncompress,
	    (Bytef *dest, uLongf *destLen,
	     const Bytef *source, uLong sourceLen))
REMAP_PROTO(int,compress2,
	    (Bytef *dest, uLongf *destLen,
	     const Bytef *source, uLong sourceLen,
	     int level))
