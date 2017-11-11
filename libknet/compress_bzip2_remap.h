#include "remap.h"

REMAP_PROTO(int,BZ2_bzBuffToBuffCompress,
	    (char* dest, unsigned int* destLen,
	     char* source, unsigned int sourceLen,
	     int blockSize100k, int verbosity,
	     int workFactor))
REMAP_PROTO(int,BZ2_bzBuffToBuffDecompress,
	    (char* dest, unsigned int* destLen,
	     char* source, unsigned int sourceLen,
	     int samll, int verbosity))
