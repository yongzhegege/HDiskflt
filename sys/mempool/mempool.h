#ifndef mempool_h__
#define mempool_h__

#include <ntifs.h>

#ifdef __cplusplus
extern "C" {
#endif

/** tag for memory blocks */
//lint -e742
#define MEM_TAG		'1VRD'


#define mempool_init()
#define mempool_fini()

#define __malloc(size)	ExAllocatePoolWithTag(NonPagedPool, (size), MEM_TAG)
#define __free(ptr)	    ExFreePoolWithTag((ptr), MEM_TAG)

#define mt_malloc(size, file, line) __malloc(size)
#define mt_free(ptr) __free(ptr)
#define mempool_malloc(size) __malloc(size)
#define mempool_free(ptr) __free(ptr)

#ifdef __cplusplus
} // extern "C"
#endif
#endif // mempool_h__