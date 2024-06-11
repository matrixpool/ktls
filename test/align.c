#include <stdio.h>

#define __ALIGN_KERNEL_MASK(x, mask)	(((x) + (mask)) & ~(mask))
#define __ALIGN_KERNEL(x, a)		__ALIGN_KERNEL_MASK(x, (__typeof__(x))(a) - 1)
#define ALIGN(x, a)		__ALIGN_KERNEL((x), (a))

int  main(){
    printf("%d\n", ALIGN(15, 8));
}