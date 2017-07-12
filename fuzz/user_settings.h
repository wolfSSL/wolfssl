#ifndef USER_GUARD
#define USER_GUARD

/* THIS HEADER IS NOT INCLUDED IN NORMAL COMPILATION OF WOLFSSL.
 *
 * It's purpose is to make wolfSSL behave deterministically when we fuzz test
 * the library, and it is only ever compiled in when we do fuzz testing. During
 * normal compilation, a proper random number generator is used.
 */

static unsigned int zz = 0;
#define CUSTOM_RAND_GENERATE() zz++
#endif
