#include <sys/stat.h>
#include <sys/time.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <time.h>

extern uint32_t _ebss;
extern uint32_t _estack;

static char* heap_end;

int _write(int file, const char* ptr, int len)
{
    (void)file;
    (void)ptr;
    return len;
}

int _close(int file)
{
    (void)file;
    return -1;
}

int _fstat(int file, struct stat* st)
{
    (void)file;
    if (st == 0) {
        errno = EINVAL;
        return -1;
    }
    st->st_mode = S_IFCHR;
    return 0;
}

int _isatty(int file)
{
    (void)file;
    return 1;
}

int _lseek(int file, int ptr, int dir)
{
    (void)file;
    (void)ptr;
    (void)dir;
    return 0;
}

int _read(int file, char* ptr, int len)
{
    (void)file;
    (void)ptr;
    (void)len;
    return 0;
}

void* _sbrk(ptrdiff_t incr)
{
    char* prev;
    char* next;

    if (heap_end == 0) {
        heap_end = (char*)&_ebss;
    }
    prev = heap_end;
    next = heap_end + incr;
    if (next >= (char*)&_estack) {
        errno = ENOMEM;
        return (void*)-1;
    }
    heap_end = next;
    return prev;
}

int _gettimeofday(struct timeval* tv, void* tzvp)
{
    (void)tzvp;
    if (tv == 0) {
        errno = EINVAL;
        return -1;
    }
    tv->tv_sec = 0;
    tv->tv_usec = 0;
    return 0;
}

time_t time(time_t* t)
{
    time_t now = 0;
    if (t != 0) {
        *t = now;
    }
    return now;
}

void _exit(int status)
{
    (void)status;
    while (1) {
        __asm volatile("wfi");
    }
}

int _kill(int pid, int sig)
{
    (void)pid;
    (void)sig;
    errno = EINVAL;
    return -1;
}

int _getpid(void)
{
    return 1;
}

void _init(void)
{
}

void _fini(void)
{
}
