/* unit.c unit tests driver */
#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <cyassl/ctaocrypt/settings.h>

#include <stdio.h>
#include <tests/unit.h>


int myoptind = 0;
char* myoptarg = NULL;


int main(int argc, char** argv)
{
    int ret;

    (void)argc;
    (void)argv;
    printf("starting unit tests...\n");

#ifdef HAVE_CAVIUM
    ret = OpenNitroxDevice(CAVIUM_DIRECT, CAVIUM_DEV_ID);
    if (ret != 0)
        err_sys("Cavium OpenNitroxDevice failed");
#endif /* HAVE_CAVIUM */

    if (CurrentDir("tests"))
        ChangeDirBack(1);
    else if (CurrentDir("build"))
        ChangeDirBack(2);

    if ( (ret = ApiTest()) != 0) {
        printf("api test failed with %d\n", ret);
        return ret;
    }

    if ( (ret = HashTest()) != 0){
        printf("hash test failed with %d\n", ret);
        return ret;
    }

    if ( (ret = SuiteTest()) != 0){
        printf("suite test failed with %d\n", ret);
        return ret;
    }

#ifdef HAVE_CAVIUM
        CspShutdown(CAVIUM_DEV_ID);
#endif

    return 0;
}


void wait_tcp_ready(func_args* args)
{
#if defined(_POSIX_THREADS) && !defined(__MINGW32__)
    pthread_mutex_lock(&args->signal->mutex);
    
    if (!args->signal->ready)
        pthread_cond_wait(&args->signal->cond, &args->signal->mutex);
    args->signal->ready = 0; /* reset */

    pthread_mutex_unlock(&args->signal->mutex);
#else
    (void)args;
#endif
}


void start_thread(THREAD_FUNC fun, func_args* args, THREAD_TYPE* thread)
{
#if defined(_POSIX_THREADS) && !defined(__MINGW32__)
    pthread_create(thread, 0, fun, args);
    return;
#else
    *thread = (THREAD_TYPE)_beginthreadex(0, 0, fun, args, 0, 0);
#endif
}


void join_thread(THREAD_TYPE thread)
{
#if defined(_POSIX_THREADS) && !defined(__MINGW32__)
    pthread_join(thread, 0);
#else
    int res = WaitForSingleObject((HANDLE)thread, INFINITE);
    assert(res == WAIT_OBJECT_0);
    res = CloseHandle((HANDLE)thread);
    assert(res);
#endif
}


void InitTcpReady(tcp_ready* ready)
{
    ready->ready = 0;
    ready->port = 0;
#if defined(_POSIX_THREADS) && !defined(__MINGW32__)
      pthread_mutex_init(&ready->mutex, 0);
      pthread_cond_init(&ready->cond, 0);
#endif
}


void FreeTcpReady(tcp_ready* ready)
{
#if defined(_POSIX_THREADS) && !defined(__MINGW32__)
    pthread_mutex_destroy(&ready->mutex);
    pthread_cond_destroy(&ready->cond);
#else
    (void)ready;
#endif
}
