/* conf.h for openssl */

struct WOLFSSL_CONF_VALUE {
    char *section;
    char *name;
    char *value;
};

struct WOLFSSL_INIT_SETTINGS {
    char* appname;
};

typedef struct WOLFSSL_CONF_VALUE CONF_VALUE;
typedef struct WOLFSSL_INIT_SETTINGS OPENSSL_INIT_SETTINGS;
