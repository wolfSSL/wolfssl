/* conf.h for openssl */

struct WOLFSSL_CONF_VALUE {
    char *section;
    char *name;
    char *value;
};

struct WOLFSSL_INIT_SETTINGS {
    char* appname;
};

typedef WOLFSSL_CONF_VALUE CONF_VALUE;
typedef WOLFSSL_INIT_SETTINGS OPENSSL_INIT_SETTINGS;
