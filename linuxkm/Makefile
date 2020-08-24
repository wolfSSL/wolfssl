all: libwolfssl.ko

.PHONY: libwolfssl.ko

ifndef MODULE_TOP
MODULE_TOP=$(CURDIR)
endif

ifndef SRC_TOP
SRC_TOP=$(shell dirname $(MODULE_TOP))
endif

WOLFSSL_CFLAGS=-DHAVE_CONFIG_H -I$(SRC_TOP) -DBUILDING_WOLFSSL $(AM_CFLAGS) $(CFLAGS)
ifeq "$(KARCH)" "x86"
WOLFSSL_CFLAGS+=-msse -mmmx -msse2 -mavx -mavx2
endif

WOLFSSL_ASFLAGS=-DHAVE_CONFIG_H -I$(SRC_TOP) -DBUILDING_WOLFSSL $(AM_CCASFLAGS) $(CCASFLAGS)

WOLFSSL_OBJ_FILES=linuxkm/module_hooks.o $(patsubst %.lo, %.o, $(patsubst src/src_libwolfssl_la-%, src/%, $(patsubst src/libwolfssl_la-%, src/%, $(patsubst wolfcrypt/src/src_libwolfssl_la-%, wolfcrypt/src/%, $(src_libwolfssl_la_OBJECTS)))))

ifeq "$(ENABLED_CRYPT_TESTS)" "yes"
WOLFSSL_OBJ_FILES+=wolfcrypt/test/test.o
else
WOLFSSL_CFLAGS+=-DNO_CRYPT_TEST
endif

export WOLFSSL_CFLAGS WOLFSSL_ASFLAGS WOLFSSL_OBJ_FILES

libwolfssl.ko:
	@if test -z "$(KROOT)"; then echo '$$KROOT is unset' >&2; exit 1; fi
	@if test -z "$(AM_CFLAGS)$(CFLAGS)"; then echo '$$AM_CFLAGS and $$CFLAGS are both unset.' >&2; exit 1; fi
	@if test -z "$(src_libwolfssl_la_OBJECTS)"; then echo '$$src_libwolfssl_la_OBJECTS is unset.' >&2; exit 1; fi
	@mkdir -p linuxkm src wolfcrypt/src wolfcrypt/test
	@if test ! -h $(SRC_TOP)/Kbuild; then ln -s $(MODULE_TOP)/Kbuild $(SRC_TOP)/Kbuild; fi
	+make -C $(KROOT) M=$(MODULE_TOP) src=$(SRC_TOP)

.PHONY: clean
clean:
	+make -C $(KROOT) M=$(MODULE_TOP) src=$(SRC_TOP) clean

.PHONY: dist
dist:

.PHONY: distdir
distdir:
