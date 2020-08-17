/* http://h-wrt.com/en/mini-how-to/autotoolsSimpleModule */

/*  src/module_hello.c */

#include <linux/init.h>
#include <linux/module.h>

static int __init
hello_init(void)
{
   printk("Hello, world!\n");
   return 0;
}

module_init(hello_init);

static void __exit
hello_exit(void)
{
   printk("Goodbye, world!\n");
}

module_exit(hello_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("noname ");
MODULE_DESCRIPTION("\"Hello, world!\" test module");
MODULE_VERSION("printk");
