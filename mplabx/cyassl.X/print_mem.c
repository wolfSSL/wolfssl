void print_mem(const unsigned char *p, int size) {
    for(; size>0; size--, p++) {
        if(size%4 == 0)printf(" ") ;
            printf("%02x", (int)*p) ;
    }
    puts("") ;
    }
