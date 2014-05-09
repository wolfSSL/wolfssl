    /* Config bits for PI32MZ, Starter Kit */
    #pragma config FPLLIDIV = DIV_1 // System PLL Input Divider (1x Divider)
    #pragma config FPLLRNG = RANGE_5_10_MHZ
    #pragma config FPLLICLK = PLL_FRC // System PLL Input Clock Selection (FRC is input to the System PLL)
    #pragma config FPLLMULT = MUL_50 // System PLL Multiplier (PLL Multiply by 50)
    #pragma config FPLLODIV = DIV_2
    // DEVCFG1
    #pragma config FNOSC = SPLL // Oscillator Selection (System PLL)
    
    #pragma config ICESEL = ICS_PGx2
        /* ICE/ICD Comm Channel Select (Communicate on PGEC2/PGED2) */