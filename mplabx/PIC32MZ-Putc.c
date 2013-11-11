
#ifdef MICROCHIP_PIC32
#if defined (__32MZ2048ECH144__) || defined (__32MZ2048ECM144__)
void _mon_putc (char c)
{
    while (U2STAbits.UTXBF);
    U2TXREG = c;
}
#endif
#endif