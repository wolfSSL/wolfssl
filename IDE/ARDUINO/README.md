### wolfSSL with Arduino

##### Reformatting wolfSSL as a compatible Arduino Library
This is a shell script that will re-organize the wolfSSL library to be 
compatible with Arduino projects. The Arduino IDE requires a library's source
files to be in the library's root directory with a header file in the name of 
the library. This script moves all src/ files to the root wolfssl directory and 
creates a stub header file called wolfssl.h.

To configure wolfSSL with Arduino, enter the following from within the 
wolfssl/IDE/ARDUINO directory:

    ./wolfssl-arduino.sh
    
#####Including wolfSSL in Arduino Libraries (for Arduino version 1.6.6)
1. Copy the wolfSSL directory into Arduino/libraries (or wherever Arduino searches for libraries).
2. In the Arduino IDE:
    - Go to ```Sketch > Include Libraries > Manage Libraries```. This refreshes your changes to the libraries.
    - Next go to ```Sketch > Include Libraries > wolfSSL```. This includes wolfSSL in your sketch.
