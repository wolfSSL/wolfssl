/*------------------------------------------------------------------------------
 * MDK Middleware - Component ::Network:Socket
 * Copyright (c) 2004-2013 ARM Germany GmbH. All rights reserved.
 *------------------------------------------------------------------------------
 * Name:    Net_Config_BSD.h
 * Purpose: Network Configuration BSD Sockets
 * Rev.:    V5.00
 *----------------------------------------------------------------------------*/

//-------- <<< Use Configuration Wizard in Context Menu >>> --------------------

// <h>Berkley (BSD) Sockets
#define BSD_ENABLE              1

//   <o>Number of BSD Sockets <1-20>
//   <i> Number of available Berkeley Sockets
//   <i> Default: 2
#define BSD_NUM_SOCKS           10

//   <o>Number of Streaming Server Sockets <0-20>
//   <i> Defines a number of Streaming (TCP) Server sockets,
//   <i> that listen for an incoming connection from the client.
//   <i> Default: 1
#define BSD_SERVER_SOCKS        1

//   <o>Receive Timeout in seconds <0-600>
//   <i> A timeout for socket receive in blocking mode.
//   <i> Timeout value of 0 means indefinite timeout.
//   <i> Default: 20
#define BSD_RECEIVE_TOUT        20

//   <q>Hostname Resolver
//   <i> Enable or disable Berkeley style hostname resolver.
#define BSD_HOSTNAME_ENABLE     0

// </h>
