/*------------------------------------------------------------------------------
 * MDK Middleware - Component ::Network:Interface
 * Copyright (c) 2004-2013 ARM Germany GmbH. All rights reserved.
 *------------------------------------------------------------------------------
 * Name:    Net_Config_ETH_0.h
 * Purpose: Network Configuration ETH Interface
 * Rev.:    V5.00
 *----------------------------------------------------------------------------*/

//-------- <<< Use Configuration Wizard in Context Menu >>> --------------------

// <h>Ethernet Network Interface 0
#define ETH0_ENABLE             1

//   <o>Connect to hardware via Driver_ETH# <0-255>
//   <i>Select driver control block for MAC and PHY interface
#define ETH0_DRIVER             1

//   <h>MAC Address
//   <i> Local Ethernet MAC Address
//   <i> Value FF:FF:FF:FF:FF:FF is not allowed.
//   <i> It is an ethernet Broadcast MAC address.
//     <o>Address byte 1 <0x00-0xff:2>
//     <i> LSB is an ethernet Multicast bit.
//     <i> Must be 0 for local MAC address.
//     <i> Default: 0x1E
#define ETH0_MAC1               0x1E

//     <o>Address byte 2 <0x00-0xff>
//     <i> Default: 0x30
#define ETH0_MAC2               0x30

//     <o>Address byte 3 <0x00-0xff>
//     <i> Default: 0x6C
#define ETH0_MAC3               0x6C

//     <o>Address byte 4 <0x00-0xff>
//     <i> Default: 0xA2
#define ETH0_MAC4               0xA2

//     <o>Address byte 5 <0x00-0xff>
//     <i> Default: 0x45
#define ETH0_MAC5               0x45

//     <o>Address byte 6 <0x00-0xff>
//     <i> Default: 0x5E
#define ETH0_MAC6               0x5E
//   </h>

//   <h>IP Address
//   <i> Local Static IP Address
//   <i> Value 255.255.255.255 is not allowed.
//   <i> It is a Broadcast IP address.
//     <o>Address byte 1 <0-255>
//     <i> Default: 192
#define ETH0_IP1                192

//     <o>Address byte 2 <0-255>
//     <i> Default: 168
#define ETH0_IP2                168

//     <o>Address byte 3 <0-255>
//     <i> Default: 0
#define ETH0_IP3                0

//     <o>Address byte 4 <0-255>
//     <i> Default: 100
#define ETH0_IP4                100
//   </h>

//   <h>Subnet mask
//   <i> Local Subnet mask
//     <o>Mask byte 1 <0-255>
//     <i> Default: 255
#define ETH0_MASK1              255

//     <o>Mask byte 2 <0-255>
//     <i> Default: 255
#define ETH0_MASK2              255

//     <o>Mask byte 3 <0-255>
//     <i> Default: 255
#define ETH0_MASK3              255

//     <o>Mask byte 4 <0-255>
//     <i> Default: 0
#define ETH0_MASK4              0
//   </h>

//   <h>Default Gateway
//   <i> Default Gateway IP Address
//     <o>Address byte 1 <0-255>
//     <i> Default: 192
#define ETH0_GW1                192

//     <o>Address byte 2 <0-255>
//     <i> Default: 168
#define ETH0_GW2                168

//     <o>Address byte 3 <0-255>
//     <i> Default: 0
#define ETH0_GW3                0

//     <o>Address byte 4 <0-255>
//     <i> Default: 254
#define ETH0_GW4                254
//   </h>

//   <h>Primary DNS Server
//   <i> Primary DNS Server IP Address
//     <o>Address byte 1 <0-255>
//     <i> Default: 194
#define ETH0_PRI_DNS1           194

//     <o>Address byte 2 <0-255>
//     <i> Default: 25
#define ETH0_PRI_DNS2           25

//     <o>Address byte 3 <0-255>
//     <i> Default: 2
#define ETH0_PRI_DNS3           2

//     <o>Address byte 4 <0-255>
//     <i> Default: 129
#define ETH0_PRI_DNS4           129
//   </h>

//   <h>Secondary DNS Server
//   <i> Secondary DNS Server IP Address
//     <o>Address byte 1 <0-255>
//     <i> Default: 194
#define ETH0_SEC_DNS1           194

//     <o>Address byte 2 <0-255>
//     <i> Default: 25
#define ETH0_SEC_DNS2           25

//     <o>Address byte 3 <0-255>
//     <i> Default: 2
#define ETH0_SEC_DNS3           2

//     <o>Address byte 4 <0-255>
//     <i> Default: 130
#define ETH0_SEC_DNS4           130
//   </h>

//   <h>ARP Definitions
//   <i> Address Resolution Protocol Definitions
//     <o>Cache Table size <5-100>
//     <i> Number of cached hardware/IP addresses
//     <i> Default: 10
#define ETH0_ARP_TAB_SIZE       10

//     <o>Cache Timeout in seconds <5-255>
//     <i> A timeout for a cached hardware/IP addresses
//     <i> Default: 150
#define ETH0_ARP_CACHE_TOUT     150

//     <o>Number of Retries <0-20>
//     <i> Number of Retries to resolve an IP address
//     <i> before ARP module gives up
//     <i> Default: 4
#define ETH0_ARP_MAX_RETRY      4

//     <o>Resend Timeout in seconds <1-10>
//     <i> A timeout to resend the ARP Request
//     <i> Default: 2
#define ETH0_ARP_RESEND_TOUT    2

//     <q>Send Notification on Address changes
//     <i> When this option is enabled, the embedded host
//     <i> will send a Gratuitous ARP notification at startup,
//     <i> or when the device IP address has changed.
//     <i> Default: Disabled
#define ETH0_ARP_NOTIFY         0
//   </h>

//   <e>IGMP Group Management
//   <i> Enable or disable Internet Group Management Protocol
#define ETH0_IGMP_ENABLE        0

//     <o>Membership Table size <2-50>
//     <i> Number of Groups this host can join
//     <i> Default: 5
#define ETH0_IGMP_TAB_SIZE      5
//   </e>

//   <q>NetBIOS Name Service
//   <i> When this option is enabled, the embedded host can be
//   <i> accessed by his name on the local LAN using NBNS protocol.
//   <i> You need to modify also the number of UDP Sockets,
//   <i> because NBNS protocol uses one UDP socket to run.
#define ETH0_NBNS_ENABLE        1

//   <e>Dynamic Host Configuration
//   <i> When this option is enabled, local IP address, Net Mask
//   <i> and Default Gateway are obtained automatically from
//   <i> the DHCP Server on local LAN.
//   <i> You need to modify also the number of UDP Sockets,
//   <i> because DHCP protocol uses one UDP socket to run.
#define ETH0_DHCP_ENABLE        1

//     <s.40>Vendor Class Identifier
//     <i> This value is optional. If specified, it is added
//     <i> to DHCP request message, identifying vendor type.
//     <i> Default: ""
#define ETH0_DHCP_VCID          ""

//     <q>Bootfile Name
//     <i> This value is optional. If enabled, the Bootfile Name
//     <i> (option 67) is also requested from DHCP server.
//     <i> Default: disabled
#define ETH0_DHCP_BOOTFILE      0

//     <q>NTP Servers
//     <i> This value is optional. If enabled, a list of NTP Servers
//     <i> (option 42) is also requested from DHCP server.
//     <i> Default: disabled
#define ETH0_DHCP_NTP_SERVERS   0
//   </e>

// </h>
