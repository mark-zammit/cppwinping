
/***********************************************************************
 rawping.h - Declares the types, constants and prototypes required to
    use the rawping.cpp module.
***********************************************************************/


/* Contributor  : Mark Zammit
 * Changes      :
 *      - Changed WSASocket() method to socket() since
 *          WSASocket() doesn't support timeouts on requests.
 *      - Added recv/send timeouts for unresponsive/non-existent
 *          hosts. This can be supplied in the setup phase.
 *      - Added a pingreq struct which is basically an information
 *          struct for each ping request made.
 *      - Added some more documentation for compiling purposes as well
 *          as checks for winsock2 availability.
 *      - Added a compiler check for MSVC to avoid confusing compiling errors.
 */

#ifndef _RAWPING_H_
#define _RAWPING_H_

#if !defined(_MSC_VER)
#error winfs.h only supported by MSVC Compiler 2005+
#endif

#define WIN32_LEAN_AND_MEAN
#include <ws2tcpip.h>

// In case winsock has already been included, this prevents redef errors
// Make sure that
#if defined(__USE_W32_SOCKETS) || !(defined(__CYGWIN__) || defined(__MSYS__) || defined(_UWIN))
#if (_WIN32_WINNT >= 0x0400)
#include <winsock2.h>
/*
 * MS likes to include winsock.h here as well,
 * but that can cause undefined symbols if
 * winsock2.h is included before windows.h
 */
#else
#error Rawping is not Winsock 1.1 compliant, remove winsock.h reference to resolve this error.
#endif /*  (_WIN32_WINNT >= 0x0400) */
#endif
#include <tchar.h>
#include <cstdlib>

#pragma comment(lib,"Ws2_32.lib")

// ICMP packet types
#define ICMP_ECHO_REPLY     0
#define ICMP_DEST_UNREACH   3
#define ICMP_TTL_EXPIRE     11
#define ICMP_ECHO_REQUEST   8

// Minimum ICMP packet size, in bytes
#define ICMP_MIN            8

#ifdef _MSC_VER
// The following two structures need to be packed tightly, but unlike
// Borland C++, Microsoft C++ does not do this by default.
#pragma pack(1)
#endif

#define WSASUCCESS                  0x00000000
#define EINVALID_HOSTNAME           0xe0000000
#define ETOO_FEW_BYTES              0xe1100000
#define EPACKET_SIZE_OUT_OF_BOUNDS  0xe1200000
#define ETTL_EXPIRED                0xe2100000
#define ETTL_SIZE_OUT_OF_BOUNDS     0xe2200000
#define EUNKNOWN_ICMP_PACKET        0xe3000000
#define EBUFFER_ALLOCATION_FAILED   0xe4000000
#define EWINSOCK_VERSION            0xef000000

// Defines Winsock version requirements
//  e.g. Winsock 2.1:
//          WINSOCK_VER_REQ_HIH = 2
//          WINSOCK_VER_REQ_LOW = 1
#define WINSOCK_VER_REQ_HIGH        2
#define WINSOCK_VER_REQ_LOW         1

/* COMMON WSA ERROR CODES RETURNED
 *  Global Codes :
 *      WSANOTINITIALISED
 *  Socket Codes :
 *      WSAENETDOWN
 *      WSAEAFNOSUPPORT
 *      WSAEFAULT
 *      WSAEINPROGRESS
 *      WSAEINVAL
 *      WSAEMFILE
 *      WSAENOBUFS
 *      WSAENETRESET
 *      WSAEPROTONOSUPPORT
 *      WSAEPROTOTYPE
 *      WSAEPROVIDERFAILEDINIT
 *      WSAENOPROTOOPT
 *      WSAENOTCONN
 *      WSAENOTSOCK
 *      WSAESOCKTNOSUPPORT
 *      WSAINVALIDPROVIDER
 *      WSAINVALIDPROCTABLE
 *  Connection Codes :
 *      WSAHOST_NOT_FOUND
 *      WSAEHOSTDOWN
 *      WSAEHOSTUNREACH
 *      WSATRY_AGAIN
 *  Read Codes :
 *      WSAEISCONN
 *      WSAEOPNOTSUPP
 *      WSAESHUTDOWN
 *      WSAEWOULDBLOCK
 *      WSAEMSGSIZE
 *      WSAETIMEDOUT
 *      WSAECONNRESET
 */

#define DEFAULT_PACKET_SIZE     32
#define DEFAULT_TTL             30
#define MAX_PING_DATA_SIZE      1024
#define MAX_TTL                 255
#define MAX_PING_PACKET_SIZE    (MAX_PING_DATA_SIZE + sizeof(IPHeader))

// The IP header
struct IPHeader {
    BYTE h_len:4;           // Length of the header in dwords
    BYTE version:4;         // Version of IP
    BYTE tos;               // Type of service
    USHORT total_len;       // Length of the packet in dwords
    USHORT ident;           // unique identifier
    USHORT flags;           // Flags
    BYTE ttl;               // Time to live
    BYTE proto;             // Protocol number (TCP, UDP etc)
    USHORT checksum;        // IP checksum
    ULONG source_ip;
    ULONG dest_ip;
};

// ICMP header
struct ICMPHeader {
    BYTE type;          // ICMP packet type
    BYTE code;          // Type sub code
    USHORT checksum;
    USHORT id;
    USHORT seq;
    ULONG timestamp;    // not part of ICMP, but we need it
};


typedef struct _ping_req_ {
    char *  hostname;
    char *  addr;
    DWORD   packet_size;
    DWORD   bytes_recv;
    DWORD   bytes_sent;
    DWORD   ttl;
    DWORD   hops;
    DWORD   seq;
    DWORD   timems;

    _ping_req_() : bytes_recv(0), bytes_sent(0),
                   packet_size(0), ttl(0), hops(0),
                   seq(0), timems(0),
                   hostname(NULL), addr(NULL) {}
    ~_ping_req_() {
        hostname ? free(hostname) : 0;
        addr ? free(addr) : 0;
    }
} pingreq;

#ifdef _MSC_VER
#pragma pack()
#endif

extern int  allocate_buffers(ICMPHeader*& send_buf, IPHeader*& recv_buf, int packet_size);
extern int  setup_for_ping(const char* host, int ttl, SOCKET& sd, sockaddr_in& dest, int timeout, pingreq* results);
extern int  send_ping(SOCKET sd, const sockaddr_in& dest, ICMPHeader* send_buf, int packet_size, pingreq* results);
extern int  recv_ping(SOCKET sd, sockaddr_in& source, IPHeader* recv_buf, int packet_size, pingreq* results);
extern int  decode_reply(IPHeader* reply, int bytes, sockaddr_in* from, pingreq* results);
extern void init_ping_packet(ICMPHeader* icmp_hdr, int packet_size, int seq_no, pingreq* results);

#endif /* _RAWPING_H_ */
