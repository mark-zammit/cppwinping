/***********************************************************************
 rawping.cpp - Contains all of the functions essential to sending "ping"
    packets using Winsock 2 raw sockets.  Depends on ip_checksum.cpp for
    calculating IP-style checksums on blocks of data, however.
***********************************************************************/

#include <rawping.h>
#include <ip_checksum.h>
#include <iostream>

/////////////////////////// allocate_buffers ///////////////////////////
// Allocates send and receive buffers.  Returns < 0 for failure.

int allocate_buffers(ICMPHeader*& send_buf, IPHeader*& recv_buf,
                        int packet_size)
{
    // First the send buffer
    if ((send_buf = (ICMPHeader*)new char[packet_size]) == NULL)
        return EBUFFER_ALLOCATION_FAILED;

    // And then the receive buffer
    if ((recv_buf = (IPHeader*)new char[MAX_PING_PACKET_SIZE]) == NULL)
        return EBUFFER_ALLOCATION_FAILED;

    return WSASUCCESS;
}

//////////////////////////// setup_for_ping ////////////////////////////
// Creates the Winsock structures necessary for sending and recieving
// ping packets.  host can be either a dotted-quad IP address, or a
// host name.  ttl is the time to live (a.k.a. number of hops) for the
// packet.  The other two parameters are outputs from the function.
// Returns < 0 for failure.

int setup_for_ping(const char* host, int ttl, SOCKET& sd, sockaddr_in& dest,
                    int timeout, pingreq* pr)
{
    // Create the socket
    sd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sd == INVALID_SOCKET)
        return WSAGetLastError();

    if (setsockopt(sd, IPPROTO_IP, IP_TTL, (const char*)&ttl,
            sizeof(ttl)) == SOCKET_ERROR)
        return WSAGetLastError();

    // Sets recv timeout
    if (setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout,
            sizeof(timeout)) == SOCKET_ERROR)
        return WSAGetLastError();
    // Sets send timeout
    if (setsockopt(sd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout,
            sizeof(timeout)) == SOCKET_ERROR)
        return WSAGetLastError();

    // Initialize the destination host info block
    memset(&dest, 0, sizeof(dest));

    // Turn first passed parameter into an IP address to ping
    unsigned int addr = inet_addr(host);
    if (addr != INADDR_NONE) {
        // It was a dotted quad number, so save result
        dest.sin_addr.s_addr = addr;
        dest.sin_family = AF_INET;
    }
    else {
        // Not in dotted quad form, so try and look it up
        hostent* hp = gethostbyname(host);
        if (hp != 0) {
            // Found an address for that host, so save it
            memcpy(&(dest.sin_addr), hp->h_addr, hp->h_length);
            dest.sin_family = hp->h_addrtype;
        }
        else {
            // Not a recognized hostname either!
            return WSAHOST_NOT_FOUND;
        }
    }

    if(pr)
    {
        // In format of ???.???.???.???
        if (addr != INADDR_NONE)
        {
            char buf[100];
            sprintf_s(buf, 100, "%d.%d.%d.%d",
                      (addr >> 0 ) & 0xff,
                      (addr >> 8 ) & 0xff,
                      (addr >> 16) & 0xff,
                      (addr >> 24) & 0xff);
            // Makes a copy of the host address name being pinged
            pr->addr = (char*)malloc(strlen(buf)+1);
            memcpy(pr->addr, buf, strlen(buf));
            pr->addr[strlen(buf)] = '\0';

            hostent* hp = gethostbyaddr((char*)&addr,sizeof(addr),AF_INET);
            if(hp != 0)
            {
                // Makes a copy of the host address name being pinged
                pr->hostname = (char*)malloc(strlen(hp->h_name)+1);
                memcpy(pr->hostname, hp->h_name, strlen(hp->h_name));
                pr->hostname[strlen(hp->h_name)] = '\0';
            }
        }
        // In resolved name format
        else
        {
            // Makes a copy of the host name being pinged
            pr->hostname = (char*)malloc(strlen(host)+1);
            memcpy(pr->hostname, host, strlen(host));
            pr->hostname[strlen(host)] = '\0';

            hostent* hp = gethostbyname(host);
            if(hp != 0)
            {
                char buf[16];
                sprintf_s(buf, 16, "%d.%d.%d.%d",
                          hp->h_addr[0] & 0xff,
                          hp->h_addr[1] & 0xff,
                          hp->h_addr[2] & 0xff,
                          hp->h_addr[3] & 0xff);
                // Makes a copy of the host address name being pinged
                pr->addr = (char*)malloc(strlen(buf)+1);
                memcpy(pr->addr, buf, strlen(buf));
                pr->addr[strlen(buf)] = '\0';
            }
        }
    }

    return WSASUCCESS;
}



/////////////////////////// init_ping_packet ///////////////////////////
// Fill in the fields and data area of an ICMP packet, making it
// packet_size bytes by padding it with a byte pattern, and giving it
// the given sequence number.  That completes the packet, so we also
// calculate the checksum for the packet and place it in the appropriate
// field.

void init_ping_packet(ICMPHeader* icmp_hdr, int packet_size, int seq_no,
                        pingreq * pr)
{
    // Set up the packet's fields
    icmp_hdr->type = ICMP_ECHO_REQUEST;
    icmp_hdr->code = 0;
    icmp_hdr->checksum = 0;
    icmp_hdr->id = (USHORT)GetCurrentProcessId();
    icmp_hdr->seq = seq_no;
    icmp_hdr->timestamp = GetTickCount();

    pr ? (pr->packet_size = packet_size) : 0;

    // "You're dead meat now, packet!"
    const unsigned long int deadmeat = 0xDEADBEEF;
    char* datapart = (char*)icmp_hdr + sizeof(ICMPHeader);
    int bytes_left = packet_size - sizeof(ICMPHeader);
    while (bytes_left > 0) {
        memcpy(datapart, &deadmeat, min(int(sizeof(deadmeat)),
                bytes_left));
        bytes_left -= sizeof(deadmeat);
        datapart += sizeof(deadmeat);
    }

    // Calculate a checksum on the result
    icmp_hdr->checksum = ip_checksum((USHORT*)icmp_hdr, packet_size);
}


/////////////////////////////// send_ping //////////////////////////////
// Send an ICMP echo ("ping") packet to host dest by way of sd with
// packet_size bytes.  packet_size is the total size of the ping packet
// to send, including the ICMP header and the payload area; it is not
// checked for sanity, so make sure that it's at least
// sizeof(ICMPHeader) bytes, and that send_buf points to at least
// packet_size bytes.  Returns < 0 for failure.

int send_ping(SOCKET sd, const sockaddr_in& dest, ICMPHeader* send_buf,
                int packet_size, pingreq* pr)
{
    send_buf->timestamp = GetTickCount();
    // Send the ping packet in send_buf as-is
    int bwrote = sendto(sd, (char*)send_buf, packet_size, 0,
            (sockaddr*)&dest, sizeof(dest));

    if (bwrote == SOCKET_ERROR)
        return WSAGetLastError();

    pr ? (pr->bytes_sent = bwrote) : 0;

    return WSASUCCESS;
}


/////////////////////////////// recv_ping //////////////////////////////
// Receive a ping reply on sd into recv_buf, and stores address info
// for sender in source.  On failure, returns < 0, 0 otherwise.
//
// Note that recv_buf must be larger than send_buf (passed to send_ping)
// because the incoming packet has the IP header attached.  It can also
// have IP options set, so it is not sufficient to make it
// sizeof(send_buf) + sizeof(IPHeader).  We suggest just making it
// fairly large and not worrying about wasting space.

int recv_ping(SOCKET sd, sockaddr_in& source, IPHeader* recv_buf,
                int packet_size, pingreq* pr)
{
    // Wait for the ping reply
    int fromlen = sizeof(source);
    int bread = recvfrom(sd, (char*)recv_buf,
            packet_size + sizeof(IPHeader), 0,
            (sockaddr*)&source, &fromlen);

    if (bread == SOCKET_ERROR)
        return WSAGetLastError();

    pr ? (pr->bytes_recv = bread) : 0;

    return WSASUCCESS;
}


///////////////////////////// decode_reply /////////////////////////////
// Decode and output details about an ICMP reply packet.  Returns -1
// on failure, -2 on "try again" and 0 on success.

int decode_reply(IPHeader* reply, int bytes, sockaddr_in* from, pingreq* pr)
{
    // Skip ahead to the ICMP header within the IP packet
    unsigned short header_len = reply->h_len * 4;
    ICMPHeader* icmphdr = (ICMPHeader*)((char*)reply + header_len);

    // Make sure the reply is sane
    if (bytes < header_len + ICMP_MIN) {
        return ETOO_FEW_BYTES ^ bytes;
    }
    else if (icmphdr->type != ICMP_ECHO_REPLY) {
        if (icmphdr->type != ICMP_TTL_EXPIRE) {
            if (icmphdr->type == ICMP_DEST_UNREACH)
                return WSAEHOSTUNREACH;
            else
                return EUNKNOWN_ICMP_PACKET ^ (int(icmphdr->type) & 0xffff);
        }
        // If "TTL expired", fall through.  Next test will fail if we
        // try it, so we need a way past it.
    }
    else if (icmphdr->id != (USHORT)GetCurrentProcessId()) {
        // Must be a reply for another pinger running locally, so just
        // ignore it.
        return WSATRY_AGAIN;
    }

    // Figure out how far the packet travelled
    int nHops = int(256 - reply->ttl);
    if (nHops == 192) {
        // TTL came back 64, so ping was probably to a host on the
        // LAN -- call it a single hop.
        nHops = 1;
    }
    else if (nHops == 128) {
        // Probably localhost
        nHops = 0;
    }

    // Okay, we ran the gamut, so the packet must be legal -- dump it
    pr ? (pr->seq = icmphdr->seq) : 0;
    pr ? (pr->hops = nHops) : 0;
    pr ? (pr->ttl = reply->ttl) : 0;

    if (icmphdr->type == ICMP_TTL_EXPIRE)
        return ETTL_EXPIRED ^ (ICMP_TTL_EXPIRE & 0xffff);

    pr ? (pr->timems = (GetTickCount() - icmphdr->timestamp)) : 0;

    return WSASUCCESS;
}
