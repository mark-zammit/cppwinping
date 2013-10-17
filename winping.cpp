#include <winping.h>

#define ERROR_BUFFER_SIZE   1000


void prcpy(pingreq * dest, pingreq * src)
{
    if(src->hostname)
    {
        dest->hostname = (char*)malloc(strlen(src->hostname)+1);
        memcpy(dest->hostname, src->hostname, strlen(src->hostname)+1);
    }

    if(src->addr)
    {
        dest->addr = (char*)malloc(strlen(src->addr)+1);
        memcpy(dest->addr, src->addr, strlen(src->addr)+1);
    }

    memcpy(&dest->packet_size,
           &src->packet_size,
           sizeof(pingreq) - 2*sizeof(char*));
}


winping::winping(bool verbose) : verbose_logging(verbose) { err = WSASUCCESS; }
winping::~winping(void) {}

int winping::tracert(TSTR host,
                     pingstat * ps,
                     int packet_size,
                     int ttl)
{
    return err;
}

int winping::ping(TSTR host,
                  pingstat * ps,
                  int packet_size,
                  int ttl,
                  int attempts,
                  int timeout)
{
    if(host.empty())
        return returnc(EINVALID_HOSTNAME);

    // Checks for valid packet size
    if(!packet_size || packet_size > MAX_PING_DATA_SIZE)
        return returnc(EPACKET_SIZE_OUT_OF_BOUNDS ^ (packet_size & 0xffff));

    // Checks for valid ttl
    if(!ttl || ttl > MAX_TTL)
        return returnc(ETTL_SIZE_OUT_OF_BOUNDS ^ (ttl & 0xffff));

    // Checks that winsock is minimum 2.1 compliant
    WSAData wsaData;
    if (WSAStartup(MAKEWORD(WINSOCK_VER_REQ_HIGH, WINSOCK_VER_REQ_LOW), &wsaData) != 0)
        return returnc(EWINSOCK_VERSION ^ wsaData.wVersion);

    // Determines packet size
    packet_size = max(sizeof(ICMPHeader),
                      min(MAX_PING_DATA_SIZE, (unsigned int)packet_size));

    SOCKET sd;
    sockaddr_in dest, source;
    pingreq pr;

    int rc = setup_for_ping(strconv<std::string,TSTR>(host).c_str(),
                            ttl,
                            sd,
                            dest,
                            timeout,
                            &pr);

    if(rc != WSASUCCESS)
    {
        // Cleanup
        WSACleanup();
        return returnc(rc);
    }

    int seq_no = 0;
    ICMPHeader* send_buf = NULL;
    IPHeader* recv_buf = NULL;

    rc = allocate_buffers(send_buf,
                          recv_buf,
                          packet_size);

    if(rc != WSASUCCESS)
    {
        // Cleanup
        delete[]send_buf;
        delete[]recv_buf;
        WSACleanup();
        return returnc(rc);
    }

    if(verbose_logging)
        _tprintf(_T("Pinging %s with %d bytes of data:\n\n"),
                 TSTR((!pr.hostname ? pr.addr : pr.hostname)).c_str(),
                 packet_size);

    int attempt=0;

    // Loops for specified number of attempts
    while((rc == WSASUCCESS || rc == WSAETIMEDOUT) &&
          attempts == PING_INFINITE ? PING_INFINITE : attempt++ < attempts)
    {
        // Re-initializes ping packet for next ping
        init_ping_packet(send_buf,
             packet_size,
             seq_no,
             &pr);

        // Send the ping and receive the reply
        if((rc = send_ping(sd, dest, send_buf, packet_size, &pr)) == WSASUCCESS)
        {
            // Keeps re-trying until the host can be reach or until
            // the timeout specification is met
            while(true)
            {
                // Receive replies until we either get a successful read,
                // or a fatal error occurs.
                if((rc = recv_ping(sd, source, recv_buf, MAX_PING_PACKET_SIZE, &pr)) != WSASUCCESS)
                {
                    // Pull the sequence number out of the ICMP header.  If
                    // it's bad, we just complain, but otherwise we take
                    // off, because the read failed for some reason.
                    unsigned short header_len = recv_buf->h_len * 4;
                    ICMPHeader* icmphdr = (ICMPHeader*)((char*)recv_buf + header_len);
                    if (icmphdr->seq != seq_no)
                        continue;
                    else
                        break;
                }
                // Success or fatal error (as opposed to a minor error) so finish up
                if((rc = decode_reply(recv_buf, packet_size, &source, &pr)) != WSATRY_AGAIN)
                    break;
            }

            // Determine if request timed out
            rc == WSAETIMEDOUT ? (pr.bytes_recv = REQUEST_TIMEOUT) : 0;
        }

        if(verbose_logging)
            printpr(pr);

        // This is to stop memory allocation errors
        // when the option to ping infinitely has been selected.
        if(attempts != PING_INFINITE)
        {
            // Makes a copy of the current pingreq to save
            pingreq * tmp = new pingreq;
            prcpy(tmp, &pr);

            // Adds the ping request data to the running list
            ps->pings.push_back(tmp);
        }
    }

    if(rc == WSAETIMEDOUT)
        rc = WSASUCCESS;

    // Cleanup
    delete[]send_buf;
    delete[]recv_buf;
    WSACleanup();

    return returnc(rc);
}


int winping::error(void)
{
    return err;
}

void winping::print_error(void)
{
    if(IS_PING_ERR(err))
    {
        TCHAR buffer[ERROR_BUFFER_SIZE];
        TSTR message;

        switch(err & 0xefff0000)
        {
            case EINVALID_HOSTNAME:
                message = _T("Invalid or empty hostname.");
                break;
            case ETOO_FEW_BYTES:
                message = _T("Too few bytes returned from host.");
                break;
            case EPACKET_SIZE_OUT_OF_BOUNDS:
                TSPRINTF_S(buffer,
                           ERROR_BUFFER_SIZE,
                           _T("Packet size out of bounds, 0 > %d or %d > %d."),
                           GET_ERR_VALUE(err),
                           GET_ERR_VALUE(err),
                           MAX_PING_DATA_SIZE);
                message = TSTR(buffer);
                break;
            case ETTL_EXPIRED:
                message = _T("TTL expired.");
                break;
            case ETTL_SIZE_OUT_OF_BOUNDS:
                TSPRINTF_S(buffer,
                           ERROR_BUFFER_SIZE,
                           _T("TTL size out of bounds, 0 > %d or %d > %d."),
                           GET_ERR_VALUE(err),
                           GET_ERR_VALUE(err),
                           MAX_TTL);
                message = TSTR(buffer);
                break;
            case EUNKNOWN_ICMP_PACKET:
                TSPRINTF_S(buffer,
                           ERROR_BUFFER_SIZE,
                           _T("Unknown ICMP packet type %d."),
                           GET_ERR_VALUE(err));
                message = TSTR(buffer);
                break;
            case EBUFFER_ALLOCATION_FAILED:
                TSPRINTF_S(buffer,
                           ERROR_BUFFER_SIZE,
                           _T("Failed to allocate output buffer [0x%.4x]."),
                           GET_ERR_VALUE(err));
                message = TSTR(buffer);
                break;
            case EWINSOCK_VERSION:
                TSPRINTF_S(buffer,
                           ERROR_BUFFER_SIZE,
                           _T("Failed to find winsock %d.%d or better, current version %d.%d."),
                           WINSOCK_VER_REQ_HIGH,
                           WINSOCK_VER_REQ_LOW,
                           GET_ERR_VALUE_HIGH(err),
                           GET_ERR_VALUE_LOW(err));
                message  = TSTR(buffer);
                break;
            default:
                message = _T("Unhandled error returned.");
                break;
        }

        _tprintf(_T("Ping Message [0x%.4x]: %hs"), err, message.c_str());
    }
    else
    {
        LPTSTR message = 0;
        FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                      NULL,
                      err,
                      LOCALE_SYSTEM_DEFAULT,
                      (LPTSTR)&message,
                      0,
                      NULL);

        _tprintf(_T("WSA Message [0x%.4x]: %hs"), err, message);
    }
}


int winping::returnc(int rc)
{
    err = rc;
    return rc;
}


void printpr(pingreq &r)
{
    if(r.bytes_recv != REQUEST_TIMEOUT)
    {
        _tprintf(_T("Reply from %hs: bytes=%d time%hs%dms hops=%d TTL=%d\n"),
                 TSTR(r.addr).c_str(),
                 r.packet_size,
                 r.timems == 0 ? _T("=<") : _T("="),
                 r.timems == 0 ? 1 : r.timems,
                 r.hops,
                 r.ttl);
    }
    else
    {
        _tprintf(_T("Request timed out for %hs\n"),
                 TSTR(r.addr).c_str());
    }
}
