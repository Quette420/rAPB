#include "stdafx.h"

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include "Network.h"

Network::Network()
{
}

int Network::Setup(char* address, int port)
{
    int result = WSAStartup(MAKEWORD(2, 2), &data);
    if (result != NO_ERROR)
        return result;

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET)
    {
        WSACleanup();
        return 1;
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(address);
    addr.sin_port = htons(port);

    return 0;
}

int Network::Connect()
{
    int result =
        connect(
            sock,
            reinterpret_cast<SOCKADDR*>(&addr),
            sizeof(addr));

    if (result == SOCKET_ERROR)
        return Dispose();

    return 0;
}

int Network::Dispose()
{
    closesocket(sock);
    WSACleanup();
    return 1;
}

int Network::Shutdown()
{
    int result = shutdown(sock, SD_SEND);

    if (result == SOCKET_ERROR)
        return Dispose();

    return 0;
}

int Network::Send(char* buffer)
{
    if (buffer == NULL)
        return 1;

    int total = 0;
    const int length =
        static_cast<int>(strlen(buffer));

    while (total < length)
    {
        int result =
            send(
                sock,
                buffer + total,
                length - total,
                0);

        if (result == SOCKET_ERROR ||
            result == 0)
        {
            return Dispose();
        }

        total += result;
    }

    return 0;
}

int Network::SendInitial(
    int districtType,
    int districtId,
    int language,
    char* address,
    char* port,
    char* token)
{
    char buffer[255] = {};

    int addressLengthDigits =
        strlen(address) < 10
            ? 1
            : 2;

    // The district type is fixed-width.  The old one-character field worked
    // for Social (1) and Financial (2), but Waterfront (21) shifted every
    // following field and made WorldServer parse invalid string lengths.
    sprintf_s(
        buffer,
        sizeof(buffer),
        "%d%02d%d%d%d%d%s%d%d%s%d%d%s",
        0,
        districtType,
        districtId,
        language,
        addressLengthDigits,
        static_cast<int>(strlen(address)),
        address,
        0,
        static_cast<int>(strlen(port)),
        port,
        0,
        8,
        token);

    return Send(buffer);
}

char* Network::Receive(int size)
{
    if (size <= 0)
        return NULL;

    // TCP is a byte stream: one recv() is not guaranteed to return the
    // complete requested protocol field.
    char* buffer =
        new char[size + 1];

    int total = 0;

    while (total < size)
    {
        int result =
            recv(
                sock,
                buffer + total,
                size - total,
                0);

        if (result > 0)
        {
            total += result;
            continue;
        }

        if (result == 0)
        {
            Logger(
                lERROR,
                "Network::Receive()",
                "Connection closed while waiting for %d bytes "
                "(received %d)",
                size,
                total);
        }
        else
        {
            Logger(
                lERROR,
                "Network::Receive()",
                "Receiving failed! Error code: %d",
                WSAGetLastError());
        }

        delete[] buffer;
        return NULL;
    }

    buffer[size] = '\0';
    return buffer;
}
