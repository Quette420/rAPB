#include "stdafx.h"
#include "Network.h"
#include "Account.h"
#include "Configuration.h"
#include "WS_DS_COM.h"
#include "ApbUdp.h"
#include <Ws2tcpip.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace
{
    Configuration* g_cfg = nullptr;
    Network* g_world = nullptr;

    std::vector<Account*> g_accounts;
    std::mutex g_accountsMutex;

    std::atomic<bool> g_udpStarted(false);
    SOCKET g_udpSocket = INVALID_SOCKET;

    // First compatibility milestone:
    // AUTH -> encrypted ACK -> encrypted WELCOME.
    // USES / JOIN actor bootstrap are deliberately not ported yet because
    // their package-map/net-index data is build-specific.
    constexpr bool kSendWelcomeAfterAuth = true;
    constexpr unsigned short kDistrictUdpPort = 6969;

    constexpr std::uint8_t NMT_HandshakeStart = 26;
    constexpr std::uint8_t NMT_HandshakeChallenge = 27;
    constexpr std::uint8_t NMT_HandshakeResponse = 28;
    constexpr std::uint8_t NMT_HandshakeComplete = 29;
    constexpr std::uint32_t kHandshakeChallengeValue = 0x12345678u;

    std::string Hex(
        const std::uint8_t* data,
        std::size_t size,
        std::size_t limit = 96)
    {
        if (data == nullptr || size == 0)
            return "<empty>";

        std::ostringstream out;
        out << std::hex << std::uppercase << std::setfill('0');

        const std::size_t shown = (std::min)(size, limit);
        for (std::size_t i = 0; i < shown; ++i)
        {
            if (i != 0)
                out << ' ';
            out << std::setw(2) << static_cast<unsigned int>(data[i]);
        }

        if (shown < size)
            out << " ...";

        return out.str();
    }

    std::string EndpointText(const sockaddr_in& endpoint)
    {
        char address[INET_ADDRSTRLEN] = {};

        IN_ADDR copy = endpoint.sin_addr;

        if (InetNtopA(
                AF_INET,
                &copy,
                address,
                static_cast<DWORD>(sizeof(address))) == nullptr)
        {
            strcpy_s(address, "unknown");
        }

        std::ostringstream out;
        out << address
            << ":"
            << ntohs(endpoint.sin_port);
        return out.str();
    }

    Account* FindAccount(std::uint32_t id)
    {
        std::lock_guard<std::mutex> lock(g_accountsMutex);

        for (Account* account : g_accounts)
        {
            if (account != nullptr && account->GetId() == id)
                return account;
        }

        return nullptr;
    }

    Account* FindAccountByEndpoint(const sockaddr_in& endpoint)
    {
        std::lock_guard<std::mutex> lock(g_accountsMutex);

        for (Account* account : g_accounts)
        {
            if (account != nullptr &&
                account->MatchesEndpoint(
                    endpoint.sin_addr.s_addr,
                    ntohs(endpoint.sin_port)))
            {
                return account;
            }
        }

        return nullptr;
    }

    Account* AddOrUpdateAccount(
        std::uint32_t id,
        const std::uint8_t encryptionKey[16])
    {
        const std::uint8_t unknownAuthToken[20] = {};

        std::lock_guard<std::mutex> lock(g_accountsMutex);

        for (Account* account : g_accounts)
        {
            if (account != nullptr && account->GetId() == id)
            {
                account->UpdateKeys(unknownAuthToken, encryptionKey);
                return account;
            }
        }

        Account* account =
            new Account(id, unknownAuthToken, encryptionKey);

        g_accounts.push_back(account);
        return account;
    }

    std::vector<Account*> SnapshotAccounts()
    {
        std::lock_guard<std::mutex> lock(g_accountsMutex);
        return g_accounts;
    }

    Account* FindOnlyPendingAccount()
    {
        std::lock_guard<std::mutex> lock(g_accountsMutex);

        Account* found = nullptr;

        for (Account* account : g_accounts)
        {
            if (account == nullptr || account->HasEndpoint())
                continue;

            if (found != nullptr)
                return nullptr;

            found = account;
        }

        return found;
    }

    // ---------------------------------------------------------------------
    // APB district UDP cipher.
    //
    // This is the 6-round whole-datagram XXTEA/BTEA variant from the working
    // reference server. It is NOT ordinary block XTEA.
    // ---------------------------------------------------------------------
    constexpr std::uint32_t kBteaDelta = 0x9E3779B9u;
    constexpr int kBteaRounds = 6;

    inline std::uint32_t BteaMx(
        std::uint32_t z,
        std::uint32_t y,
        std::uint32_t sum,
        const std::uint32_t key[4],
        unsigned e,
        unsigned p)
    {
        return (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^
               ((sum ^ y) + (key[(p & 3u) ^ e] ^ z));
    }

    void BteaLoadKey(
        const std::array<std::uint8_t, 16>& key,
        std::uint32_t out[4])
    {
        for (int i = 0; i < 4; ++i)
        {
            out[i] =
                static_cast<std::uint32_t>(key[i * 4]) |
                (static_cast<std::uint32_t>(key[i * 4 + 1]) << 8) |
                (static_cast<std::uint32_t>(key[i * 4 + 2]) << 16) |
                (static_cast<std::uint32_t>(key[i * 4 + 3]) << 24);
        }
    }

    void BteaLoadWords(
        const std::vector<std::uint8_t>& data,
        std::vector<std::uint32_t>& words)
    {
        const std::size_t count = data.size() / 4;
        words.resize(count);

        for (std::size_t i = 0; i < count; ++i)
        {
            words[i] =
                static_cast<std::uint32_t>(data[i * 4]) |
                (static_cast<std::uint32_t>(data[i * 4 + 1]) << 8) |
                (static_cast<std::uint32_t>(data[i * 4 + 2]) << 16) |
                (static_cast<std::uint32_t>(data[i * 4 + 3]) << 24);
        }
    }

    void BteaStoreWords(
        const std::vector<std::uint32_t>& words,
        std::vector<std::uint8_t>& data)
    {
        for (std::size_t i = 0; i < words.size(); ++i)
        {
            data[i * 4]     = static_cast<std::uint8_t>(words[i]);
            data[i * 4 + 1] = static_cast<std::uint8_t>(words[i] >> 8);
            data[i * 4 + 2] = static_cast<std::uint8_t>(words[i] >> 16);
            data[i * 4 + 3] = static_cast<std::uint8_t>(words[i] >> 24);
        }
    }

    bool BteaEncrypt(
        std::vector<std::uint8_t>& data,
        const std::array<std::uint8_t, 16>& key)
    {
        if (data.size() < 8 || (data.size() % 4) != 0)
            return false;

        std::vector<std::uint32_t> words;
        BteaLoadWords(data, words);

        const std::size_t n = words.size();
        std::uint32_t k[4];
        BteaLoadKey(key, k);

        std::uint32_t sum = 0;
        std::uint32_t z = words[n - 1];
        std::uint32_t y = 0;

        for (int round = 0; round < kBteaRounds; ++round)
        {
            sum += kBteaDelta;
            const unsigned e = (sum >> 2) & 3u;

            for (std::size_t p = 0; p + 1 < n; ++p)
            {
                y = words[p + 1];
                words[p] +=
                    BteaMx(z, y, sum, k, e, static_cast<unsigned>(p));
                z = words[p];
            }

            y = words[0];
            words[n - 1] +=
                BteaMx(z, y, sum, k, e, static_cast<unsigned>(n - 1));
            z = words[n - 1];
        }

        BteaStoreWords(words, data);
        return true;
    }

    bool BteaDecrypt(
        std::vector<std::uint8_t>& data,
        const std::array<std::uint8_t, 16>& key)
    {
        if (data.size() < 8 || (data.size() % 4) != 0)
            return false;

        std::vector<std::uint32_t> words;
        BteaLoadWords(data, words);

        const std::size_t n = words.size();
        std::uint32_t k[4];
        BteaLoadKey(key, k);

        std::uint32_t sum =
            static_cast<std::uint32_t>(kBteaRounds) * kBteaDelta;
        std::uint32_t y = words[0];
        std::uint32_t z = 0;

        for (int round = 0; round < kBteaRounds; ++round)
        {
            const unsigned e = (sum >> 2) & 3u;

            for (std::size_t p = n - 1; p > 0; --p)
            {
                z = words[p - 1];
                words[p] -=
                    BteaMx(z, y, sum, k, e, static_cast<unsigned>(p));
                y = words[p];
            }

            z = words[n - 1];
            words[0] -= BteaMx(z, y, sum, k, e, 0);
            y = words[0];
            sum -= kBteaDelta;
        }

        BteaStoreWords(words, data);
        return true;
    }

    bool ProtectOutgoingPacket(
        std::vector<std::uint8_t>& packet,
        Account* account)
    {
        if (account == nullptr)
            return false;

        if (packet.size() < 8)
            packet.resize(8, 0);
        else if ((packet.size() % 4) != 0)
            packet.resize(
                (packet.size() + 3u) &
                ~static_cast<std::size_t>(3u),
                0);

        return BteaEncrypt(packet, account->GetEncryptionKey());
    }

    bool SendProtectedPacket(
        SOCKET socket,
        const sockaddr_in& endpoint,
        Account* account,
        std::vector<std::uint8_t> packet,
        const char* label)
    {
        if (!ProtectOutgoingPacket(packet, account))
        {
            Logger(
                lERROR,
                "District UDP",
                "Could not protect %s packet.",
                label);
            return false;
        }

        const int sent =
            sendto(
                socket,
                reinterpret_cast<const char*>(packet.data()),
                static_cast<int>(packet.size()),
                0,
                reinterpret_cast<const sockaddr*>(&endpoint),
                sizeof(endpoint));

        if (sent == SOCKET_ERROR)
        {
            Logger(
                lERROR,
                "District UDP",
                "TX %s to %s failed: %d",
                label,
                EndpointText(endpoint).c_str(),
                WSAGetLastError());
            return false;
        }

        Logger(
            lSUCCESS,
            "District UDP",
            "TX %s: %d bytes to %s | %s",
            label,
            sent,
            EndpointText(endpoint).c_str(),
            Hex(packet.data(), packet.size(), 96).c_str());

        return true;
    }

    bool SendAck(
        SOCKET socket,
        const sockaddr_in& endpoint,
        Account* account,
        std::uint32_t clientPacketId)
    {
        if (account == nullptr)
            return false;

        std::vector<std::uint8_t> packet =
            ApbUdp::BuildAckPacket(
                0,
                account->AllocateServerPacketId(),
                clientPacketId);

        return SendProtectedPacket(
            socket,
            endpoint,
            account,
            packet,
            "ACK");
    }

    const char* WelcomeLevelForDistrictType(int districtType)
    {
        switch (districtType)
        {
        case 2:
            return "financialdistrict_master";

        case 21:
            return "waterfrontdistrict_master";

        case 1:
        default:
            return "rworldsocialdistrict_master";
        }
    }

    bool SendWelcome(
        SOCKET socket,
        const sockaddr_in& endpoint,
        Account* account)
    {
        if (account == nullptr)
            return false;

        const char* level =
            WelcomeLevelForDistrictType(
                g_cfg != nullptr
                    ? g_cfg->GetDistrictType()
                    : 1);

        std::ostringstream text;
        text << "WELCOME LEVEL=" << level
             << " CHALLENGE=0";

        std::vector<std::uint8_t> packet =
            ApbUdp::BuildTextControlPacket(
                0,
                account->AllocateServerPacketId(),
                account->AllocateServerReliableSequence(),
                text.str());

        const bool sent =
            SendProtectedPacket(
                socket,
                endpoint,
                account,
                packet,
                "WELCOME");

        if (sent)
        {
            account->SetHandshakeState(
                Account::HandshakeState::Complete);

            Logger(
                lSUCCESS,
                "District Handshake",
                "Sent %s to account %u. USES/package-map is intentionally "
                "not sent in this first compatibility patch.",
                text.str().c_str(),
                static_cast<unsigned int>(account->GetId()));
        }

        return sent;
    }

    bool SendHandshakeChallenge(
        SOCKET socket,
        const sockaddr_in& endpoint,
        Account* account,
        std::uint32_t clientPacketId)
    {
        if (account == nullptr)
            return false;

        SendAck(socket, endpoint, account, clientPacketId);

        const std::uint8_t payload[4] =
        {
            static_cast<std::uint8_t>(kHandshakeChallengeValue),
            static_cast<std::uint8_t>(kHandshakeChallengeValue >> 8),
            static_cast<std::uint8_t>(kHandshakeChallengeValue >> 16),
            static_cast<std::uint8_t>(kHandshakeChallengeValue >> 24)
        };

        std::vector<std::uint8_t> packet =
            ApbUdp::BuildBinaryControlPacket(
                0,
                account->AllocateServerPacketId(),
                account->AllocateServerReliableSequence(),
                NMT_HandshakeChallenge,
                payload,
                sizeof(payload));

        const bool sent =
            SendProtectedPacket(
                socket,
                endpoint,
                account,
                packet,
                "HANDSHAKE-CHALLENGE");

        if (sent)
        {
            account->SetHandshakeChallenge(kHandshakeChallengeValue);
            account->SetHandshakeState(
                Account::HandshakeState::ChallengeSent);

            Logger(
                lSUCCESS,
                "District Handshake",
                "Sent NMT_HandshakeChallenge(27) to account %u; "
                "challenge=0x%08X",
                static_cast<unsigned int>(account->GetId()),
                static_cast<unsigned int>(kHandshakeChallengeValue));
        }

        return sent;
    }

    bool SendHandshakeComplete(
        SOCKET socket,
        const sockaddr_in& endpoint,
        Account* account,
        std::uint32_t clientPacketId)
    {
        if (account == nullptr)
            return false;

        // Keep the packet-level ACK separate. The live newer client already
        // proved that it accepts this 8-byte encrypted ACK after packet 0.
        const bool ackSent =
            SendAck(
                socket,
                endpoint,
                account,
                clientPacketId);

        std::vector<std::uint8_t> packet =
            ApbUdp::BuildBinaryControlPacket(
                0,
                account->AllocateServerPacketId(),
                account->AllocateServerReliableSequence(),
                NMT_HandshakeComplete,
                nullptr,
                0);

        const bool completeSent =
            SendProtectedPacket(
                socket,
                endpoint,
                account,
                packet,
                "HANDSHAKE-COMPLETE");

        if (completeSent)
        {
            account->SetHandshakeState(
                Account::HandshakeState::Complete);

            Logger(
                lSUCCESS,
                "District Handshake",
                "Sent NMT_HandshakeComplete(29) directly after "
                "NMT_HandshakeStart(26) to account %u (ACK sent=%d).",
                static_cast<unsigned int>(account->GetId()),
                ackSent ? 1 : 0);
        }

        return ackSent && completeSent;
    }

    bool ProcessBinaryHandshakePacket(
        SOCKET socket,
        const sockaddr_in& endpoint,
        Account*& account,
        const ApbUdp::Packet& packet)
    {
        for (const ApbUdp::Bunch& bunch : packet.Bunches)
        {
            std::uint8_t messageType = 0;
            std::vector<std::uint8_t> payload;

            if (!ApbUdp::ReadBinaryControlMessage(
                    bunch,
                    messageType,
                    payload))
            {
                continue;
            }

            Logger(
                lINFO,
                "District Binary Control",
                "RX message=%u packetId=%u open=%d paused=%d "
                "payloadBytes=%u payload=%s",
                static_cast<unsigned int>(messageType),
                static_cast<unsigned int>(packet.PacketId),
                bunch.Open ? 1 : 0,
                bunch.ReplicationPaused ? 1 : 0,
                static_cast<unsigned int>(payload.size()),
                payload.empty()
                    ? "<empty>"
                    : Hex(
                        payload.data(),
                        payload.size(),
                        64).c_str());

            if (messageType == NMT_HandshakeStart)
            {
                if (account == nullptr)
                {
                    account = FindOnlyPendingAccount();

                    if (account == nullptr)
                    {
                        Logger(
                            lERROR,
                            "District Handshake",
                            "NMT_HandshakeStart from %s could not be associated "
                            "with exactly one pending WorldServer handoff.",
                            EndpointText(endpoint).c_str());
                        return true;
                    }

                    account->BindEndpoint(
                        endpoint.sin_addr.s_addr,
                        ntohs(endpoint.sin_port));
                    account->SetAuthenticated(true);

                    Logger(
                        lSUCCESS,
                        "District Handshake",
                        "Bound %s to pending account %u from WorldServer handoff.",
                        EndpointText(endpoint).c_str(),
                        static_cast<unsigned int>(account->GetId()));
                }

                account->SetLastClientPacketId(packet.PacketId);

                // V6 APB-specific WelcomeDirect probe.
                //
                // The old working retail-APB reference used WelcomeDirect:
                // ACK the initial authentication/control packet and immediately
                // send WELCOME, with no CHALLENGE round trip.  The newer client
                // now enters through NMT_HandshakeStart(26) instead of the old
                // text AUTH command, so apply the same lifecycle here.
                const bool ackSent =
                    SendAck(
                        socket,
                        endpoint,
                        account,
                        packet.PacketId);

                const bool welcomeSent =
                    SendWelcome(
                        socket,
                        endpoint,
                        account);

                Logger(
                    (ackSent && welcomeSent) ? lSUCCESS : lERROR,
                    "District Handshake",
                    "WelcomeDirect probe after NMT_HandshakeStart(26) for "
                    "account %u; ACK sent=%d WELCOME sent=%d. "
                    "No NMT_HandshakeChallenge/Response/Complete used.",
                    static_cast<unsigned int>(account->GetId()),
                    ackSent ? 1 : 0,
                    welcomeSent ? 1 : 0);

                return true;
            }

            if (messageType == NMT_HandshakeResponse)
            {
                if (account == nullptr)
                    return true;

                std::uint32_t response = 0;

                if (payload.size() >= 4)
                {
                    response =
                        static_cast<std::uint32_t>(payload[0]) |
                        (static_cast<std::uint32_t>(payload[1]) << 8) |
                        (static_cast<std::uint32_t>(payload[2]) << 16) |
                        (static_cast<std::uint32_t>(payload[3]) << 24);
                }

                Logger(
                    lSUCCESS,
                    "District Handshake",
                    "Received NMT_HandshakeResponse(28) from account %u: "
                    "response=0x%08X expectedChallenge=0x%08X",
                    static_cast<unsigned int>(account->GetId()),
                    static_cast<unsigned int>(response),
                    static_cast<unsigned int>(
                        account->GetHandshakeChallenge()));

                SendHandshakeComplete(
                    socket,
                    endpoint,
                    account,
                    packet.PacketId);

                return true;
            }

            if (messageType == NMT_HandshakeComplete)
            {
                Logger(
                    lINFO,
                    "District Handshake",
                    "Client sent NMT_HandshakeComplete(29).");
                return true;
            }
        }

        return false;
    }

    bool ProcessAuthPacket(
        SOCKET socket,
        const sockaddr_in& endpoint,
        const ApbUdp::Packet& packet)
    {
        for (const ApbUdp::Bunch& bunch : packet.Bunches)
        {
            for (const std::string& text : bunch.ControlStrings)
            {
                ApbUdp::AuthCommand auth;
                if (!ApbUdp::ParseAuthCommand(text, auth))
                    continue;

                Account* account = FindAccount(auth.AccountId);
                if (account == nullptr)
                {
                    Logger(
                        lERROR,
                        "District AUTH",
                        "AUTH from %s names account %u, but WorldServer "
                        "has not handed that account to the district.",
                        EndpointText(endpoint).c_str(),
                        static_cast<unsigned int>(auth.AccountId));
                    return true;
                }

                const bool alreadyComplete =
                    account->GetHandshakeState() ==
                    Account::HandshakeState::Complete;

                account->BindEndpoint(
                    endpoint.sin_addr.s_addr,
                    ntohs(endpoint.sin_port));
                account->SetAuthenticated(true);
                account->SetLastClientPacketId(packet.PacketId);
                account->IncrementUdpReceiveCount();

                Logger(
                    lSUCCESS,
                    "District AUTH",
                    "Authenticated account %u from %s; packetId=%u; "
                    "AUTHKEY=%s",
                    static_cast<unsigned int>(auth.AccountId),
                    EndpointText(endpoint).c_str(),
                    static_cast<unsigned int>(packet.PacketId),
                    auth.AuthKeyText.c_str());

                Logger(
                    lWARN,
                    "District AUTH",
                    "Legacy WorldServer handoff supplied only the 16-byte "
                    "UDP encryption key, so the 20-byte AUTHKEY is logged "
                    "but not validated in this compatibility patch.");

                SendAck(socket, endpoint, account, packet.PacketId);

                if (!alreadyComplete && kSendWelcomeAfterAuth)
                    SendWelcome(socket, endpoint, account);

                return true;
            }
        }

        return false;
    }

    bool ProcessTextControlPacket(
        SOCKET socket,
        const sockaddr_in& endpoint,
        Account* account,
        const ApbUdp::Packet& packet)
    {
        if (account == nullptr)
            return false;

        bool sawText = false;
        bool sawLogin = false;

        for (const ApbUdp::Bunch& bunch : packet.Bunches)
        {
            for (const std::string& text : bunch.ControlStrings)
            {
                sawText = true;

                Logger(
                    lINFO,
                    "District Control",
                    "Account %u -> %s",
                    static_cast<unsigned int>(account->GetId()),
                    text.c_str());

                if (text.compare(0, 6, "LOGIN ") == 0)
                {
                    sawLogin = true;

                    Logger(
                        lSUCCESS,
                        "District Handshake",
                        "LOGIN reached for account %u; replying with WELCOME.",
                        static_cast<unsigned int>(account->GetId()));
                }
                else if (text == "JOIN" ||
                         text.compare(0, 5, "JOIN ") == 0)
                {
                    Logger(
                        lSUCCESS,
                        "District Handshake",
                        "JOIN reached for account %u. Network login is now "
                        "past WELCOME; the next required stage is "
                        "PlayerController/package-map bootstrap.",
                        static_cast<unsigned int>(account->GetId()));
                }
            }
        }

        if (sawText)
            SendAck(socket, endpoint, account, packet.PacketId);

        if (sawLogin)
            SendWelcome(socket, endpoint, account);

        return sawText;
    }

    bool PacketContainsHandshakeStart(
        const ApbUdp::Packet& packet)
    {
        for (const ApbUdp::Bunch& bunch : packet.Bunches)
        {
            std::uint8_t messageType = 0;
            std::vector<std::uint8_t> payload;

            if (ApbUdp::ReadBinaryControlMessage(
                    bunch,
                    messageType,
                    payload) &&
                messageType == NMT_HandshakeStart)
            {
                return true;
            }
        }

        return false;
    }

    bool TryParseEncrypted(
        const std::uint8_t* data,
        std::size_t size,
        Account* account,
        ApbUdp::Packet& packet,
        std::vector<std::uint8_t>& plaintext)
    {
        if (account == nullptr ||
            data == nullptr ||
            size < 8 ||
            (size % 4) != 0)
        {
            return false;
        }

        plaintext.assign(data, data + size);

        if (!BteaDecrypt(
                plaintext,
                account->GetEncryptionKey()))
        {
            return false;
        }

        return ApbUdp::ParsePacket(
            plaintext.data(),
            plaintext.size(),
            packet);
    }

    bool TryPendingAccountKeys(
        const std::uint8_t* data,
        std::size_t size,
        ApbUdp::Packet& packet,
        std::vector<std::uint8_t>& plaintext,
        Account*& candidateAccount)
    {
        const std::vector<Account*> accounts =
            SnapshotAccounts();

        for (Account* account : accounts)
        {
            if (account == nullptr || account->HasEndpoint())
                continue;

            ApbUdp::Packet candidate;
            std::vector<std::uint8_t> candidatePlaintext;

            if (TryParseEncrypted(
                    data,
                    size,
                    account,
                    candidate,
                    candidatePlaintext))
            {
                packet = candidate;
                plaintext.swap(candidatePlaintext);
                candidateAccount = account;
                return true;
            }
        }

        return false;
    }

    void UdpListenerThread()
    {
        SOCKET socketHandle =
            socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

        if (socketHandle == INVALID_SOCKET)
        {
            Logger(
                lERROR,
                "District UDP",
                "socket() failed: %d",
                WSAGetLastError());
            return;
        }

        sockaddr_in bindAddress = {};
        bindAddress.sin_family = AF_INET;
        bindAddress.sin_addr.s_addr = htonl(INADDR_ANY);
        bindAddress.sin_port = htons(kDistrictUdpPort);

        if (bind(
                socketHandle,
                reinterpret_cast<sockaddr*>(&bindAddress),
                sizeof(bindAddress)) == SOCKET_ERROR)
        {
            Logger(
                lERROR,
                "District UDP",
                "bind(0.0.0.0:%u) failed: %d",
                static_cast<unsigned int>(kDistrictUdpPort),
                WSAGetLastError());

            closesocket(socketHandle);
            return;
        }

        g_udpSocket = socketHandle;

        Logger(
            lSUCCESS,
            "District UDP",
            "Listening on 0.0.0.0:%u; UE3 parser + 6-round XXTEA active.",
            static_cast<unsigned int>(kDistrictUdpPort));

        std::vector<std::uint8_t> receiveBuffer(65535);

        while (true)
        {
            sockaddr_in remoteAddress = {};
            int remoteLength = sizeof(remoteAddress);

            const int received =
                recvfrom(
                    socketHandle,
                    reinterpret_cast<char*>(receiveBuffer.data()),
                    static_cast<int>(receiveBuffer.size()),
                    0,
                    reinterpret_cast<sockaddr*>(&remoteAddress),
                    &remoteLength);

            if (received == SOCKET_ERROR)
            {
                Logger(
                    lERROR,
                    "District UDP",
                    "recvfrom() failed: %d",
                    WSAGetLastError());
                Sleep(50);
                continue;
            }

            if (received <= 0)
                continue;

            Logger(
                lINFO,
                "District UDP",
                "RX %d bytes from %s | %s",
                received,
                EndpointText(remoteAddress).c_str(),
                Hex(
                    receiveBuffer.data(),
                    static_cast<std::size_t>(received),
                    128).c_str());

            ApbUdp::Packet packet;
            bool parsed = false;
            bool wasEncrypted = false;
            std::vector<std::uint8_t> plaintext;

            Account* endpointAccount =
                FindAccountByEndpoint(remoteAddress);

            // After AUTH the endpoint has a session key, so encrypted parsing
            // gets priority. A ciphertext packet can occasionally look like a
            // valid plaintext UE3 packet by chance.
            if (endpointAccount != nullptr)
            {
                parsed =
                    TryParseEncrypted(
                        receiveBuffer.data(),
                        static_cast<std::size_t>(received),
                        endpointAccount,
                        packet,
                        plaintext);

                wasEncrypted = parsed;
            }

            // Before an endpoint is bound, the only plaintext packet we accept
            // from this newer client is a packet containing NMT_HandshakeStart.
            // The generic parser is intentionally tolerant of unknown trailing
            // framing, so random ciphertext must not be allowed to "win" just
            // because it accidentally resembles ACK/data bits.
            if (!parsed)
            {
                ApbUdp::Packet rawCandidate;

                if (ApbUdp::ParsePacket(
                        receiveBuffer.data(),
                        static_cast<std::size_t>(received),
                        rawCandidate))
                {
                    if (endpointAccount != nullptr ||
                        PacketContainsHandshakeStart(rawCandidate))
                    {
                        packet = rawCandidate;
                        parsed = true;
                    }
                    else
                    {
                        Logger(
                            lINFO,
                            "District UE3",
                            "Rejected accidental raw parse from %s; "
                            "no NMT_HandshakeStart in unbound plaintext packet.",
                            EndpointText(remoteAddress).c_str());
                    }
                }
                else
                {
                    // Preserve the most useful parser error for final logging if
                    // decryption with pending account keys also fails.
                    packet = rawCandidate;
                }
            }

            // Compatibility probe: if this client encrypts even the first
            // packet, try every pending account's handed-off session key.
            Account* pendingKeyAccount = nullptr;

            if (!parsed)
            {
                if (TryPendingAccountKeys(
                        receiveBuffer.data(),
                        static_cast<std::size_t>(received),
                        packet,
                        plaintext,
                        pendingKeyAccount))
                {
                    parsed = true;
                    wasEncrypted = true;
                }
            }

            if (!parsed)
            {
                Logger(
                    lWARN,
                    "District UE3",
                    "Could not parse packet from %s: %s",
                    EndpointText(remoteAddress).c_str(),
                    packet.Error.c_str());
                continue;
            }

            Logger(
                lINFO,
                "District UE3",
                "%s%s",
                wasEncrypted ? "DECRYPTED " : "PLAINTEXT ",
                ApbUdp::DescribePacket(packet).c_str());

            if (ProcessBinaryHandshakePacket(
                    socketHandle,
                    remoteAddress,
                    endpointAccount,
                    packet))
            {
                continue;
            }

            if (ProcessAuthPacket(
                    socketHandle,
                    remoteAddress,
                    packet))
            {
                continue;
            }

            endpointAccount =
                FindAccountByEndpoint(remoteAddress);

            if (endpointAccount == nullptr &&
                pendingKeyAccount != nullptr)
            {
                // We parsed with a pending key but did not find an AUTH control
                // string. Do not bind the endpoint blindly.
                Logger(
                    lWARN,
                    "District UDP",
                    "Packet decrypted with pending account %u key but did not "
                    "contain AUTH; endpoint remains unbound.",
                    static_cast<unsigned int>(
                        pendingKeyAccount->GetId()));
            }

            if (endpointAccount != nullptr)
            {
                ProcessTextControlPacket(
                    socketHandle,
                    remoteAddress,
                    endpointAccount,
                    packet);
            }
        }
    }

    void StartUdpListenerOnce()
    {
        bool expected = false;

        if (!g_udpStarted.compare_exchange_strong(
                expected,
                true))
        {
            return;
        }

        std::thread listener(UdpListenerThread);
        listener.detach();
    }

    bool ProcessWorldPacket(WS2DS* packet)
    {
        if (packet == nullptr)
            return false;

        if (packet->ReadHeader() == WS2DS::ResponseToInitial)
        {
            Logger(
                lINFO,
                "ProcessWorldPacket()",
                "Received response for initial packet");

            switch (packet->ReadChar())
            {
            case WS2DS::NotAllowed:
                Logger(
                    lERROR,
                    "ProcessWorldPacket()",
                    "Not allowed to host a district");
                return false;

            case WS2DS::DistrictAlreadyExists1:
            case WS2DS::DistrictAlreadyExists2:
                Logger(
                    lERROR,
                    "ProcessWorldPacket()",
                    "District already exists");
                return false;

            case WS2DS::RegisterSuccess:
                Logger(
                    lSUCCESS,
                    "ProcessWorldPacket()",
                    "Registered at World Server");

                StartUdpListenerOnce();
                return true;

            case WS2DS::IDis0:
                Logger(
                    lERROR,
                    "ProcessWorldPacket()",
                    "ID can not be 0");
                return false;

            default:
                return false;
            }
        }

        if (packet->ReadHeader() == WS2DS::AccountEntersDistrict)
        {
            const std::uint32_t accountId =
                static_cast<std::uint8_t>(
                    packet->ReadChar());

            std::unique_ptr<char[]> keyPayload(
                g_world->Receive(16));

            if (!keyPayload)
            {
                Logger(
                    lERROR,
                    "WorldControl",
                    "Failed to receive 16-byte encryption key for account %u",
                    static_cast<unsigned int>(accountId));
                return false;
            }

            std::uint8_t encryptionKey[16] = {};
            std::memcpy(
                encryptionKey,
                keyPayload.get(),
                sizeof(encryptionKey));

            Account* account =
                AddOrUpdateAccount(
                    accountId,
                    encryptionKey);

            Logger(
                lSUCCESS,
                "WorldControl",
                "District enter handoff: account=%u; XXTEA key=%s",
                static_cast<unsigned int>(account->GetId()),
                Hex(
                    encryptionKey,
                    sizeof(encryptionKey),
                    sizeof(encryptionKey)).c_str());

            return true;
        }

        return false;
    }

    bool ReadDistrictToken(char token[9])
    {
        std::ifstream input(
            "Configs\\token.id",
            std::ios::in | std::ios::binary);

        if (!input)
            return false;

        std::string value;
        std::getline(input, value);

        if (!value.empty() &&
            value.back() == '\r')
        {
            value.pop_back();
        }

        if (value.size() != 8)
        {
            Logger(
                lERROR,
                "main()",
                "Configs\\token.id must contain exactly 8 characters; got %u.",
                static_cast<unsigned int>(value.size()));
            return false;
        }

        std::memset(token, 0, 9);
        std::memcpy(token, value.data(), 8);
        return true;
    }
}

int main()
{
    Log_Clear();

    g_cfg =
        new Configuration(
            "Configs\\District.conf");

    char token[9] = {};
    if (!ReadDistrictToken(token))
    {
        Logger(
            lERROR,
            "main()",
            "Could not read district token.");
        return 1;
    }

    g_world = new Network();

    if (g_world->Setup(
            g_cfg->GetWorldIP(),
            atoi(g_cfg->GetWorldPort())) != OK)
    {
        Logger(
            lERROR,
            "Network::Setup()",
            "Socket setup failed");
        return 1;
    }

    Logger(
        lINFO,
        "Network::Setup()",
        "Ready to connect to World Server");

    if (g_world->Connect() != OK)
    {
        Logger(
            lERROR,
            "Network::Connect()",
            "Connection failed");
        return 1;
    }

    Logger(
        lSUCCESS,
        "Network::Connect()",
        "Connected to World Server");

    if (g_world->SendInitial(
            g_cfg->GetDistrictType(),
            g_cfg->GetDistrictID(),
            g_cfg->GetDistrictLanguage(),
            GetPublicIP(),
            "6969",
            token) != OK)
    {
        Logger(
            lERROR,
            "Network::Send()",
            "Data sending failed");
        return 1;
    }

    Logger(
        lINFO,
        "Network::Send()",
        "Initial data sent");

    while (true)
    {
        std::unique_ptr<char[]> response(
            g_world->Receive(2));

        if (!response)
        {
            Logger(
                lERROR,
                "WorldControl",
                "WorldServer connection closed.");
            return 1;
        }

        WS2DS packet(response.get());

        if (!ProcessWorldPacket(&packet))
        {
            Logger(
                lERROR,
                "ProcessPacket()",
                "World packet failed to process.");
            return 1;
        }
    }
}
