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
#include <cctype>
#include <cstring>
#include <cstdlib>
#include <map>
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
	// ---------------------------------------------------------------------
// Reliable sequence нумеруется ОТДЕЛЬНО на каждый канал.
// UNetConnection держит InReliable[ChIndex] и проверяет
// InReliable < ChSequence, поэтому повторно использованный номер
// молча отбрасывается как дубликат.
// ---------------------------------------------------------------------
std::mutex g_channelSequenceMutex;
std::map<std::pair<std::uint32_t, std::uint16_t>, std::uint16_t>
    g_channelSequences;

struct GriStartupState
{
    std::uint32_t OpenPacketId = 0;
    bool OpenPacketTracked = false;
    bool OpenAcked = false;
    bool MatchHasBegunSent = false;
};

std::mutex g_griStartupMutex;

std::map<std::uint32_t, GriStartupState>
    g_griStartupStates;

void ResetGriStartupState(Account* account)
{
    if (account == nullptr)
        return;

    std::lock_guard<std::mutex> guard(
        g_griStartupMutex);

    g_griStartupStates.erase(
        account->GetId());
}

void TrackGriOpenPacket(
    Account* account,
    std::uint32_t packetId)
{
    if (account == nullptr)
        return;

    std::lock_guard<std::mutex> guard(
        g_griStartupMutex);

    GriStartupState& state =
        g_griStartupStates[account->GetId()];

    state.OpenPacketId = packetId;
    state.OpenPacketTracked = true;
    state.OpenAcked = false;
    state.MatchHasBegunSent = false;
}

bool ConsumeGriOpenAck(
    Account* account,
    std::uint32_t acknowledgedPacketId)
{
    if (account == nullptr)
        return false;

    std::lock_guard<std::mutex> guard(
        g_griStartupMutex);

    auto it =
        g_griStartupStates.find(
            account->GetId());

    if (it == g_griStartupStates.end())
        return false;

    GriStartupState& state = it->second;

    if (!state.OpenPacketTracked)
        return false;

    if (state.OpenPacketId != acknowledgedPacketId)
        return false;

    state.OpenAcked = true;

    if (state.MatchHasBegunSent)
        return false;

    // Сразу резервируем флаг, чтобы повторные ACK
    // не породили второй property update.
    state.MatchHasBegunSent = true;

    return true;
}

std::uint16_t AllocateChannelSequence(
    Account* account,
    std::uint16_t channelIndex)
{
    const std::uint32_t accountId =
        account != nullptr ? account->GetId() : 0u;

    std::lock_guard<std::mutex> guard(g_channelSequenceMutex);
    std::uint16_t& next =
        g_channelSequences[std::make_pair(accountId, channelIndex)];
    ++next;                 // первый bunch на свежем канале = 1
    return next;
}

void ResetChannelSequences(Account* account)
{
    const std::uint32_t accountId =
        account != nullptr ? account->GetId() : 0u;

    std::lock_guard<std::mutex> guard(g_channelSequenceMutex);
    for (auto it = g_channelSequences.begin();
         it != g_channelSequences.end(); )
    {
        it = (it->first.first == accountId)
            ? g_channelSequences.erase(it)
            : std::next(it);
    }
}

    std::atomic<bool> g_udpStarted(false);
    SOCKET g_udpSocket = INVALID_SOCKET;

    // First compatibility milestone:
    // AUTH -> encrypted ACK -> encrypted WELCOME.
    // USES / JOIN actor bootstrap are deliberately not ported yet because
    // their package-map/net-index data is build-specific.
    constexpr bool kSendWelcomeAfterAuth = true;

    constexpr unsigned short kDistrictUdpPort = 6969;

    constexpr std::uint8_t NMT_Hello     = 0;
    constexpr std::uint8_t NMT_Welcome   = 1;
    constexpr std::uint8_t NMT_Upgrade   = 2;
    constexpr std::uint8_t NMT_Challenge = 3;
    constexpr std::uint8_t NMT_Netspeed  = 4;
    constexpr std::uint8_t NMT_Login     = 5;
    constexpr std::uint8_t NMT_Failure   = 6;
    constexpr std::uint8_t NMT_Uses      = 7;
    constexpr std::uint8_t NMT_Unload = 8;
    constexpr std::uint8_t NMT_Join   = 9;   // не 10: APB сдвинул enum

    constexpr std::int32_t kServerEngineVersion    = 3908;
    constexpr std::int32_t kServerMinNetVersion    = 3077;
    constexpr std::uint8_t NMT_HandshakeStart = 26;
    constexpr std::uint8_t NMT_HandshakeChallenge = 27;
    constexpr std::uint8_t NMT_HandshakeResponse = 28;
    constexpr std::uint8_t NMT_HandshakeComplete = 29;
    constexpr std::uint32_t kHandshakeChallengeValue = 0x12345678u;

    enum class HandshakeProbeMode
    {
        Ack,
        Challenge,
        Complete,
        Welcome
    };

    HandshakeProbeMode GetHandshakeProbeMode()
    {
        const char* raw = std::getenv("RAPB_HANDSHAKE_PROBE");

        if (raw == nullptr || *raw == '\0')
            return HandshakeProbeMode::Challenge;

        std::string value(raw);
        std::transform(
            value.begin(),
            value.end(),
            value.begin(),
            [](unsigned char c)
            {
                return static_cast<char>(std::tolower(c));
            });

        if (value == "ack" || value == "ack-only")
            return HandshakeProbeMode::Ack;

        if (value == "complete" || value == "29")
            return HandshakeProbeMode::Complete;

        if (value == "welcome")
            return HandshakeProbeMode::Welcome;

        return HandshakeProbeMode::Challenge;
    }

    const char* HandshakeProbeModeText(HandshakeProbeMode mode)
    {
        switch (mode)
        {
        case HandshakeProbeMode::Ack:
            return "ack";
        case HandshakeProbeMode::Complete:
            return "complete";
        case HandshakeProbeMode::Welcome:
            return "welcome";
        case HandshakeProbeMode::Challenge:
        default:
            return "challenge";
        }
    }

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

    bool TraceReadBits(
        const std::uint8_t* data,
        std::size_t endBit,
        std::size_t& position,
        std::size_t count,
        std::uint32_t& value)
    {
        value = 0;

        if (data == nullptr || count > 32 || position + count > endBit)
            return false;

        for (std::size_t index = 0; index < count; ++index)
        {
            const std::size_t absolute = position + index;
            const std::uint8_t bit =
                (data[absolute / 8] >> (absolute % 8)) & 1u;

            value |= static_cast<std::uint32_t>(bit) << index;
        }

        position += count;
        return true;
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
        // Self-parse clear server packets before XXTEA. ACK is already proven
        // on the wire, but this catches writer/header/sequence corruption in
        // future ControlChannel experiments before encryption obscures it.
        ApbUdp::Packet clearPacket;

        if (ApbUdp::ParsePacket(packet.data(), packet.size(), clearPacket))
        {
            Logger(
                lINFO,
                "District TX Clear",
                "%s | %s | %s",
                label,
                ApbUdp::DescribePacket(clearPacket).c_str(),
                Hex(packet.data(), packet.size(), 96).c_str());
        }
        else
        {
            Logger(
                lWARN,
                "District TX Clear",
                "%s self-parse failed: %s | %s",
                label,
                clearPacket.Error.c_str(),
                Hex(packet.data(), packet.size(), 96).c_str());
        }

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

    std::mutex g_ackMutex;
    std::map<std::uint32_t, std::uint64_t> g_lastAckedClientPacketId;

    // Возвращает false, если этот packetId для этого аккаунта уже подтверждён.
    // Хранится значение +1, чтобы отсутствие записи отличалось от packetId 0.
    bool ShouldAckClientPacket(
        Account* account,
        std::uint32_t clientPacketId)
    {
        if (account == nullptr)
            return false;

        const std::uint64_t marker =
            static_cast<std::uint64_t>(clientPacketId) + 1u;

        std::lock_guard<std::mutex> lock(g_ackMutex);
        std::uint64_t& last =
            g_lastAckedClientPacketId[account->GetId()];

        if (last == marker)
            return false;

        last = marker;
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

        if (!ShouldAckClientPacket(account, clientPacketId))
            return true;

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

    void AppendInt32(std::vector<std::uint8_t>& out, std::int32_t value)
    {
        const std::uint32_t v = static_cast<std::uint32_t>(value);
        out.push_back(static_cast<std::uint8_t>(v));
        out.push_back(static_cast<std::uint8_t>(v >> 8));
        out.push_back(static_cast<std::uint8_t>(v >> 16));
        out.push_back(static_cast<std::uint8_t>(v >> 24));
    }

    // UE3 FString: INT длина ВКЛЮЧАЯ терминатор, затем символы и \0.
    void AppendFString(std::vector<std::uint8_t>& out, const std::string& text)
    {
        AppendInt32(out, static_cast<std::int32_t>(text.size() + 1u));
        out.insert(out.end(), text.begin(), text.end());
        out.push_back(0);
    }
    
    bool SendNetChallenge(
    SOCKET socket,
    const sockaddr_in& endpoint,
    Account* account,
    std::uint32_t clientPacketId)
    {
        if (account == nullptr)
            return false;

        SendAck(socket, endpoint, account, clientPacketId);

        // Вариант A (стоковый UE3): INT ServerNetworkVersion + FString Challenge.
        // Вариант B: только FString. Переключается RAPB_NET_CHALLENGE_FORM=a|b.
        const char* form = std::getenv("RAPB_NET_CHALLENGE_FORM");
        const bool withVersion = (form == nullptr || form[0] != 'b');

        std::vector<std::uint8_t> body;
        if (withVersion)
            AppendInt32(body, kServerEngineVersion);
        AppendFString(body, "0");

        std::vector<std::uint8_t> packet =
            ApbUdp::BuildBinaryControlPacket(
                0,
                account->AllocateServerPacketId(),
                account->AllocateServerReliableSequence(),
                NMT_Challenge,
                body.data(),
                body.size());

        const bool sent = SendProtectedPacket(
            socket, endpoint, account, packet, "NET-CHALLENGE");

        Logger(
            lSUCCESS,
            "District Net",
            "Sent NMT_Challenge(3) form=%s bodyBytes=%u sent=%d",
            withVersion ? "int+fstring" : "fstring",
            static_cast<unsigned int>(body.size()),
            sent ? 1 : 0);

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

    void AppendByte(std::vector<std::uint8_t>& out, std::uint8_t value)
    {
        out.push_back(value);
    }

        void AppendGuid(std::vector<std::uint8_t>& out, const std::uint32_t guid[4])
    {
        for (int i = 0; i < 4; ++i)
            AppendInt32(out, static_cast<std::int32_t>(guid[i]));
    }

    struct UsesEntry
{
    const char*   Name;
    std::uint32_t Guid[4];
    std::int32_t  Generation;
    std::uint32_t NetObjectCount;   // из живого клиента, не из парсера
};

 // NMT_Uses(7), порядок подтверждён по FPackageInfo::SerializeWire:
        //   FGuid(16) | FString PackageName | FString | FString
        //   | INT PackageFlags | INT Generation | FString | BYTE
        // Три FString становятся FName в структуре клиента.
const UsesEntry kPackages[] =
{
    { "Core",    { 0x0FE825BC, 0x4970D0BC, 0xE10969A8, 0x4C498AF9 }, 2,  1575 },
    { "Engine",  { 0x8CC8C348, 0x4498F5A3, 0x05567188, 0x79EC40E0 }, 2, 31931 },
    { "APBGame", { 0x726ED7C5, 0x49A968E8, 0x50E644AA, 0x50ED3A99 }, 2, 30964 },
};

constexpr std::uint32_t kBadNetIndex = 0xFFFFFFFFu;
// APBGame.Default__cAPBPlayerController, локальный NetIndex.
// Подтверждено live probe: NetIndex=12773 @0x06BD2B40.
// Не путать с классом cAPBPlayerController -- он на 12772.
constexpr std::uint32_t kPlayerControllerLocalNetIndex = 12773u;
// APBGame.Default__cAPBGameReplicationInfo, локальный NetIndex.
// Live probe: NetIndex=13049 @0x06BD6130.
constexpr std::uint32_t kGriLocalNetIndex = 13049u;
// APBGame.cHUDBase (класс, не CDO) -- локальный NetIndex.
constexpr std::uint32_t kHudClassLocalNetIndex = 21299u;   // ← подставить
// Клиент локально открывает два канала до первого серверного пакета:
//   0 -> ControlChannel (type 1)
//   1 -> VoiceChannel   (type 4)
// Actor-bunch на канале 1 достаётся голосовому каналу и молча
// отбрасывается. Первый свободный слот -- 2.
constexpr std::uint16_t kControllerChannel = 2u;
constexpr std::uint16_t kGriChannel        = 3u;
constexpr std::uint16_t kPawnChannel       = 4u;
constexpr std::uint16_t kPriChannel = 5u;

// APBGame.Default__cAPBPlayerReplicationInfo, локальный NetIndex.
// Live probe: NetIndex=13199 @0x06BD5A80. Глобальный: 33506 + 13199 = 46705.
constexpr std::uint32_t kPriLocalNetIndex = 13199u;

// LIVE FClassNetCache, Engine.Controller.PlayerReplicationInfo,
// ObjectProperty, ConditionIndex=21.
constexpr std::uint32_t kFieldPlayerReplicationInfo = 21u;

// LIVE FClassNetCache, APB 1.13.1:
constexpr std::uint32_t kControllerFieldMax = 684u;   // cAPBPlayerController
constexpr std::uint32_t kGriFieldMax        = 63u;    // cAPBGameReplicationInfo
constexpr std::uint32_t kFieldAskDistrictEnter = 138u;
// LIVE FClassNetCache:
// Engine.GameReplicationInfo.bMatchHasBegun
// в контексте APBGame.cAPBGameReplicationInfo, FieldMax=63.
constexpr std::uint32_t kFieldGriMatchHasBegun = 45u;
constexpr std::uint32_t kFieldAnsDistrictEnter = 139u;
constexpr std::uint32_t kFieldServerUseAutoReady = 670u;
constexpr std::uint32_t kFieldServerSyncState    = 80u;
// APB 1.13.1 LIVE FClassNetCache:
// cAPBPlayerController.ClientGoToSpawnZoneSelectScreen(byte eFaction)
constexpr std::uint32_t kFieldClientGoToSpawnZoneSelectScreen = 390u;

// cAPBPlayerController.ClientSetInitialState(
//     int nCharacterUID,
//     byte Faction,
//     byte Gender)
constexpr std::uint32_t kFieldClientSetInitialState = 573u;
// APB 1.13.1 LIVE FClassNetCache.
constexpr std::uint32_t kFieldClientUpdateLevelStreamingStatus = 92u;
constexpr std::uint32_t kFieldServerUpdateLevelVisibilityIndex = 93u;
constexpr std::uint32_t kFieldServerUpdateLevelVisibilityString = 94u;
constexpr std::uint32_t kFieldClientFlushLevelStreaming         = 98u;
constexpr std::uint32_t kFieldServerNotifyClientLoaded          = 419u;

struct StreamingPlanEntry
{
    const char* PackageName;
    bool ShouldBeLoaded;
    bool ShouldBeVisible;
    bool ShouldBlockOnLoad;
};

constexpr StreamingPlanEntry kSocialStreamingPlan[] =
{
    {
        "rworldsocialdistrict_artprops_blockout",
        true, true, false
    },
    {
        "rworldsocialdistrict_tile_000_000_block_250_000terrain",
        true, true, false
    },
    {
        "rworldsocialdistrict_design",
        true, true, false
    },

    // Character/vehicle customisation streaming levels exist in the
    // master StreamingLevels array, but should remain unloaded here.
    {
        "cc_background_1",
        false, false, false
    },
    {
        "cc_matinee",
        false, false, false
    },
    {
        "vc_matinee",
        false, false, false
    },
    {
        "wardrobe_matinee",
        false, false, false
    },

    {
        "rworldsocialdistrict_block01",
        true, true, false
    },
    {
        "rworldsocialdistrict_block02",
        true, true, false
    },
    {
        "rworldsocialdistrict_block03",
        true, true, false
    },
    {
        "rworldsocialdistrict_block04",
        true, true, false
    },
    {
        "rworldsocialdistrict_props_block01",
        true, true, false
    },
    {
        "rworldsocialdistrict_props_block02",
        true, true, false
    },
    {
        "rworldsocialdistrict_props_block03",
        true, true, false
    },
    {
        "rworldsocialdistrict_props_block04",
        true, true, false
    },
    {
        "rworldsocialdistrict_vista",
        true, true, false
    },
    {
        "rworldsocialdistrict_beacons",
        true, true, false
    }
};

// UPackageMap::Compute() назначает основания как бегущую сумму по списку
// в порядке отправки Uses. Порядок наш, поэтому индексы задаём мы.
std::uint32_t PackageFirstNetIndex(const char* name)
{

    std::uint32_t base = 0;
    for (const UsesEntry& e : kPackages)
    {
        if (std::strcmp(e.Name, name) == 0)
            return base;
        base += e.NetObjectCount;
    }
    Logger(lERROR, "District Net",
        "Package '%s' is not in kPackages", name);
    return kBadNetIndex;
}

bool SendGriMatchHasBegun(
    SOCKET socket,
    const sockaddr_in& endpoint,
    Account* account)
{
    if (account == nullptr)
        return false;

    const std::uint32_t packetId =
        account->AllocateServerPacketId();

    const std::uint16_t sequence =
        AllocateChannelSequence(
            account,
            kGriChannel);

    std::vector<std::uint8_t> packet =
        ApbUdp::BuildActorBoolFieldPacket(
            packetId,
            kGriChannel,
            sequence,
            kFieldGriMatchHasBegun,
            kGriFieldMax,
            true);

    if (packet.empty())
    {
        Logger(
            lERROR,
            "District GRI Startup",
            "BuildActorBoolFieldPacket returned empty for "
            "bMatchHasBegun.");

        return false;
    }

    const bool sent =
        SendProtectedPacket(
            socket,
            endpoint,
            account,
            packet,
            "GRI-MATCH-HAS-BEGUN");

    Logger(
        sent ? lSUCCESS : lERROR,
        "District GRI Startup",
        "bMatchHasBegun=true sent=%d "
        "packetId=%u ch=%u seq=%u field=%u fieldMax=%u",
        sent ? 1 : 0,
        static_cast<unsigned int>(packetId),
        static_cast<unsigned int>(kGriChannel),
        static_cast<unsigned int>(sequence),
        static_cast<unsigned int>(
            kFieldGriMatchHasBegun),
        static_cast<unsigned int>(
            kGriFieldMax));

    return sent;
}

std::uint32_t GlobalNetIndex(const char* package, std::uint32_t localNetIndex)
{
    const std::uint32_t base = PackageFirstNetIndex(package);
    return base == kBadNetIndex ? kBadNetIndex : base + localNetIndex;
}

bool SendPackageUses(
        SOCKET socket,
        const sockaddr_in& endpoint,
        Account* account)
    {
        if (account == nullptr)
            return false;
 
        bool allSent = true;

        for (const UsesEntry& e : kPackages)
        {
            std::vector<std::uint8_t> body;
            AppendGuid(body, e.Guid);
            AppendFString(body, e.Name);
            AppendFString(body, "");
            AppendFString(body, "");
            AppendInt32(body, 0);            // PackageFlags: PKG_Need не ставим
            AppendInt32(body, e.Generation);
            AppendFString(body, "");
            body.push_back(0);               // BYTE

            std::vector<std::uint8_t> packet =
                ApbUdp::BuildBinaryControlPacket(
                    0,
                    account->AllocateServerPacketId(),
                    account->AllocateServerReliableSequence(),
                    NMT_Uses,
                    body.data(),
                    body.size());

            const bool sent = SendProtectedPacket(
                socket, endpoint, account, packet, "NET-USES");

            allSent = allSent && sent;

            Logger(sent ? lSUCCESS : lERROR, "District Net",
                "Sent NMT_Uses(7) package='%s' generation=%d bodyBytes=%u",
                e.Name, e.Generation,
                static_cast<unsigned int>(body.size()));
        }

        return allSent;
    }
    
        bool SendNetWelcome(
        SOCKET socket,
        const sockaddr_in& endpoint,
        Account* account)
    {
        if (account == nullptr)
            return false;

        const char* level =
            WelcomeLevelForDistrictType(
                g_cfg != nullptr ? g_cfg->GetDistrictType() : 1);

        const char* levelOverride = std::getenv("RAPB_WELCOME_LEVEL");
        if (levelOverride != nullptr && levelOverride[0] != '\0')
            level = levelOverride;

        const char* gameName = std::getenv("RAPB_WELCOME_GAME");
        if (gameName == nullptr || gameName[0] == '\0')
            gameName = "APBGame.cAPBGameInfo";

        // NMT_Welcome(1) = FString LevelName, FString GameName, INT bStrippedData.
        // Подтверждено декомпиляцией UNetPendingLevel::NotifyReceivedText:
        // третий параметр читается как int и сравнивается на равенство с
        // клиентской глобалкой stripped-data; при несовпадении клиент
        // показывает "Content Mismatch" и бросает соединение.
        // Клиент этой сборки stripped, поэтому по умолчанию шлём 1.
        const char* strippedEnv = std::getenv("RAPB_WELCOME_STRIPPED");
        const std::int32_t stripped =
            (strippedEnv != nullptr && strippedEnv[0] == '0') ? 0 : 1;

        std::vector<std::uint8_t> body;
        AppendFString(body, level);
        AppendFString(body, gameName);
        AppendInt32(body, stripped);

        std::vector<std::uint8_t> packet =
            ApbUdp::BuildBinaryControlPacket(
                0,
                account->AllocateServerPacketId(),
                account->AllocateServerReliableSequence(),
                NMT_Welcome,
                body.data(),
                body.size());

        const bool sent =
            SendProtectedPacket(
                socket,
                endpoint,
                account,
                packet,
                "NET-WELCOME");

        if (sent)
        {
            account->SetHandshakeState(
                Account::HandshakeState::Complete);
        }

        Logger(
            sent ? lSUCCESS : lERROR,
            "District Net",
            "Sent NMT_Welcome(1) level='%s' game='%s' stripped=%d "
            "bodyBytes=%u sent=%d",
            level,
            gameName,
            stripped,
            static_cast<unsigned int>(body.size()),
            sent ? 1 : 0);

        return sent;
    }
	    // Открывает actor-канал с PlayerReplicationInfo и привязывает его к
    // контроллеру через реплицируемое свойство Controller.PlayerReplicationInfo.
    //
    // Property-update, в отличие от RPC-параметра, presence-бита не имеет:
    // SerializeInt(FieldIndex, FieldMax), затем сразу значение.
    // Ссылка на актор с открытым каналом идёт как флаг 1 + номер канала
    // (граница 0x3FF) -- kind "object".
    bool SendPlayerReplicationInfo(
        SOCKET socket,
        const sockaddr_in& endpoint,
        Account* account)
    {
        if (account == nullptr)
            return false;

        const std::uint32_t priArchetype =
            GlobalNetIndex("APBGame", kPriLocalNetIndex);

        if (priArchetype == kBadNetIndex)
            return false;

        // 1. Открыть канал PRI.
        const std::uint16_t priSequence =
            AllocateChannelSequence(account, kPriChannel);

        std::vector<std::uint8_t> priOpen =
            ApbUdp::BuildActorOpenPacket(
                account->AllocateServerPacketId(),
                kPriChannel,
                priSequence,
                priArchetype,
                0.0f, 0.0f, 0.0f);

        const bool openSent = SendProtectedPacket(
            socket, endpoint, account, priOpen, "PRI-OPEN");

        Logger(openSent ? lSUCCESS : lERROR, "District Net",
            "PRI open sent=%d ch=%u seq=%u archetypeNetIndex=%u",
            openSent ? 1 : 0,
            static_cast<unsigned int>(kPriChannel),
            static_cast<unsigned int>(priSequence),
            static_cast<unsigned int>(priArchetype));

        if (!openSent)
            return false;

        // 2. Controller.PlayerReplicationInfo = <актор на канале 5>.
        std::vector<ApbUdp::DebugParam> params(1u);
        params[0].Kind = "object";
        params[0].A    = static_cast<std::int64_t>(kPriChannel);

        const std::uint16_t linkSequence =
            AllocateChannelSequence(account, kControllerChannel);

        std::vector<std::uint8_t> link =
            ApbUdp::BuildActorParamsFieldPacket(
                account->AllocateServerPacketId(),
                kControllerChannel,
                linkSequence,
                kFieldPlayerReplicationInfo,
                kControllerFieldMax,
                params);

        const bool linkSent = SendProtectedPacket(
            socket, endpoint, account, link, "PRI-LINK");

        Logger(linkSent ? lSUCCESS : lERROR, "District Net",
            "PlayerReplicationInfo link sent=%d ch=%u seq=%u field=%u "
            "refChannel=%u",
            linkSent ? 1 : 0,
            static_cast<unsigned int>(kControllerChannel),
            static_cast<unsigned int>(linkSequence),
            static_cast<unsigned int>(kFieldPlayerReplicationInfo),
            static_cast<unsigned int>(kPriChannel));

        return linkSent;
    }
	    // Engine.PlayerController.ClientSetHUD(class<HUD>, class<Scoreboard>)
    // LIVE FClassNetCache: field 42, fieldMax 684.
    // Оба параметра -- ClassProperty, идут как ссылки через package map.
    // Scoreboard передаём null: presence-бит 0.
    bool SendClientSetHUD(
        SOCKET socket,
        const sockaddr_in& endpoint,
        Account* account,
        std::uint32_t hudClassNetIndex)
    {
        if (account == nullptr || hudClassNetIndex == kBadNetIndex)
            return false;

        constexpr std::uint32_t kFieldClientSetHUD = 42u;

        std::vector<ApbUdp::DebugParam> params(2u);
        params[0].Kind = "classp";
        params[0].A    = static_cast<std::int64_t>(hudClassNetIndex);
        params[1].Kind = "classp";
        params[1].A    = 0;                    // newScoringType = None

        const std::uint16_t seq =
            AllocateChannelSequence(account, kControllerChannel);

        std::vector<std::uint8_t> packet =
            ApbUdp::BuildActorParamsFieldPacket(
                account->AllocateServerPacketId(),
                kControllerChannel,
                seq,
                kFieldClientSetHUD,
                kControllerFieldMax,
                params);

        const bool sent = SendProtectedPacket(
            socket, endpoint, account, packet, "CLIENT-SET-HUD");

        Logger(sent ? lSUCCESS : lERROR, "District Net",
            "ClientSetHUD sent=%d ch=%u seq=%u field=%u hudClassNetIndex=%u",
            sent ? 1 : 0,
            static_cast<unsigned int>(kControllerChannel),
            static_cast<unsigned int>(seq),
            static_cast<unsigned int>(kFieldClientSetHUD),
            static_cast<unsigned int>(hudClassNetIndex));

        return sent;
    }
    
	    // ---------------------------------------------------------------------
    // cAPBPlayerController.ClientSetInitialState(
    //     int nCharacterUID,
    //     byte Faction,
    //     byte Gender)
    //
    // APB 1.13.1 LIVE FClassNetCache:
    //   FieldIndex = 573
    //   FieldMax   = 684
    //
    // В ApbUdp уже есть специальный builder, который правильно пишет
    // presence/non-default bits для всех трёх RPC-параметров.
    // ---------------------------------------------------------------------
    bool SendClientSetInitialState(
        SOCKET socket,
        const sockaddr_in& endpoint,
        Account* account)
    {
        if (account == nullptr)
            return false;

        if (!account->HasCharacterProfile())
        {
            Logger(
                lERROR,
                "District Net",
                "ClientSetInitialState not sent: character profile is missing.");
            return false;
        }

        const std::uint32_t characterId =
            account->GetCharacterId();

        const std::uint8_t faction =
            account->GetCharacterFaction();

        const std::uint8_t gender =
            account->GetCharacterGender();

        // Reflection:
        //   etFaction -> 5 enum entries
        //   etGender  -> 5 enum entries
        //
        // 0..4 допустимы. Для обычного выбранного персонажа ожидаются
        // реальные faction/gender, а не MAX.
        if (faction >= 5u || gender >= 5u)
        {
            Logger(
                lERROR,
                "District Net",
                "ClientSetInitialState not sent: invalid profile "
                "characterUID=%u faction=%u gender=%u",
                static_cast<unsigned int>(characterId),
                static_cast<unsigned int>(faction),
                static_cast<unsigned int>(gender));

            return false;
        }

        const std::uint16_t seq =
            AllocateChannelSequence(
                account,
                kControllerChannel);

        std::vector<std::uint8_t> packet =
            ApbUdp::BuildClientSetInitialStatePacket(
                account->AllocateServerPacketId(),
                kControllerChannel,
                seq,
                kFieldClientSetInitialState,
                kControllerFieldMax,
                static_cast<std::int32_t>(characterId),
                faction,
                gender);

        if (packet.empty())
        {
            Logger(
                lERROR,
                "District Net",
                "BuildClientSetInitialStatePacket returned empty packet.");
            return false;
        }

        const bool sent =
            SendProtectedPacket(
                socket,
                endpoint,
                account,
                packet,
                "CLIENT-SET-INITIAL-STATE");

        Logger(
            sent ? lSUCCESS : lERROR,
            "District Net",
            "ClientSetInitialState sent=%d ch=%u seq=%u field=%u "
            "characterUID=%u faction=%u gender=%u",
            sent ? 1 : 0,
            static_cast<unsigned int>(kControllerChannel),
            static_cast<unsigned int>(seq),
            static_cast<unsigned int>(kFieldClientSetInitialState),
            static_cast<unsigned int>(characterId),
            static_cast<unsigned int>(faction),
            static_cast<unsigned int>(gender));

        return sent;
    }


    // ---------------------------------------------------------------------
    // cAPBPlayerController.ClientGoToSpawnZoneSelectScreen(
    //     byte eFaction)
    //
    // APB 1.13.1 LIVE FClassNetCache:
    //   FieldIndex = 390
    //   FieldMax   = 684
    //
    // В ApbUdp уже есть специальный builder с правильным
    // ByteProperty RPC presence-bit + SerializeInt(eFaction, 5).
    // ---------------------------------------------------------------------
    bool SendClientGoToSpawnZoneSelectScreen(
        SOCKET socket,
        const sockaddr_in& endpoint,
        Account* account)
    {
        if (account == nullptr)
            return false;

        if (!account->HasCharacterProfile())
        {
            Logger(
                lERROR,
                "District Net",
                "ClientGoToSpawnZoneSelectScreen not sent: "
                "character profile is missing.");
            return false;
        }

        const std::uint8_t faction =
            account->GetCharacterFaction();

        if (faction >= 5u)
        {
            Logger(
                lERROR,
                "District Net",
                "ClientGoToSpawnZoneSelectScreen not sent: "
                "invalid faction=%u",
                static_cast<unsigned int>(faction));

            return false;
        }

        const std::uint16_t seq =
            AllocateChannelSequence(
                account,
                kControllerChannel);

        std::vector<std::uint8_t> packet =
            ApbUdp::BuildClientGoToSpawnZoneSelectScreenPacket(
                account->AllocateServerPacketId(),
                kControllerChannel,
                seq,
                kFieldClientGoToSpawnZoneSelectScreen,
                kControllerFieldMax,
                faction);

        if (packet.empty())
        {
            Logger(
                lERROR,
                "District Net",
                "BuildClientGoToSpawnZoneSelectScreenPacket "
                "returned empty packet.");
            return false;
        }

        const bool sent =
            SendProtectedPacket(
                socket,
                endpoint,
                account,
                packet,
                "CLIENT-GOTO-SPAWN-ZONE-SELECT");

        Logger(
            sent ? lSUCCESS : lERROR,
            "District Net",
            "ClientGoToSpawnZoneSelectScreen sent=%d "
            "ch=%u seq=%u field=%u faction=%u",
            sent ? 1 : 0,
            static_cast<unsigned int>(kControllerChannel),
            static_cast<unsigned int>(seq),
            static_cast<unsigned int>(
                kFieldClientGoToSpawnZoneSelectScreen),
            static_cast<unsigned int>(faction));

        return sent;
    }

bool SendSocialLevelStreaming(
    SOCKET socket,
    const sockaddr_in& endpoint,
    Account* account)
{
    if (account == nullptr)
        return false;

    constexpr std::size_t planCount =
        sizeof(kSocialStreamingPlan) /
        sizeof(kSocialStreamingPlan[0]);

    Logger(
        lINFO,
        "District Streaming",
        "Starting Social streaming plan: entries=%u",
        static_cast<unsigned int>(planCount));

    for (std::size_t index = 0;
         index < planCount;
         ++index)
    {
        const StreamingPlanEntry& entry =
            kSocialStreamingPlan[index];

        const std::uint32_t packetId =
            account->AllocateServerPacketId();

        const std::uint16_t sequence =
            AllocateChannelSequence(
                account,
                kControllerChannel);

        std::vector<std::uint8_t> packet =
            ApbUdp::BuildLevelStreamingStatusPacket(
                packetId,
                kControllerChannel,
                sequence,
                kFieldClientUpdateLevelStreamingStatus,
                kControllerFieldMax,
                entry.PackageName,
                entry.ShouldBeLoaded,
                entry.ShouldBeVisible,
                entry.ShouldBlockOnLoad,
                false,
                3);

        if (packet.empty())
        {
            Logger(
                lERROR,
                "District Streaming",
                "BuildLevelStreamingStatusPacket returned empty: "
                "entry=%u package=%s",
                static_cast<unsigned int>(index + 1),
                entry.PackageName);

            return false;
        }

        const bool sent =
            SendProtectedPacket(
                socket,
                endpoint,
                account,
                packet,
                "LEVEL-STREAM");

        Logger(
        sent ? lSUCCESS : lERROR,
        "District Streaming",
        "ClientUpdateLevelStreamingStatus sent=%d "
        "entry=%u/%u packetId=%u ch=%u seq=%u "
        "field=%u package='%s' loaded=%d visible=%d block=%d",
        sent ? 1 : 0,
        static_cast<unsigned int>(index + 1),
        static_cast<unsigned int>(planCount),
        static_cast<unsigned int>(packetId),
        static_cast<unsigned int>(kControllerChannel),
        static_cast<unsigned int>(sequence),
        static_cast<unsigned int>(
            kFieldClientUpdateLevelStreamingStatus),
        entry.PackageName,
        entry.ShouldBeLoaded ? 1 : 0,
        entry.ShouldBeVisible ? 1 : 0,
        entry.ShouldBlockOnLoad ? 1 : 0);

        if (!sent)
            return false;
    }

    // ВОТ СЮДА
    Logger(
        lINFO,
        "District Streaming",
        "DIAGNOSTIC: all 17 corrected field-92 entries sent; "
        "stopping before ClientFlushLevelStreaming.");

    return true;

    // Ниже существующий Flush пока недостижим.
    const std::uint32_t flushPacketId =
        account->AllocateServerPacketId();

    const std::uint16_t flushSequence =
        AllocateChannelSequence(
            account,
            kControllerChannel);

    std::vector<std::uint8_t> flushPacket =
        ApbUdp::BuildActorVoidFieldPacket(
            flushPacketId,
            kControllerChannel,
            flushSequence,
            kFieldClientFlushLevelStreaming,
            kControllerFieldMax);

    if (flushPacket.empty())
        return false;

    const bool flushSent =
        SendProtectedPacket(
            socket,
            endpoint,
            account,
            flushPacket,
            "FLUSH-STREAMING");

    return flushSent;
}

        bool ProcessBinaryHandshakePacket(
        SOCKET socket,
        const sockaddr_in& endpoint,
        Account*& account,
        const ApbUdp::Packet& packet)
    {
        bool handledAny = false;

        for (const ApbUdp::Bunch& bunch : packet.Bunches)
        {
            ApbUdp::ControlReader reader;
            if (!ApbUdp::OpenControlReader(bunch, reader))
                continue;

            std::uint8_t messageType = 0;

            while (reader.ReadByte(messageType))
            {
                const std::size_t bodyStart = reader.Pos;

                Logger(
                    lINFO,
                    "District Binary Control",
                    "RX message=%u packetId=%u open=%d paused=%d "
                    "bytesLeft=%u",
                    static_cast<unsigned int>(messageType),
                    static_cast<unsigned int>(packet.PacketId),
                    bunch.Open ? 1 : 0,
                    bunch.ReplicationPaused ? 1 : 0,
                    static_cast<unsigned int>(reader.Remaining()));

                if (messageType == NMT_Netspeed)
                {
                    std::int32_t rate = 0;
                    if (!reader.ReadInt32(rate))
                        break;

                    Logger(lINFO, "District Net",
                        "NMT_Netspeed(4) rate=%d", rate);

                    handledAny = true;
                    continue;
                }

                if (messageType == NMT_Login)
                {
                    std::string response;
                    std::string url;
                    std::uint64_t uniqueId = 0;

                    if (!reader.ReadFString(response) ||
                        !reader.ReadFString(url) ||
                        !reader.ReadUInt64(uniqueId))
                    {
                        Logger(lERROR, "District Net",
                            "NMT_Login(5) truncated at byte %u/%u",
                            static_cast<unsigned int>(reader.Pos),
                            static_cast<unsigned int>(reader.Size));
                        break;
                    }

                    Logger(lSUCCESS, "District Net",
                        "NMT_Login(5) response='%s' url='%s' uid=0x%016llX",
                        response.c_str(),
                        url.c_str(),
                        static_cast<unsigned long long>(uniqueId));

					SendPackageUses(socket, endpoint, account);   // <- должен быть активен
                    SendNetWelcome(socket, endpoint, account);
                    
                    handledAny = true;
                    continue;
                }

                if (messageType == NMT_HandshakeStart)
                {
                    // V10 interpretation of the 25-byte body:
                    //   byte        platform candidate
                    //   uint32 LE   account-id candidate
                    //   20 bytes    auth-token candidate
                    const std::size_t bodyRemaining = reader.Remaining();

                    std::uint8_t handshakePlatform = 0;
                    std::uint32_t handshakeAccountId = 0;
                    const std::uint8_t* handshakeToken = nullptr;
                    const bool bodyOk = (bodyRemaining == 25u);

                    if (bodyOk)
                    {
                        const std::uint8_t* body =
                            reader.Data + reader.Pos;

                        handshakePlatform = body[0];
                        handshakeAccountId =
                            static_cast<std::uint32_t>(body[1]) |
                            (static_cast<std::uint32_t>(body[2]) << 8) |
                            (static_cast<std::uint32_t>(body[3]) << 16) |
                            (static_cast<std::uint32_t>(body[4]) << 24);
                        handshakeToken = body + 5;

                        Logger(
                            lSUCCESS,
                            "District HandshakeStart V10",
                            "body=25 platformCandidate=%u accountCandidate=%u "
                            "token20=%s",
                            static_cast<unsigned int>(handshakePlatform),
                            static_cast<unsigned int>(handshakeAccountId),
                            Hex(handshakeToken, 20, 20).c_str());
                    }
                    else
                    {
                        Logger(
                            lWARN,
                            "District HandshakeStart V10",
                            "Unexpected HandshakeStart body size: %u "
                            "(expected 25 after opcode).",
                            static_cast<unsigned int>(bodyRemaining));
                    }

                    if (account == nullptr)
                    {
                        account = FindOnlyPendingAccount();

                        if (account == nullptr)
                        {
                            Logger(
                                lERROR,
                                "District Handshake",
                                "NMT_HandshakeStart from %s could not be "
                                "associated with exactly one pending "
                                "WorldServer handoff.",
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
                            "Bound %s to pending account %u from "
                            "WorldServer handoff.",
                            EndpointText(endpoint).c_str(),
                            static_cast<unsigned int>(account->GetId()));
                    }

                    if (bodyOk)
                    {
                        Logger(
                            handshakeAccountId == account->GetId()
                                ? lSUCCESS
                                : lWARN,
                            "District HandshakeStart V10",
                            "accountCandidate=%u handoffAccount=%u match=%d; "
                            "platformCandidate=%u",
                            static_cast<unsigned int>(handshakeAccountId),
                            static_cast<unsigned int>(account->GetId()),
                            handshakeAccountId == account->GetId() ? 1 : 0,
                            static_cast<unsigned int>(handshakePlatform));
                    }

                    account->SetLastClientPacketId(packet.PacketId);

                    const HandshakeProbeMode probeMode =
                        GetHandshakeProbeMode();

                    Logger(
                        lINFO,
                        "District Handshake V10",
                        "Probe mode=%s (set RAPB_HANDSHAKE_PROBE="
                        "ack|challenge|complete|welcome before launch).",
                        HandshakeProbeModeText(probeMode));

                    bool probeSent = false;

                    switch (probeMode)
                    {
                    case HandshakeProbeMode::Ack:
                        probeSent =
                            SendAck(socket, endpoint, account, packet.PacketId);

                        Logger(
                            probeSent ? lSUCCESS : lERROR,
                            "District Handshake V10",
                            "ACK-only modern-header probe; sent=%d.",
                            probeSent ? 1 : 0);
                        break;

                    case HandshakeProbeMode::Complete:
                        probeSent =
                            SendHandshakeComplete(
                                socket, endpoint, account, packet.PacketId);

                        Logger(
                            probeSent ? lSUCCESS : lERROR,
                            "District Handshake V10",
                            "ACK + NMT_HandshakeComplete(29) modern-header "
                            "probe; sent=%d.",
                            probeSent ? 1 : 0);
                        break;

                    case HandshakeProbeMode::Welcome:
                    {
                        const bool ackSent =
                            SendAck(socket, endpoint, account, packet.PacketId);
                        const bool welcomeSent =
                            SendWelcome(socket, endpoint, account);

                        probeSent = ackSent && welcomeSent;

                        Logger(
                            probeSent ? lSUCCESS : lERROR,
                            "District Handshake V10",
                            "ACK + WELCOME modern-header probe; ACK=%d "
                            "WELCOME=%d.",
                            ackSent ? 1 : 0,
                            welcomeSent ? 1 : 0);
                        break;
                    }

                    case HandshakeProbeMode::Challenge:
                    default:
                        probeSent =
                            SendHandshakeChallenge(
                                socket, endpoint, account, packet.PacketId);

                        Logger(
                            probeSent ? lSUCCESS : lERROR,
                            "District Handshake V10",
                            "ACK + NMT_HandshakeChallenge(27) modern-header "
                            "probe; challenge=0x%08X sent=%d.",
                            static_cast<unsigned int>(kHandshakeChallengeValue),
                            probeSent ? 1 : 0);
                        break;
                    }

                    return true;
                }

                if (messageType == NMT_HandshakeResponse)
                {
                    if (account == nullptr)
                        return true;

                    std::uint32_t response = 0;
                    if (reader.Remaining() >= 4)
                    {
                        const std::uint8_t* body = reader.Data + reader.Pos;
                        response =
                            static_cast<std::uint32_t>(body[0]) |
                            (static_cast<std::uint32_t>(body[1]) << 8) |
                            (static_cast<std::uint32_t>(body[2]) << 16) |
                            (static_cast<std::uint32_t>(body[3]) << 24);
                        reader.Pos += 4;
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
                        socket, endpoint, account, packet.PacketId);

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

                if (messageType == NMT_Hello)
                {
                    if (account == nullptr)
                        return true;

                    std::int32_t values[3] = { 0, 0, 0 };
                    for (std::size_t i = 0; i < 3; ++i)
                    {
                        if (!reader.ReadInt32(values[i]))
                            break;
                    }

                    Logger(
                        lSUCCESS,
                        "District Net",
                        "NMT_Hello(0) from account %u: minVer=%d ver=%d "
                        "extra=%d",
                        static_cast<unsigned int>(account->GetId()),
                        values[0], values[1], values[2]);

                    SendNetChallenge(socket, endpoint, account, packet.PacketId);
                    return true;
                }
                                if (messageType == NMT_Join)
                {
                    if (account == nullptr)
                        return true;

                    account->SetHandshakeState(
                        Account::HandshakeState::Complete);
                    ResetChannelSequences(account);
					ResetGriStartupState(account);

                    Logger(lSUCCESS, "District Net",
                        "NMT_Join(9) from account %u",
                        static_cast<unsigned int>(account->GetId()));

                    // PlayerController.
                    // Архетип: 33506 (база APBGame) + 12773 (local) = 46279.
                    // Default__cAPBPlayerController.bNetInitialRotation=false,
                    // поэтому поворот не пишем; NetPlayerIndex=0 -- локальный
                    // вьюпорт, именно он заставляет клиента считать актора
                    // своим контроллером.
                    const std::uint32_t playerArchetype =
                        GlobalNetIndex("APBGame", kPlayerControllerLocalNetIndex);

                    if (playerArchetype == kBadNetIndex)
                    {
                        Logger(lERROR, "District Net",
                            "APBGame is not in the Uses list");
                        continue;
                    }

                    const std::uint16_t playerSequence =
                        AllocateChannelSequence(account, kControllerChannel);

                    std::vector<std::uint8_t> playerControllerOpen =
                        ApbUdp::BuildPlayerControllerOpenPacket(
                            account->AllocateServerPacketId(),
                            kControllerChannel,
                            playerSequence,
                            playerArchetype,
                            0.0f, 0.0f, 0.0f,
                            0u);

                    const bool pcSent = SendProtectedPacket(
                        socket, endpoint, account,
                        playerControllerOpen, "PLAYERCONTROLLER-OPEN");

                    Logger(pcSent ? lSUCCESS : lERROR, "District Net",
                        "PlayerController open sent=%d ch=%u seq=%u "
                        "archetypeNetIndex=%u NetPlayerIndex=0",
                        pcSent ? 1 : 0,
                        static_cast<unsigned int>(kControllerChannel),
                        static_cast<unsigned int>(playerSequence),
                        static_cast<unsigned int>(playerArchetype));

                    // GameReplicationInfo.
                    // Архетип: 33506 + 13049 = 46555.
                    const std::uint32_t griArchetype =
                        GlobalNetIndex("APBGame", kGriLocalNetIndex);

                    if (griArchetype != kBadNetIndex)
                    {
                        const std::uint16_t griSequence =
                            AllocateChannelSequence(account, kGriChannel);

                        const std::uint32_t griOpenPacketId =
    					account->AllocateServerPacketId();

						std::vector<std::uint8_t> griOpen =
    						ApbUdp::BuildActorOpenPacket(
        						griOpenPacketId,
        						kGriChannel,
        						griSequence,
        						griArchetype,
        						0.0f, 0.0f, 0.0f);

                        const bool griSent = SendProtectedPacket(
                            socket, endpoint, account, griOpen, "GRI-OPEN");
						if (griSent)
{
    TrackGriOpenPacket(
        account,
        griOpenPacketId);

    Logger(
        lINFO,
        "District GRI Startup",
        "Tracking GRI actor-open ACK: "
        "account=%u packetId=%u ch=%u seq=%u",
        static_cast<unsigned int>(
            account->GetId()),
        static_cast<unsigned int>(
            griOpenPacketId),
        static_cast<unsigned int>(
            kGriChannel),
        static_cast<unsigned int>(
            griSequence));
}

                        Logger(griSent ? lSUCCESS : lERROR, "District Net",
                            "GRI open sent=%d ch=%u seq=%u archetypeNetIndex=%u",
                            griSent ? 1 : 0,
                            static_cast<unsigned int>(kGriChannel),
                            static_cast<unsigned int>(griSequence),
                            static_cast<unsigned int>(griArchetype));
                    }

                    continue;
                }

                Logger(lWARN, "District Net",
                    "Unhandled control message %u, %u bytes left; stop "
                    "parsing bunch",
                    static_cast<unsigned int>(messageType),
                    static_cast<unsigned int>(reader.Remaining() -
                        (reader.Pos - bodyStart)));
                break;
            }
        }

        return handledAny;
    }

	void ProcessServerPacketAcks(
    SOCKET socket,
    const sockaddr_in& endpoint,
    Account* account,
    const ApbUdp::Packet& packet)
{
    if (account == nullptr)
        return;

    for (const ApbUdp::Bunch& bunch :
         packet.Bunches)
    {
        if (bunch.Kind !=
            ApbUdp::BunchKind::Ack)
        {
            continue;
        }

        const std::uint32_t ackedPacketId =
            bunch.AckPacketId;

        if (!ConsumeGriOpenAck(
                account,
                ackedPacketId))
        {
            continue;
        }

        Logger(
            lSUCCESS,
            "District GRI Startup",
            "GRI actor-open ACK received: "
            "account=%u ACK(%u). "
            "Sending bMatchHasBegun=true.",
            static_cast<unsigned int>(
                account->GetId()),
            static_cast<unsigned int>(
                ackedPacketId));

        if (!SendGriMatchHasBegun(
                socket,
                endpoint,
                account))
        {
            Logger(
                lERROR,
                "District GRI Startup",
                "Failed to send "
                "bMatchHasBegun=true after "
                "GRI actor-open ACK.");
        }
    }
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


    // APB 1.13.1 / UE3 build 3908, read directly from the live heap
    // FClassNetCache for APBGame.cAPBPlayerController:
    //   GetMaxIndex() = 684
    //   138 = Receive_GC2DS_ASK_DISTRICT_ENTER
    //   139 = Receive_DS2GC_ANS_DISTRICT_ENTER
    //
    // Live UFunction reflection confirms three int32 parameters:
    //   nReturnCode @ +0x00
    //   nDistrictUID @ +0x04
    //   nInstanceNo @ +0x08
    //
    // The server opened channel 1 with reliable sequence 1, so the next
    // server->client reliable bunch on that channel is sequence 2.
    bool ProcessPlayerControllerActorPacket(
        SOCKET socket,
        const sockaddr_in& endpoint,
        Account* account,
        const ApbUdp::Packet& packet)
    {
        if (account == nullptr)
            return false;

        for (const ApbUdp::Bunch& bunch : packet.Bunches)
        {
            if (bunch.Kind != ApbUdp::BunchKind::Data ||
                bunch.ChannelIndex != kControllerChannel)
            {
                continue;
            }

            std::uint32_t fieldIndex = 0;
            std::size_t parameterBits = 0;
            std::string decodeError;

                       const bool decoded = ApbUdp::DecodeActorFieldIndex(
                    bunch,
                    kControllerFieldMax,
                    fieldIndex,
                    parameterBits,
                    decodeError);

            if (!decoded)
            {
                Logger(lWARN, "District RX",
                    "ch=%u rel=%d seq=%u bits=%u DECODE FAILED: %s",
                    static_cast<unsigned int>(bunch.ChannelIndex),
                    bunch.Reliable ? 1 : 0,
                    static_cast<unsigned int>(bunch.ChannelSequence),
                    static_cast<unsigned int>(bunch.DataBitCount),
                    decodeError.c_str());
                continue;
            }

            Logger(lINFO, "District RX",
                "ch=%u rel=%d seq=%u bits=%u field=%u paramBits=%u",
                static_cast<unsigned int>(bunch.ChannelIndex),
                bunch.Reliable ? 1 : 0,
                static_cast<unsigned int>(bunch.ChannelSequence),
                static_cast<unsigned int>(bunch.DataBitCount),
                static_cast<unsigned int>(fieldIndex),
                static_cast<unsigned int>(parameterBits));

                        if (fieldIndex == kFieldServerSyncState ||
                			fieldIndex == kFieldServerUseAutoReady)
            {
                // Клиент сообщает, ответа не ждёт.
                continue;
            }
            if (fieldIndex == kFieldServerNotifyClientLoaded)
            {
                Logger(
                    lSUCCESS,
                    "District Bootstrap",
                    "ServerNotifyClientLoaded received: account=%u",
                    account->GetId());

                const bool priSent =
                    SendPlayerReplicationInfo(
                        socket,
                        endpoint,
                        account);

                Logger(
                    priSent ? lSUCCESS : lERROR,
                    "District Bootstrap",
                    "Post-load PRI sent=%d",
                    priSent ? 1 : 0);

                continue;
            }
            
            if (fieldIndex != kFieldAskDistrictEnter)
                continue;

            const std::int32_t districtUid =
                static_cast<std::int32_t>(
                    g_cfg != nullptr ? g_cfg->GetDistrictType() : 1);

            std::vector<ApbUdp::DebugParam> params(3u);
            params[0].Kind = "int";  params[0].A = 0;           // nReturnCode
            params[1].Kind = "int";  params[1].A = districtUid; // nDistrictUID
            params[2].Kind = "int";  params[2].A = 1;           // nInstanceNo

            const std::uint16_t answerSequence =
                AllocateChannelSequence(account, kControllerChannel);

            std::vector<std::uint8_t> answer =
                ApbUdp::BuildActorParamsFieldPacket(
                    account->AllocateServerPacketId(),
                    kControllerChannel,
                    answerSequence,
                    kFieldAnsDistrictEnter,
                    kControllerFieldMax,
                    params);

            const bool sent = SendProtectedPacket(
                socket, endpoint, account, answer, "DISTRICT-ENTER-ANSWER");

            Logger(sent ? lSUCCESS : lERROR, "District Handshake",
                "ASK(%u) -> ANS(%u) sent=%d returnCode=0 districtUID=%d "
                "instanceNo=1 ch=%u seq=%u fieldMax=%u reqParamBits=%u",
                static_cast<unsigned int>(kFieldAskDistrictEnter),
                static_cast<unsigned int>(kFieldAnsDistrictEnter),
                sent ? 1 : 0,
                districtUid,
                static_cast<unsigned int>(kControllerChannel),
                static_cast<unsigned int>(answerSequence),
                static_cast<unsigned int>(kControllerFieldMax),
                static_cast<unsigned int>(parameterBits));

            if (sent)
            {
                // Reference lifecycle:
                // ANS_DISTRICT_ENTER
                //   -> 750 ms settle
                //   -> 500 ms GRI/startup settle
                //   -> ClientSetHUD
                //   -> 250 ms
                //   -> ClientSetInitialState
                //   -> 50 ms
                //   -> ClientGoToSpawnZoneSelectScreen
                //   -> 250 ms
                //   -> STOP before streaming

                Logger(
                    lINFO,
                    "District Bootstrap",
                    "ANS_DISTRICT_ENTER sent; waiting 750 ms before "
                    "controller startup.");

                Sleep(750);

                Logger(
                    lINFO,
                    "District Bootstrap",
                    "Waiting 500 ms GRI/startup settle.");

                Sleep(500);

                // ---------------------------------------------------------
                // Stage 1: HUD.
                // ---------------------------------------------------------
                const bool hudSent =
                    SendClientSetHUD(
                        socket,
                        endpoint,
                        account,
                        GlobalNetIndex(
                            "APBGame",
                            kHudClassLocalNetIndex));

                if (!hudSent)
                {
                    Logger(
                        lERROR,
                        "District Bootstrap",
                        "ClientSetHUD failed; stopping bootstrap.");

                    return sent;
                }

                // Reference HUD -> startup settle.
                Sleep(250);

                // ---------------------------------------------------------
                // IMPORTANT:
                // PRI is intentionally NOT opened here.
                // Reference emulator creates/links PRI later with pawn bootstrap.
                // ---------------------------------------------------------

                // ---------------------------------------------------------
                // Stage 2: local character identity.
                // ---------------------------------------------------------
                const bool initialStateSent =
                    SendClientSetInitialState(
                        socket,
                        endpoint,
                        account);

                if (!initialStateSent)
                {
                    Logger(
                        lERROR,
                        "District Bootstrap",
                        "ClientSetInitialState failed; stopping bootstrap.");

                    return sent;
                }

                Sleep(50);

                // ---------------------------------------------------------
                // Stage 3: MapSelect.
                // ---------------------------------------------------------
                const bool spawnZoneScreenSent =
                    SendClientGoToSpawnZoneSelectScreen(
                        socket,
                        endpoint,
                        account);

                if (!spawnZoneScreenSent)
                {
                    Logger(
                        lERROR,
                        "District Bootstrap",
                        "ClientGoToSpawnZoneSelectScreen failed; "
                        "stopping bootstrap.");

                    return sent;
                }

                // Give BeginState(Map Select) time to complete.
                Sleep(250);

                // ---------------------------------------------------------
                // Stage 4: Social district streaming.
                // 17 x ClientUpdateLevelStreamingStatus
                // + ClientFlushLevelStreaming
                // ---------------------------------------------------------
                const bool streamingSent =
                    SendSocialLevelStreaming(
                        socket,
                        endpoint,
                        account);

                if (!streamingSent)
                {
                    Logger(
                        lERROR,
                        "District Streaming",
                        "Corrected field-92 diagnostic failed.");

                    return sent;
                }

                Logger(
                    lSUCCESS,
                    "District Bootstrap",
                    "post-enter bootstrap: HUD=%d PRI=DEFERRED "
                    "InitialState=%d SpawnZoneScreen=%d Streaming=%d",
                    hudSent ? 1 : 0,
                    initialStateSent ? 1 : 0,
                    spawnZoneScreenSent ? 1 : 0,
                    streamingSent ? 1 : 0);
            }

            return sent;
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

            // Packet-level ACK для любого пакета с data-bunch'ами.
            // UE3 держит reliable bunch в очереди отправки, пока не придёт
            // подтверждение несущего его пакета, поэтому подтверждать надо
            // до разбора сообщения и независимо от того, какой обработчик
            // потом заберёт пакет. Дубликаты гасит ShouldAckClientPacket.
            {
                Account* ackAccount = endpointAccount;

                if (ackAccount == nullptr)
                    ackAccount = FindAccountByEndpoint(remoteAddress);

                if (ackAccount != nullptr)
                {
                    bool hasDataBunch = false;

                    for (const ApbUdp::Bunch& bunch : packet.Bunches)
                    {
                        if (bunch.Kind == ApbUdp::BunchKind::Data)
                        {
                            hasDataBunch = true;
                            break;
                        }
                    }

                    if (hasDataBunch)
                    {
                        SendAck(
                            socketHandle,
                            remoteAddress,
                            ackAccount,
                            packet.PacketId);
                    }
                }
            }
            // Client ACKs of packets previously sent by the server.
// Process these before controller RPCs from the same incoming
// packet: ACK(GRI-OPEN) and ASK_DISTRICT_ENTER may arrive together.
{
    Account* ackedAccount =
        endpointAccount;

    if (ackedAccount == nullptr)
    {
        ackedAccount =
            FindAccountByEndpoint(
                remoteAddress);
    }

    if (ackedAccount != nullptr)
    {
        ProcessServerPacketAcks(
            socketHandle,
            remoteAddress,
            ackedAccount,
            packet);
    }
}

            // Packet ACK only retires transport reliability. Handle the APB
            // application-level PlayerController RPC separately.
            {
                Account* actorAccount = endpointAccount;

                if (actorAccount == nullptr)
                    actorAccount = FindAccountByEndpoint(remoteAddress);

                if (actorAccount != nullptr)
                {
                    ProcessPlayerControllerActorPacket(
                        socketHandle,
                        remoteAddress,
                        actorAccount,
                        packet);
                }
            }

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
			
			// WorldServer immediately follows the 16-byte session key with:
//
//   int32 CharacterUID
//   uint8 Faction
//   uint8 Gender
//   uint8 AppearanceVersion
//
// Total: 7 bytes.
std::unique_ptr<char[]> profilePayload(
    g_world->Receive(7));

if (!profilePayload)
{
    Logger(
        lERROR,
        "WorldControl",
        "Failed to receive 7-byte character profile "
        "for account %u",
        static_cast<unsigned int>(accountId));

    return false;
}

std::uint32_t characterId = 0;

std::memcpy(
    &characterId,
    profilePayload.get(),
    sizeof(characterId));

const std::uint8_t faction =
    static_cast<std::uint8_t>(
        profilePayload[4]);

const std::uint8_t gender =
    static_cast<std::uint8_t>(
        profilePayload[5]);

const std::uint8_t appearanceVersion =
    static_cast<std::uint8_t>(
        profilePayload[6]);			

           Account* account =
    AddOrUpdateAccount(
        accountId,
        encryptionKey);

account->SetCharacterProfile(
    characterId,
    faction,
    gender,
    appearanceVersion,
    std::string(),
    std::string(),
    std::vector<std::uint8_t>());

Logger(
    lSUCCESS,
    "WorldControl",
    "Character profile handoff: "
    "account=%u characterUID=%u faction=%u "
    "gender=%u appearanceVersion=%u",
    static_cast<unsigned int>(accountId),
    static_cast<unsigned int>(characterId),
    static_cast<unsigned int>(faction),
    static_cast<unsigned int>(gender),
    static_cast<unsigned int>(appearanceVersion));

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

	static_assert(sizeof(kPackages) / sizeof(kPackages[0]) == 3, "");
	// в инициализации сервера:
	Logger(lINFO, "District Net",
    "PackageMap plan: Core@0 Engine@%u APBGame@%u, "
    "Default__cAPBPlayerController -> %u",
    PackageFirstNetIndex("Engine"),
    PackageFirstNetIndex("APBGame"),
    GlobalNetIndex("APBGame", kPlayerControllerLocalNetIndex));
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
