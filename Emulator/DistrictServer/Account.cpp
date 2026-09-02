#include "stdafx.h"
#include "Account.h"

#include <algorithm>

Account::Account(
    std::uint32_t id,
    const std::uint8_t authToken[20],
    const std::uint8_t encryptionKey[16])
    : Id(id),
      CharacterProfileAvailable(false),
      CharacterId(0),
      CharacterFaction(0),
      CharacterGender(0),
      AppearanceVersion(0),
      EndpointBound(false),
      EndpointAddress(0),
      EndpointPort(0),
      Authenticated(false),
      NextServerPacketId(0),
      NextServerReliableSequence(1),
      LastClientPacketId(0),
      HandshakeChallenge(0),
      CurrentHandshakeState(HandshakeState::WaitingForAuth),
      ChallengeSendCount(0),
      UdpReceiveCount(0)
{
    std::copy(authToken, authToken + AuthToken.size(), AuthToken.begin());
    std::copy(encryptionKey, encryptionKey + EncryptionKey.size(), EncryptionKey.begin());
}

std::uint32_t Account::GetId() const
{
    std::lock_guard<std::mutex> lock(Mutex);
    return Id;
}

void Account::UpdateKeys(
    const std::uint8_t authToken[20],
    const std::uint8_t encryptionKey[16])
{
    std::lock_guard<std::mutex> lock(Mutex);
    std::copy(authToken, authToken + AuthToken.size(), AuthToken.begin());
    std::copy(encryptionKey, encryptionKey + EncryptionKey.size(), EncryptionKey.begin());
    EndpointBound = false;
    EndpointAddress = 0;
    EndpointPort = 0;
    Authenticated = false;
    NextServerPacketId = 0;
    NextServerReliableSequence = 1;
    LastClientPacketId = 0;
    HandshakeChallenge = 0;
    CurrentHandshakeState = HandshakeState::WaitingForAuth;
    ChallengeSendCount = 0;
    UdpReceiveCount = 0;
}

std::array<std::uint8_t, 20> Account::GetAuthToken() const
{
    std::lock_guard<std::mutex> lock(Mutex);
    return AuthToken;
}

std::array<std::uint8_t, 16> Account::GetEncryptionKey() const
{
    std::lock_guard<std::mutex> lock(Mutex);
    return EncryptionKey;
}

void Account::SetCharacterProfile(
    std::uint32_t characterId,
    std::uint8_t faction,
    std::uint8_t gender,
    std::uint8_t appearanceVersion,
    const std::string& characterName,
    const std::string& clanName,
    const std::vector<std::uint8_t>& appearance)
{
    std::lock_guard<std::mutex> lock(Mutex);
    CharacterProfileAvailable = characterId != 0;
    CharacterId = characterId;
    CharacterFaction = faction;
    CharacterGender = gender;
    AppearanceVersion = appearanceVersion;
    CharacterName = characterName;
    ClanName = clanName;
    Appearance = appearance;
}

void Account::ClearCharacterProfile()
{
    std::lock_guard<std::mutex> lock(Mutex);
    CharacterProfileAvailable = false;
    CharacterId = 0;
    CharacterFaction = 0;
    CharacterGender = 0;
    AppearanceVersion = 0;
    CharacterName.clear();
    ClanName.clear();
    Appearance.clear();
}

bool Account::HasCharacterProfile() const
{
    std::lock_guard<std::mutex> lock(Mutex);
    return CharacterProfileAvailable;
}

std::uint32_t Account::GetCharacterId() const
{
    std::lock_guard<std::mutex> lock(Mutex);
    return CharacterId;
}

std::uint8_t Account::GetCharacterFaction() const
{
    std::lock_guard<std::mutex> lock(Mutex);
    return CharacterFaction;
}

std::uint8_t Account::GetCharacterGender() const
{
    std::lock_guard<std::mutex> lock(Mutex);
    return CharacterGender;
}

std::uint8_t Account::GetAppearanceVersion() const
{
    std::lock_guard<std::mutex> lock(Mutex);
    return AppearanceVersion;
}

std::string Account::GetCharacterName() const
{
    std::lock_guard<std::mutex> lock(Mutex);
    return CharacterName;
}

std::string Account::GetClanName() const
{
    std::lock_guard<std::mutex> lock(Mutex);
    return ClanName;
}

std::size_t Account::GetAppearanceSize() const
{
    std::lock_guard<std::mutex> lock(Mutex);
    return Appearance.size();
}

std::vector<std::uint8_t> Account::GetAppearance() const
{
    std::lock_guard<std::mutex> lock(Mutex);
    return Appearance;
}

void Account::BindEndpoint(
    std::uint32_t addressNetworkOrder,
    std::uint16_t portHostOrder)
{
    std::lock_guard<std::mutex> lock(Mutex);
    EndpointAddress = addressNetworkOrder;
    EndpointPort = portHostOrder;
    EndpointBound = true;
}

bool Account::MatchesEndpoint(
    std::uint32_t addressNetworkOrder,
    std::uint16_t portHostOrder) const
{
    std::lock_guard<std::mutex> lock(Mutex);
    return EndpointBound &&
           EndpointAddress == addressNetworkOrder &&
           EndpointPort == portHostOrder;
}

bool Account::HasEndpoint() const
{
    std::lock_guard<std::mutex> lock(Mutex);
    return EndpointBound;
}

std::uint32_t Account::GetEndpointAddress() const
{
    std::lock_guard<std::mutex> lock(Mutex);
    return EndpointAddress;
}

std::uint16_t Account::GetEndpointPort() const
{
    std::lock_guard<std::mutex> lock(Mutex);
    return EndpointPort;
}

void Account::SetAuthenticated(bool value)
{
    std::lock_guard<std::mutex> lock(Mutex);
    Authenticated = value;
}

bool Account::IsAuthenticated() const
{
    std::lock_guard<std::mutex> lock(Mutex);
    return Authenticated;
}

std::uint32_t Account::AllocateServerPacketId()
{
    std::lock_guard<std::mutex> lock(Mutex);
    const std::uint32_t value = NextServerPacketId;
    NextServerPacketId = (NextServerPacketId + 1u) & 0x3FFFFFFFu;
    return value;
}

std::uint16_t Account::AllocateServerReliableSequence()
{
    std::lock_guard<std::mutex> lock(Mutex);
    const std::uint16_t value = NextServerReliableSequence;
    NextServerReliableSequence =
        static_cast<std::uint16_t>((NextServerReliableSequence + 1u) % 1024u);
    if (NextServerReliableSequence == 0)
        NextServerReliableSequence = 1;
    return value;
}

void Account::SetLastClientPacketId(std::uint32_t value)
{
    std::lock_guard<std::mutex> lock(Mutex);
    LastClientPacketId = value;
}

std::uint32_t Account::GetLastClientPacketId() const
{
    std::lock_guard<std::mutex> lock(Mutex);
    return LastClientPacketId;
}

void Account::SetHandshakeChallenge(std::uint32_t value)
{
    std::lock_guard<std::mutex> lock(Mutex);
    HandshakeChallenge = value;
}

std::uint32_t Account::GetHandshakeChallenge() const
{
    std::lock_guard<std::mutex> lock(Mutex);
    return HandshakeChallenge;
}

void Account::SetHandshakeState(HandshakeState value)
{
    std::lock_guard<std::mutex> lock(Mutex);
    CurrentHandshakeState = value;
}

Account::HandshakeState Account::GetHandshakeState() const
{
    std::lock_guard<std::mutex> lock(Mutex);
    return CurrentHandshakeState;
}

std::uint32_t Account::IncrementChallengeSendCount()
{
    std::lock_guard<std::mutex> lock(Mutex);
    return ++ChallengeSendCount;
}

std::uint32_t Account::GetChallengeSendCount() const
{
    std::lock_guard<std::mutex> lock(Mutex);
    return ChallengeSendCount;
}

std::uint32_t Account::IncrementUdpReceiveCount()
{
    std::lock_guard<std::mutex> lock(Mutex);
    return ++UdpReceiveCount;
}

std::uint32_t Account::GetUdpReceiveCount() const
{
    std::lock_guard<std::mutex> lock(Mutex);
    return UdpReceiveCount;
}
