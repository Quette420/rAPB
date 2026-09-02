#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

class Account
{
public:
    enum class HandshakeState
    {
        WaitingForAuth,
        ChallengeSent,
        Complete
    };

    Account(
        std::uint32_t id,
        const std::uint8_t authToken[20],
        const std::uint8_t encryptionKey[16]);

    std::uint32_t GetId() const;

    void UpdateKeys(
        const std::uint8_t authToken[20],
        const std::uint8_t encryptionKey[16]);

    std::array<std::uint8_t, 20> GetAuthToken() const;
    std::array<std::uint8_t, 16> GetEncryptionKey() const;

    void SetCharacterProfile(
        std::uint32_t characterId,
        std::uint8_t faction,
        std::uint8_t gender,
        std::uint8_t appearanceVersion,
        const std::string& characterName,
        const std::string& clanName,
        const std::vector<std::uint8_t>& appearance);

    void ClearCharacterProfile();
    bool HasCharacterProfile() const;
    std::uint32_t GetCharacterId() const;
    std::uint8_t GetCharacterFaction() const;
    std::uint8_t GetCharacterGender() const;
    std::uint8_t GetAppearanceVersion() const;
    std::string GetCharacterName() const;
    std::string GetClanName() const;
    std::size_t GetAppearanceSize() const;
    std::vector<std::uint8_t> GetAppearance() const;

    void BindEndpoint(
        std::uint32_t addressNetworkOrder,
        std::uint16_t portHostOrder);

    bool MatchesEndpoint(
        std::uint32_t addressNetworkOrder,
        std::uint16_t portHostOrder) const;

    bool HasEndpoint() const;
    std::uint32_t GetEndpointAddress() const;
    std::uint16_t GetEndpointPort() const;

    void SetAuthenticated(bool value);
    bool IsAuthenticated() const;

    std::uint32_t AllocateServerPacketId();
    std::uint16_t AllocateServerReliableSequence();
    void SetLastClientPacketId(std::uint32_t value);
    std::uint32_t GetLastClientPacketId() const;

    void SetHandshakeChallenge(std::uint32_t value);
    std::uint32_t GetHandshakeChallenge() const;
    void SetHandshakeState(HandshakeState value);
    HandshakeState GetHandshakeState() const;
    std::uint32_t IncrementChallengeSendCount();
    std::uint32_t GetChallengeSendCount() const;

    std::uint32_t IncrementUdpReceiveCount();
    std::uint32_t GetUdpReceiveCount() const;

private:
    mutable std::mutex Mutex;
    std::uint32_t Id;
    std::array<std::uint8_t, 20> AuthToken;
    std::array<std::uint8_t, 16> EncryptionKey;
    bool CharacterProfileAvailable;
    std::uint32_t CharacterId;
    std::uint8_t CharacterFaction;
    std::uint8_t CharacterGender;
    std::uint8_t AppearanceVersion;
    std::string CharacterName;
    std::string ClanName;
    std::vector<std::uint8_t> Appearance;
    bool EndpointBound;
    std::uint32_t EndpointAddress;
    std::uint16_t EndpointPort;
    bool Authenticated;
    std::uint32_t NextServerPacketId;
    std::uint16_t NextServerReliableSequence;
    std::uint32_t LastClientPacketId;
    std::uint32_t HandshakeChallenge;
    HandshakeState CurrentHandshakeState;
    std::uint32_t ChallengeSendCount;
    std::uint32_t UdpReceiveCount;
};
