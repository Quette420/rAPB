#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <array>

namespace ApbUdp
{
    enum class BunchKind
    {
        Data,
        Ack
    };

    struct DebugParam
    {
        std::string   Kind;    // "object" | "enum" | "int" | "bool" | "float"
        std::int64_t  A = 0;   // значение / номер канала
        std::uint32_t B = 0;   // граница для enum
    };

    // One enum-backed ByteProperty appended to an actor's initial open bunch.
    // The field is serialized exactly like a later replicated property update:
    // ClassNetCache handle followed directly by SerializeInt(value, enum max).
    struct ActorInitialEnumByteFieldWire
    {
        std::uint32_t FieldIndex = 0;
        std::uint32_t FieldMax = 0;
        std::uint8_t Value = 0;
        std::uint32_t EnumValueCount = 0;
    };

    // APBGame.VehicleUseData, declared by cAPBPawn.  This is deliberately a
    // wire model rather than the C++ in-memory layout: UE3 serializes the
    // individual reflected members, including each BoolProperty as one bit.
    struct VehicleUseDataWire
    {
        std::int32_t VehicleId = 0;
        std::uint8_t UseId = 1;
        bool InsideVehicle = false;
        std::uint8_t SeatPosition = 5; // etVehiclePositionIndex::MAX
        bool SwitchingToAdjacentSeat = false;
        bool TeleportIn = false;
        bool OpenVehicleDoor = false;
        bool CloseVehicleDoor = false;
        bool GetInToVehicle = false;
        bool GetOutOfVehicle = false;
        bool BailOut = false;
        bool RouteingToVAP = false;
        bool EnteringVCP = false;
        bool ExitingVCP = false;
        bool ExitingVCPDeath = false;
        bool Death = false;
        bool LeaningOut = false;
        bool EjectInitial = false;
        bool EjectLater = false;
        bool DoingDriverEjectFromPassengerSide = false;
        bool CloseingDriverDoorFromInside = false;
        bool CanDriveVehicle = false;
        bool Enforcer = false;
        std::int32_t NpcTypeDriver = -1;
        std::int32_t DriverAssetIndex = 0;
        float LeaveVehicleX = 0.0f;
        float LeaveVehicleY = 0.0f;
        float LeaveVehicleZ = 0.0f;
    };

    struct VehicleVStateWire
    {
        float PosX = 0.0f, PosY = 0.0f, PosZ = 0.0f;
        float QuatX = 0.0f, QuatY = 0.0f, QuatZ = 0.0f, QuatW = 1.0f;
        float LinVelX = 0.0f, LinVelY = 0.0f, LinVelZ = 0.0f;
        float AngVelX = 0.0f, AngVelY = 0.0f, AngVelZ = 0.0f;

        std::uint8_t bNewData = 0;
        bool bSleeping = false;
        bool bForceState = false;

        std::uint8_t ServerBrake = 0x80;
        std::uint8_t ServerGas = 0x80;
        std::uint8_t ServerGear = 0x01;
        std::uint8_t ServerSteering = 0x80;
        std::uint8_t ServerRise = 0x80;
        std::uint8_t ServerSprint = 0x80;
        bool bServerHandbrake = false;
        std::int32_t ServerView = 0;
    };

    struct Bunch
    {
        BunchKind Kind = BunchKind::Data;
        std::uint32_t AckPacketId = 0;
        bool Open = false;
        bool Close = false;
        bool ReplicationPaused = false;
        bool Reliable = false;
        std::uint16_t ChannelIndex = 0;
        std::uint16_t ChannelSequence = 0;
        std::uint8_t ChannelType = 0;
        std::uint16_t DataBitCount = 0;
        std::size_t DataBitOffset = 0;
        std::vector<std::uint8_t> RawData;
        std::vector<std::string> ControlStrings;
    };

    struct Packet
    {
        bool Valid = false;
        std::uint16_t Prefix = 0;
        std::uint32_t PacketId = 0;
        std::size_t PayloadBitCount = 0;
        std::vector<Bunch> Bunches;
        std::string Error;
    };

    struct AuthCommand
    {
        bool Valid = false;
        std::uint32_t AccountId = 0;
        std::string AuthKeyText;
        std::array<std::uint8_t, 20> AuthKey{};
        std::string Error;
    };
    
    // Байтовый курсор по payload control-bunch. Payload извлекается с битовой
    // границы bunch, но внутри RawData выровнен по байту, поэтому чтение
    // байтовое.
    struct ControlReader
    {
        const std::uint8_t* Data = nullptr;
        std::size_t Size = 0;
        std::size_t Pos = 0;

        std::size_t Remaining() const { return Pos < Size ? Size - Pos : 0; }
        bool ReadByte(std::uint8_t& value);
        bool ReadInt32(std::int32_t& value);
        bool ReadUInt64(std::uint64_t& value);
        bool ReadFString(std::string& value);
    };

    bool OpenControlReader(const Bunch& bunch, ControlReader& reader);

    bool ParsePacket(
        const std::uint8_t* data,
        std::size_t size,
        Packet& packet);

    bool ParseAuthCommand(
        const std::string& text,
        AuthCommand& auth);

    std::vector<std::uint8_t> BuildAckPacket(
        std::uint16_t prefix,
        std::uint32_t serverPacketId,
        std::uint32_t acknowledgedPacketId);

    std::vector<std::uint8_t> BuildAckAndBinaryControlPacket(
        std::uint16_t prefix,
        std::uint32_t serverPacketId,
        std::uint32_t acknowledgedPacketId,
        std::uint16_t channelSequence,
        std::uint8_t messageType,
        const std::uint8_t* payload,
        std::size_t payloadSize);

    std::vector<std::uint8_t> BuildBinaryControlPacket(
        std::uint16_t prefix,
        std::uint32_t serverPacketId,
        std::uint16_t channelSequence,
        std::uint8_t messageType,
        const std::uint8_t* payload,
        std::size_t payloadSize);

    std::vector<std::uint8_t> BuildTextControlPacket(
        std::uint16_t prefix,
        std::uint32_t serverPacketId,
        std::uint16_t channelSequence,
        const std::string& text);

    std::vector<std::uint8_t> BuildAckAndTextControlPacket(
        std::uint16_t prefix,
        std::uint32_t serverPacketId,
        std::uint32_t acknowledgedPacketId,
        std::uint16_t channelSequence,
        const std::string& text);

    bool ReadBinaryControlMessage(
        const Bunch& bunch,
        std::uint8_t& messageType,
        std::vector<std::uint8_t>& payload);


    std::vector<std::uint8_t> BuildActorOpenPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t archetypeNetIndex,
        float spawnX,
        float spawnY,
        float spawnZ);

    // Initial actor-channel open for the connection's PlayerController.
    // APB 1.13.1 consumes archetype, compressed location, optional rotation,
    // then BYTE NetPlayerIndex. Runtime values for this build:
    //   Default__cAPBPlayerController global NetIndex = 46279
    //   bNetInitialRotation = false
    //   NetPlayerIndex = 0 for the main local viewport.
    std::vector<std::uint8_t> BuildPlayerControllerOpenPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t archetypeNetIndex,
        float spawnX,
        float spawnY,
        float spawnZ,
        std::uint8_t netPlayerIndex);

    // Actor open bunch with a reflected property stream immediately after the
    // archetype reference and compressed spawn location. Used by isolated
    // lifecycle experiments where sending the same fields in later bunches is
    // observably too late.
    std::vector<std::uint8_t> BuildActorOpenPacketWithInitialEnumByteFields(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t archetypeNetIndex,
        float spawnX,
        float spawnY,
        float spawnZ,
        const ActorInitialEnumByteFieldWire* fields,
        std::size_t fieldCount);

    std::vector<std::uint8_t> BuildActorClosePacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence);

    std::vector<std::uint8_t> BuildActorVehicleVStateFieldPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        const VehicleVStateWire& value);

    std::vector<std::uint8_t> BuildActorObjectFieldPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        std::uint16_t referencedChannel);

    // One update to a replicated fixed-size ObjectProperty array. APB keeps
    // one ClassNetCache field handle for the whole ArrayDim, followed by a
    // raw uint8 ArrayIndex and exactly one serialized UObject reference.
    std::vector<std::uint8_t> BuildActorStaticObjectArrayElementFieldPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        std::uint32_t elementIndex,
        std::uint32_t elementCount,
        std::uint16_t referencedChannel);

    // Same UObject payload, but framed as a single RPC parameter. UE3 writes
    // a top-level non-default/presence bit before the object reference.
    std::vector<std::uint8_t> BuildActorObjectRpcPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        std::uint16_t referencedChannel,
        std::size_t trailingDefaultParameterCount = 0);

    // RPC invocation with all ordinary parameters left at their defaults.
    std::vector<std::uint8_t> BuildActorDefaultRpcPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        std::size_t parameterCount);

    // Calls PlayerController.ClientGotoState(NewState, NAME_None).
    std::vector<std::uint8_t> BuildClientGotoStatePacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        const std::string& stateName);


    // Sends an unreliable client RPC carrying one raw float parameter.
    // Used for PlayerController.ClientAckGoodMove(TimeStamp).
    std::vector<std::uint8_t> BuildUnreliableActorFloatFieldPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        float value);

    std::vector<std::uint8_t> BuildActorIntFieldPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        const std::int32_t* values,
        std::size_t valueCount);

    // Replicated enum-backed ByteProperty. Replicated properties serialize
    // directly after the field index; unlike RPC parameters, there is no
    // non-default/presence bit.
    std::vector<std::uint8_t> BuildActorEnumByteFieldPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        std::uint8_t value,
        std::uint32_t enumValueCount);

    // Replicated APBGame.APBVehicleStateFSM StructProperty:
    //   FName sActorState
    //   EPKCState ePseudoKinCompState
    // There is no outer presence bit for a replicated property update.
    std::vector<std::uint8_t> BuildActorVehicleStateFSMFieldPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        const std::string& actorState,
        std::uint8_t pseudoKinCompState);

    // Replicated cAPBPawn.m_VehicleUseData.  This is a StructProperty, so it
    // has no RPC/default presence bit after the ClassNetCache field index.
    std::vector<std::uint8_t> BuildActorVehicleUseDataFieldPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        const VehicleUseDataWire& data);

    // cGolemTypes.CompactGolemDescriptor as declared by APBGame.u:
    //   +0x00 Guid m_CharacterGuid
    //   +0x10 Guid m_StatueGuid
    //   +0x20 Guid m_AudioGUID
    //
    // Each UE3 FGuid is four little-endian uint32 values. This is a
    // replicated StructProperty, not an RPC parameter, so no outer
    // presence/default bit is written. Total property data: 384 bits.
    std::vector<std::uint8_t> BuildActorCompactGolemDescriptorFieldPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        const std::array<std::uint8_t, 48>& descriptor);

    // Replicated fixed-size native StructProperty/raw field. Retained for
    // unrelated experiments; CompactGolemDescriptor uses the explicit
    // three-FGuid builder above.
    std::vector<std::uint8_t> BuildActorRawFieldPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        const std::uint8_t* value,
        std::size_t valueSize,
        bool writeStructPresenceBit = false);

    std::vector<std::uint8_t> BuildActorParamsFieldPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        const std::vector<DebugParam>& params);

    std::vector<std::uint8_t> BuildActorBoolFieldPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        bool value);


    std::vector<std::uint8_t> BuildActorVectorFieldPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        float x,
        float y,
        float z,
        bool compressed);

    std::vector<std::uint8_t> BuildLevelStreamingStatusPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        const std::string& packageName,
        bool shouldBeLoaded,
        bool shouldBeVisible,
        bool blockOnLoad,
        bool nameIncludesNumber,
	int boolCount);

    std::vector<std::uint8_t> BuildClientSetHudPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        std::uint32_t hudClassNetIndex,
        std::uint32_t scoringClassNetIndex);

    std::vector<std::uint8_t> BuildClientSetInitialStatePacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        std::int32_t characterUid,
        std::uint8_t faction,
        std::uint8_t gender);

    // cAPBPlayerController.ClientReceiveCharacterInfo(
    //     cGameInfoCache.CharacterInfoPacket packet)
    std::vector<std::uint8_t> BuildClientReceiveCharacterInfoPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        std::int32_t accountUid,
        std::int32_t characterUid,
        std::int32_t clanUid,
        std::int32_t groupId,
        std::int32_t sideId,
        const std::string& characterName,
        const std::string& clanName,
        std::uint8_t faction,
        std::uint32_t factionValueMax);

    // cHostingPlayerController.Receive_DS2GC_CHAT_SYSTEM(string sMessage)
    //
    // Один обязательный FString-параметр. Индексы 37..39 принадлежат
    // cHostingPlayerController, от которого наследуется
    // cAPBPlayerController - на канале контроллера они действительны
    // с fieldMax = kPlayerControllerFieldMax.
    std::vector<std::uint8_t> BuildActorStringFieldPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        const std::string& text);

    // cAPBPlayerController.CharacterData, reflected size 108 bytes:
    //
    //   int m_aCharacterFnMods[4]
    //   int m_nWeaponPrimary
    //   int m_aWeaponPrimaryFnMods[3]
    //   int m_nWeaponSecondary
    //   int m_aWeaponSecondaryFnMods[3]
    //   int m_nWeaponGrenade
    //   FString m_sGraffitiSymbolName
    //   FString m_sThemeName
    //   FGuid m_nGraffitiCustomisationGuid
    //   FGuid m_nThemeGuid
    struct CharacterDataPayload
    {
        std::array<std::int32_t, 4> CharacterFnMods{};
        std::int32_t WeaponPrimary = 0;
        std::array<std::int32_t, 3> WeaponPrimaryFnMods{};
        std::int32_t WeaponSecondary = 0;
        std::array<std::int32_t, 3> WeaponSecondaryFnMods{};
        std::int32_t WeaponGrenade = 0;
        std::string GraffitiSymbolName;
        std::string ThemeName;
        std::array<std::uint32_t, 4> GraffitiCustomisationGuid{};
        std::array<std::uint32_t, 4> ThemeGuid{};
    };

    // cAPBPlayerController.ClientReceiveCharacterData(
    //     cAPBPlayerController.CharacterData playerCharacterData)
    //
    // explicitPayload=false emits the normal all-default StructProperty
    // delta marker only. explicitPayload=true serializes every member.
    std::vector<std::uint8_t> BuildClientReceiveCharacterDataPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        const CharacterDataPayload& data,
        bool explicitPayload);

    // cCharacterScorer.CharacterStats, reflected size 36 bytes.
    struct CharacterStatsPayload
    {
        float TotalTimeInSeconds = 0.0f;
        std::int32_t TotalKills = 0;
        float SessionTimeInSeconds = 0.0f;
        std::int32_t SessionKills = 0;
        std::int32_t SessionMissionsWon = 0;
        std::int32_t SessionMissionsLost = 0;
        std::int32_t SessionPlayersArrested = 0;
        std::int32_t SessionPlayersFreed = 0;
        std::int32_t SessionMedals = 0;
    };

    // cAPBPlayerController.ClientReceiveCharacterStats(
    //     cCharacterScorer.CharacterStats playerCharacterStats)
    std::vector<std::uint8_t> BuildClientReceiveCharacterStatsPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        const CharacterStatsPayload& stats,
        bool explicitPayload);

    // cAPBPlayerController.CharacterRolesData is one fixed byte[99].
    struct CharacterRolesDataPayload
    {
        std::array<std::uint8_t, 99> RoleMilestones{};
    };

    // cAPBPlayerController.ClientReceiveCharacterRolesData(
    //     CharacterRolesData RolesData)
    std::vector<std::uint8_t> BuildClientReceiveCharacterRolesDataPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        const CharacterRolesDataPayload& roles,
        bool explicitPayload);

    // cAPBPlayerController.ClientPrecacheCustomisation(
    //     Guid TheGuid,
    //     cEnums.etPlayerCustomisation eType,
    //     bool bLocalPlayer)
    std::vector<std::uint8_t> BuildClientPrecacheCustomisationPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        const std::array<std::uint32_t, 4>& guid,
        std::uint8_t customisationType,
        bool localPlayer);

    enum class FixedByteArrayWireMode
    {
        PerElementDelta,
        SinglePresenceRaw,
        Raw
    };

    // APBGame.cCustomisationReplicator.ClientReceiveData(
    //     int nCount,
    //     byte packet[256])
    std::vector<std::uint8_t> BuildClientReceiveDataPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        std::int32_t count,
        const std::array<std::uint8_t, 256>& packet,
        FixedByteArrayWireMode wireMode);

    std::vector<std::uint8_t>
    BuildClientGoToSpawnZoneSelectScreenPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        std::uint8_t faction);

    std::vector<std::uint8_t> BuildActorVoidFieldPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax);

    // Network form of APBGame.cHUDMarkerManager.HUDMarkerData. UObject
    // pointers are represented through the package map rather than copied
    // from the local 32-byte script struct. A zero reference serializes null.
    struct HUDMarkerWireData
    {
        bool LinkedActorByChannel = false;
        std::uint32_t LinkedActorReference = 0;

        float LocationX = 0.0f;
        float LocationY = 0.0f;
        float LocationZ = 0.0f;

        std::uint8_t OffsetOverride = 0;
        std::uint8_t AutoRouteData = 0;
        std::uint8_t Type = 0;
        std::uint8_t State = 0;
        bool IsBeingModified = false;
        std::int32_t UserData = 0;
        std::int32_t UserData2 = 0;
        std::int32_t ServerMarkerId = 0;

        // APBGame.u metadata: OffsetOverride, AutoRouteData and Type are
        // unbacked ByteProperties (raw 8 bits); only State is enum-backed and
        // uses SerializeInt(value, 19). RawByteEncoding makes State raw too.
        bool RawByteEncoding = false;
        // HUDMarkerData.Location resolves to Core.Vector. Its UE3 NetSerializeItem
        // path uses FVector compressed network serialization.
        bool CompressedLocation = true;
        // Retained for ABI/source compatibility. RPC parameter presence is
        // now written unconditionally by BuildClientReplicateHudMarkerPacket.
        bool WriteStructPresenceBit = true;
        // Retained for configuration compatibility; the first three byte
        // fields are metadata-proven raw bytes and these maxima are unused.
        std::uint32_t OffsetOverrideMax = 2;
        std::uint32_t AutoRouteDataMax = 4;
        std::uint32_t TypeMax = 256;
        std::uint32_t StateMax = 19;
    };

    std::vector<std::uint8_t> BuildClientReplicateHudMarkerPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        const HUDMarkerWireData& marker);


    struct ControllerMovementRpc
    {
        bool Matched = false;

        bool IsDualServerMove = false;
        bool IsOldServerMove = false;
        bool IsServerMove = false;

        std::uint32_t FieldIndex = 0;
        std::size_t FieldIndexBits = 0;
        std::size_t ParameterBits = 0;
        std::size_t ConsumedBits = 0;
        std::size_t TrailingBits = 0;

        std::uint32_t RpcCount = 0;
        std::uint32_t DualServerMoveCount = 0;
        std::uint32_t OldServerMoveCount = 0;
        std::uint32_t ServerMoveCount = 0;

        // Latest processable move timestamp. OldServerMove is historical
        // context and is not selected as the acknowledgement target by itself.
        bool TimeStampPresent = false;
        bool HasTimeStamp = false;
        float TimeStamp = 0.0f;

        // Latest decoded primary acceleration and location.
        bool AccelerationPresent = false;
        std::int32_t AccelerationX = 0;
        std::int32_t AccelerationY = 0;
        std::int32_t AccelerationZ = 0;

        bool ClientLocationPresent = false;
        std::int32_t ClientLocationX = 0;
        std::int32_t ClientLocationY = 0;
        std::int32_t ClientLocationZ = 0;

        bool MoveFlagsPresent = false;
        std::uint8_t MoveFlags = 0;

        bool ClientRollPresent = false;
        std::uint8_t ClientRoll = 0;

        bool ViewPresent = false;
        std::uint32_t View = 0;

        // OldServerMove's quantized historical acceleration/flags.
        bool OldAccelerationPresent = false;
        std::uint8_t OldAccelX = 0;
        std::uint8_t OldAccelY = 0;
        std::uint8_t OldAccelZ = 0;
        bool OldMoveFlagsPresent = false;
        std::uint8_t OldMoveFlags = 0;
    };

    // Fully decodes every contiguous movement RPC at the beginning of one
    // PlayerController actor bunch. This handles standalone calls and the
    // normal UE3 coalesced forms:
    //
    //   OldServerMove + ServerMove
    //   OldServerMove + DualServerMove
    //
    // FVector parameters use the build-3908 compressed-vector serializer.
    // If a non-movement field follows, it is left in TrailingBits rather than
    // being misinterpreted as part of the movement RPC.
    bool DecodeControllerMovementRpc(
        const Bunch& bunch,
        std::uint32_t fieldMax,
        std::uint32_t dualServerMoveField,
        std::uint32_t oldServerMoveField,
        std::uint32_t serverMoveField,
        ControllerMovementRpc& movement,
        std::string& error);

    struct ControllerActorField
    {
        std::uint32_t FieldIndex = 0;
        std::size_t BeginBit = 0;
        std::size_t EndBit = 0;

        bool IsServerUpdateLevelVisibility = false;
        bool IsServerNotifyClientLoaded = false;
        bool IsServerSelectSpawnZone = false;
        bool IsServerRequestCharacterData = false;
        bool IsServerRequestCharacterStats = false;
        bool IsServerRequestCharacterRolesData = false;
        bool IsNewServerDrive = false;

        // NewServerDrive(float TimeStamp, byte Inputs). Each ordinary RPC
        // parameter has its own non-default/presence bit.
        bool DriveTimeStampPresent = false;
        float DriveTimeStamp = 0.0f;
        bool DriveInputsPresent = false;
        std::uint8_t DriveInputs = 0;

        // Decoded from the one-int Character UID request RPCs.
        std::int32_t RequestedCharacterUid = 0;
        std::int32_t RequestedCharacterStatsUid = 0;
        std::int32_t RequestedCharacterRolesUid = 0;

        // Object reference decoded from ServerSelectSpawnZone(SpawnZone).
        // Value 0 in package-map form represents None.
        bool ObjectReferenceByChannel = false;
        std::uint32_t ObjectReferenceValue = 0;

        std::string PackageName;
        bool IsVisible = false;
    };

    // Decodes actor-channel fields sent by the client on its
    // cAPBPlayerController channel. Field 78 is skipped using its observed
    // fixed 56-bit parameter width. Field 484 is skipped using its proven
    // 168-bit total field width inside the reliable post-stream batch. Other
    // unknown fields are returned with their field
    // index and stop parsing because their parameter layout is not yet known.
    // Field 90 is fully decoded as:
    //
    //   ServerUpdateLevelVisibility(FName PackageName, bool bIsVisible)
    //
    // Field 371 is decoded as:
    //
    //   ServerSelectSpawnZone(cPlayerCharacterSpawnZone SpawnZone)
    //
    // Field 376 is decoded as:
    //
    //   NewServerDrive(float TimeStamp, byte Inputs)
    //
    // Multiple recognized RPCs may be packed into one bunch.
    bool DecodeControllerActorFields(
        const Bunch& bunch,
        std::uint32_t fieldMax,
        std::uint32_t serverUpdateLevelVisibilityField,
        std::uint32_t serverNotifyClientLoadedField,
        std::uint32_t serverSelectSpawnZoneField,
        std::vector<ControllerActorField>& fields,
        std::string& error);

    // Reads the first ClassNetCache field index from an actor-channel bunch.
    // Used for small class-specific RPC channels such as
    // cCustomisationReplicator.
    bool DecodeActorFieldIndex(
        const Bunch& bunch,
        std::uint32_t fieldMax,
        std::uint32_t& fieldIndex,
        std::size_t& parameterBits,
        std::string& error);

    struct CSAKeyPressedRpc
    {
        bool Matched = false;
        std::int32_t InputMapping = 0;
        std::int32_t AimRotation = 0;
        float CameraCollidePercent = 0.0f;
        bool TargetPresent = false;
        bool TargetByChannel = false;
        std::uint32_t TargetReference = 0;
        std::size_t ConsumedBits = 0;
    };

    bool DecodeCSAKeyPressedRpc(
        const Bunch& bunch,
        std::uint32_t fieldMax,
        std::uint32_t expectedField,
        CSAKeyPressedRpc& rpc,
        std::string& error);

    // Decodes a one-int actor RPC parameter:
    //
    //   SerializeInt(FieldIndex, FieldMax)
    //   IntProperty non-default/presence bit
    //   raw int32 value
    //
    // APB build 3908 uses this exact shape for
    // cCustomisationReplicator.ServerSendData(int nBaseIndex).
    bool DecodeActorIntRpc(
        const Bunch& bunch,
        std::uint32_t fieldMax,
        std::uint32_t expectedField,
        std::int32_t& value,
        std::size_t& trailingBits,
        std::string& error);

    std::string DescribePacket(const Packet& packet);
    std::string Hex(const std::uint8_t* data, std::size_t size, std::size_t maximum = 256);
    bool RunSelfTest(std::string& details);
}
