#include "stdafx.h"
#include "ApbUdp.h"
#include <cmath>
#include <cstring>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <iomanip>
#include <limits>
#include <sstream>

namespace
{
    // APB 1.13.1: UNetConnection::MaxPacket = 1024, поэтому длина bunch
    // сериализуется как SerializeInt(NumBits, 8192) = 13 бит.
    // В старом билде было 512 -> 4096 -> 12 бит.
    constexpr std::uint32_t kMaxBunchDataBits = 512u * 8u;   // 4096
    constexpr std::size_t   kBunchLengthBits  = 12u;
    
    class BitReader
    {
    public:
        BitReader(
            const std::uint8_t* data,
            std::size_t beginBit,
            std::size_t endBit)
            : Data(data), Position(beginBit), End(endBit)
        {
        }

        std::size_t Tell() const
        {
            return Position;
        }

        std::size_t Remaining() const
        {
            return Position <= End
                ? End - Position
                : 0;
        }

        bool ReadBit(bool& value)
        {
            std::uint32_t temporary = 0;
            if (!ReadBits(1, temporary))
                return false;
            value = temporary != 0;
            return true;
        }

        bool ReadBits(std::size_t count, std::uint32_t& value)
        {
            value = 0;

            if (count > 32 || count > Remaining())
                return false;

            for (std::size_t index = 0; index < count; ++index)
            {
                const std::size_t absolute = Position + index;
                const std::uint8_t bit =
                    (Data[absolute / 8] >> (absolute % 8)) & 1u;

                value |=
                    static_cast<std::uint32_t>(bit) << index;
            }

            Position += count;
            return true;
        }

        bool ReadByte(std::uint8_t& value)
        {
            std::uint32_t temporary = 0;
            if (!ReadBits(8, temporary))
                return false;
            value = static_cast<std::uint8_t>(temporary);
            return true;
        }

        bool ReadBoundedInt(
            std::uint32_t valueMax,
            std::uint32_t& value)
        {
            value = 0;

            if (valueMax <= 1)
                return true;

            for (std::uint32_t mask = 1;
                 value + mask < valueMax;
                 mask <<= 1)
            {
                bool bit = false;

                if (!ReadBit(bit))
                    return false;

                if (bit)
                    value |= mask;

                if ((mask & 0x80000000u) != 0)
                    break;
            }

            return true;
        }

        bool ReadFString(std::string& value)
        {
            value.clear();

            std::uint32_t rawLength = 0;

            if (!ReadBits(32, rawLength))
                return false;

            const std::int32_t length =
                static_cast<std::int32_t>(rawLength);

            if (length == 0)
                return true;

            if (length > 0)
            {
                if (length > 65536 ||
                    static_cast<std::size_t>(length) * 8u >
                        Remaining())
                {
                    return false;
                }

                value.reserve(
                    static_cast<std::size_t>(length));

                for (std::int32_t index = 0;
                     index < length;
                     ++index)
                {
                    std::uint8_t character = 0;

                    if (!ReadByte(character))
                        return false;

                    if (character != 0)
                        value.push_back(
                            static_cast<char>(character));
                }

                return true;
            }

            const std::int64_t wideCount =
                -static_cast<std::int64_t>(length);

            if (wideCount <= 0 ||
                wideCount > 32768 ||
                static_cast<std::size_t>(wideCount) * 16u >
                    Remaining())
            {
                return false;
            }

            value.reserve(
                static_cast<std::size_t>(wideCount));

            for (std::int64_t index = 0;
                 index < wideCount;
                 ++index)
            {
                std::uint32_t character = 0;

                if (!ReadBits(16, character))
                    return false;

                if (character == 0)
                    continue;

                value.push_back(
                    character <= 0x7Fu
                        ? static_cast<char>(character)
                        : '?');
            }

            return true;
        }

        bool Skip(std::size_t count)
        {
            if (count > Remaining())
                return false;
            Position += count;
            return true;
        }

    private:
        const std::uint8_t* Data;
        std::size_t Position;
        std::size_t End;
    };

    class BitWriter
    {
    public:
        void WriteBit(bool value)
        {
            const std::size_t byteIndex = WrittenBits / 8;
            const std::size_t bitIndex = WrittenBits % 8;

            if (byteIndex >= Data.size())
                Data.push_back(0);

            if (value)
                Data[byteIndex] |= static_cast<std::uint8_t>(1u << bitIndex);

            ++WrittenBits;
        }

        void WriteBits(std::uint32_t value, std::size_t count)
        {
            for (std::size_t index = 0; index < count; ++index)
                WriteBit(((value >> index) & 1u) != 0);
        }

        void WriteBytes(const std::uint8_t* value, std::size_t count)
        {
            if (value == nullptr)
                return;

            for (std::size_t index = 0; index < count; ++index)
                WriteBits(value[index], 8);
        }

        // UE3's FBitWriter::SerializeInt(Value, ValueMax): a variable length
        // encoding that emits bits least-significant first and stops as soon as
        // the accumulated value plus the next mask would reach ValueMax. This is
        // the exact counterpart of the reader used everywhere in the packet
        // parser, and it is how channel indices (max 0x3FF), packet ids
        // (max 0x40000000) and package-map net indices (max 0x80000000) go on
        // the wire.
        void WriteBoundedInt(std::uint32_t value, std::uint32_t valueMax)
        {
            std::uint32_t accumulated = 0;
            for (std::uint32_t mask = 1;
                 accumulated + mask < valueMax;
                 mask <<= 1)
            {
                const bool bit = (value & mask) != 0;
                if (bit)
                    accumulated |= mask;
                WriteBit(bit);

                if (mask & 0x80000000u)
                    break;
            }
        }

        // FVector::SerializeCompressed, recovered from FUN_10DCC5E0:
        //     bits = bitlength(max(|X|,|Y|,|Z|)) clamped to [1,20]
        //     SerializeInt(bits - 1, 20)
        //     Bias = 1 << bits;  Max = 1 << (bits + 1)
        //     SerializeInt(X + Bias, Max), then Y, then Z
        // On load the client computes X = DX - Bias, which is why a bunch that
        // ends before this data decodes to (-2,-2,-2): it reads bits-1 = 0,
        // giving Bias = 2 and DX = 0.
        void WriteCompressedVector(float x, float y, float z)
        {
            const std::int32_t ix =
                static_cast<std::int32_t>(x < 0 ? x - 0.5f : x + 0.5f);
            const std::int32_t iy =
                static_cast<std::int32_t>(y < 0 ? y - 0.5f : y + 0.5f);
            const std::int32_t iz =
                static_cast<std::int32_t>(z < 0 ? z - 0.5f : z + 0.5f);

            std::uint32_t largest = static_cast<std::uint32_t>(std::abs(ix));
            largest = (std::max)(largest, static_cast<std::uint32_t>(std::abs(iy)));
            largest = (std::max)(largest, static_cast<std::uint32_t>(std::abs(iz)));

            std::uint32_t bits = 0;
            while (largest >> bits)
                ++bits;
            if (bits < 1) bits = 1;
            if (bits > 20) bits = 20;

            WriteBoundedInt(bits - 1, 20);

            const std::uint32_t bias = 1u << bits;
            const std::uint32_t maximum = 1u << (bits + 1);

            WriteBoundedInt(
                static_cast<std::uint32_t>(ix + static_cast<std::int32_t>(bias)),
                maximum);
            WriteBoundedInt(
                static_cast<std::uint32_t>(iy + static_cast<std::int32_t>(bias)),
                maximum);
            WriteBoundedInt(
                static_cast<std::uint32_t>(iz + static_cast<std::int32_t>(bias)),
                maximum);
        }

        // FString as UE3 serialises it: a 32 bit length (including the
        // terminator) followed by the characters and a trailing null. Same
        // encoding the text control messages already use.
        void WriteFString(const std::string& text, bool nullTerminated = true)
        {
            const std::uint32_t length =
                static_cast<std::uint32_t>(text.size() + (nullTerminated ? 1u : 0u));
            WriteBits(length, 32);
            for (char character : text)
                WriteBits(static_cast<std::uint8_t>(character), 8);
            if (nullTerminated)
                WriteBits(0, 8);
        }

        // UPackageMap::SerializeName first serializes a one-bit selector.
        // For non-hardcoded names the selector is zero and the name follows as
        // an FString.  The previous implementation omitted this bit, so the
        // low bit of the FString length became the selector.  For the terrain
        // name the serialized length is 55 (odd), which shifted the remaining
        // payload and decoded as:
        //   FName(Index=76533, Number=405772312), bools=(0,0,0)
        // instead of the existing terrain FName and (1,1,0).
        //
        // APB's network reader derives the FName Number from the string when
        // using this path; do not append a raw 32-bit number unless explicitly
        // testing an alternate build.
        void WriteName(
            const std::string& text,
            std::uint32_t number = 0,
            bool includeNumber = false,
            bool nullTerminated = true)
        {
            // v0.5 proved false decodes as NAME_None and consumes no
            // FString. True selects the FString representation.
            WriteBit(true); // FString name follows
            WriteFString(text, nullTerminated);
            if (includeNumber)
                WriteBits(number, 32);
        }

        // UPackageMapLevel::SerializeObject. An object reference is one flag bit
        // followed by a bounded int:
        //   flag = 0 -> package map reference, SerializeInt(NetIndex, 0x80000000)
        //   flag = 1 -> channel reference,     SerializeInt(ChIndex, 0x3FF)
        // Classes and other loaded assets use the package-map form; actors that
        // already have an open channel use the channel form.
        void WriteObjectByNetIndex(std::uint32_t netIndex)
        {
            WriteBit(false);
            WriteBoundedInt(netIndex, 0x80000000u);
        }

        void WriteObjectByChannel(std::uint32_t channelIndex)
        {
            WriteBit(true);
            WriteBoundedInt(channelIndex, 0x3FFu);
        }

        std::vector<std::uint8_t> FinishWithTrailer()
        {
            WriteBit(true);
            return Data;
        }

        // Number of bits written so far (no trailer). Needed when a payload has
        // to be measured before its length is written into a bunch header.
        std::size_t BitCount() const
        {
            return WrittenBits;
        }

        // Raw bytes written so far, without adding a terminator.
        const std::vector<std::uint8_t>& Snapshot() const
        {
            return Data;
        }

        // Appends `count` bits taken from `source`, least-significant bit of
        // each byte first, matching how WriteBit lays bits out.
        void WriteBitsFrom(
            const std::vector<std::uint8_t>& source,
            std::size_t count)
        {
            for (std::size_t index = 0; index < count; ++index)
            {
                const std::size_t byteIndex = index / 8;
                const std::size_t bitIndex = index % 8;
                if (byteIndex >= source.size())
                    break;
                WriteBit(((source[byteIndex] >> bitIndex) & 1u) != 0);
            }
        }

    private:
        std::vector<std::uint8_t> Data;
        std::size_t WrittenBits = 0;
    };

    bool FindPayloadBitCount(
        const std::uint8_t* data,
        std::size_t size,
        std::size_t& payloadBitCount)
    {
        if (data == nullptr || size == 0)
            return false;

        for (std::size_t reverse = size; reverse > 0; --reverse)
        {
            const std::size_t byteIndex = reverse - 1;
            const std::uint8_t value = data[byteIndex];

            if (value == 0)
                continue;

            for (int bit = 7; bit >= 0; --bit)
            {
                if ((value & static_cast<std::uint8_t>(1u << bit)) != 0)
                {
                    // The highest set bit is UE3's packet trailer marker.
                    payloadBitCount = byteIndex * 8 + static_cast<std::size_t>(bit);
                    return true;
                }
            }
        }

        return false;
    }

    bool ExtractBits(
        const std::uint8_t* source,
        std::size_t beginBit,
        std::size_t bitCount,
        std::vector<std::uint8_t>& output)
    {
        output.assign((bitCount + 7) / 8, 0);

        for (std::size_t index = 0; index < bitCount; ++index)
        {
            const std::size_t sourceBit = beginBit + index;
            const std::uint8_t value =
                (source[sourceBit / 8] >> (sourceBit % 8)) & 1u;

            if (value != 0)
                output[index / 8] |= static_cast<std::uint8_t>(1u << (index % 8));
        }

        return true;
    }

    bool ParseControlStrings(
        const std::uint8_t* data,
        std::size_t beginBit,
        std::size_t bitCount,
        std::vector<std::string>& strings)
    {
        BitReader reader(data, beginBit, beginBit + bitCount);

        while (reader.Remaining() >= 32)
        {
            std::uint32_t rawLength = 0;
            if (!reader.ReadBits(32, rawLength))
                return false;

            const std::int32_t length = static_cast<std::int32_t>(rawLength);

            if (length == 0)
            {
                strings.push_back(std::string());
                continue;
            }

            if (length > 0)
            {
                if (length > 65536 ||
                    static_cast<std::size_t>(length) * 8 > reader.Remaining())
                {
                    return strings.size() > 0;
                }

                std::string value;
                value.reserve(static_cast<std::size_t>(length));

                for (std::int32_t index = 0; index < length; ++index)
                {
                    std::uint8_t character = 0;
                    if (!reader.ReadByte(character))
                        return false;

                    if (character != 0)
                        value.push_back(static_cast<char>(character));
                }

                strings.push_back(value);
            }
            else
            {
                const std::int64_t wideCount64 = -static_cast<std::int64_t>(length);
                if (wideCount64 <= 0 ||
                    wideCount64 > 32768 ||
                    static_cast<std::size_t>(wideCount64) * 16 > reader.Remaining())
                {
                    return strings.size() > 0;
                }

                std::string value;
                value.reserve(static_cast<std::size_t>(wideCount64));

                for (std::int64_t index = 0; index < wideCount64; ++index)
                {
                    std::uint32_t character = 0;
                    if (!reader.ReadBits(16, character))
                        return false;

                    if (character == 0)
                        continue;

                    if (character <= 0x7f)
                        value.push_back(static_cast<char>(character));
                    else
                        value.push_back('?');
                }

                strings.push_back(value);
            }
        }

        return !strings.empty();
    }

    bool IsHexCharacter(char value)
    {
        return std::isxdigit(static_cast<unsigned char>(value)) != 0;
    }

    std::uint8_t HexNibble(char value)
    {
        if (value >= '0' && value <= '9')
            return static_cast<std::uint8_t>(value - '0');
        if (value >= 'a' && value <= 'f')
            return static_cast<std::uint8_t>(10 + value - 'a');
        if (value >= 'A' && value <= 'F')
            return static_cast<std::uint8_t>(10 + value - 'A');
        return 0xff;
    }

    bool ReadToken(
        const std::string& text,
        const std::string& key,
        std::string& value)
    {
        const std::size_t position = text.find(key);
        if (position == std::string::npos)
            return false;

        const std::size_t begin = position + key.size();
        std::size_t end = begin;

        while (end < text.size() &&
               !std::isspace(static_cast<unsigned char>(text[end])))
        {
            ++end;
        }

        value = text.substr(begin, end - begin);
        return !value.empty();
    }
}

namespace ApbUdp
{
    namespace
    {
        bool HasUsableControlBunch(const Packet& packet)
        {
            for (const Bunch& bunch : packet.Bunches)
            {
                if (bunch.Kind == BunchKind::Data &&
                    bunch.ChannelIndex == 0 &&
                    bunch.ChannelType == 1 &&
                    bunch.DataBitCount >= 8 &&
                    !bunch.RawData.empty())
                {
                    return true;
                }
            }

            return false;
        }

        bool FinishPartialPacket(
            Packet& packet,
            const char* error)
        {
            packet.Error = error != nullptr ? error : "trailing framing parse error";

            // Newer APB builds append transport/framing bits after the first
            // useful ControlChannel bunch. We do not fully model that tail yet.
            // If a complete channel-0 control bunch was already decoded, keep it
            // and let the district handshake layer consume it.
            if (HasUsableControlBunch(packet))
            {
                packet.Valid = true;
                return true;
            }

            return false;
        }
    }

    bool ParsePacket(
        const std::uint8_t* data,
        std::size_t size,
        Packet& packet)
    {
        packet = Packet();

        std::size_t payloadBitCount = 0;
        if (!FindPayloadBitCount(data, size, payloadBitCount))
        {
            packet.Error = "missing UE3 trailer marker";
            return false;
        }

        packet.PayloadBitCount = payloadBitCount;

        BitReader reader(data, 0, payloadBitCount);
        std::uint32_t value = 0;

        // The packet id is the field beginning at bit 0. Its low 16 bits were
        // previously mislabelled as "prefix"; the next 14 bits are the (normally
        // zero) high part. The real client packet id is the low 16 bits.
        if (!reader.ReadBits(16, value))
        {
            packet.Error = "truncated packet id (low)";
            return false;
        }
        const std::uint32_t packetIdLow = value;
        packet.Prefix = static_cast<std::uint16_t>(value);

        if (!reader.ReadBits(14, value))
        {
            packet.Error = "truncated packet id (high)";
            return false;
        }
        // value holds the high 14 bits (normally 0). Track the real client
        // packet id so acknowledgements reference the correct sequence number.
        packet.PacketId = static_cast<std::uint16_t>(packetIdLow);

        while (reader.Remaining() > 0)
        {
            Bunch bunch;
            bool flag = false;

            if (!reader.ReadBit(flag))
            {
                return FinishPartialPacket(
                    packet,
                    "truncated ACK/data flag");
            }

            if (flag)
            {
                // Ack bunch: [IsAck=1][bHasId][if bHasId: ReadInt(0x40000000)].
                // The client's UNetConnection::ReceivedPacket reads a full
                // 30-bit packet id here, not a 14-bit one; reading 14 bits
                // shifted every following bunch and produced spurious
                // "bunch data exceeds packet payload" errors.
                bunch.Kind = BunchKind::Ack;

                bool hasAckId = false;
                if (!reader.ReadBit(hasAckId))
                {
                    return FinishPartialPacket(
                        packet,
                        "truncated ACK id presence flag");
                }

                if (hasAckId)
                {
                    if (!reader.ReadBits(30, value))
                    {
                        return FinishPartialPacket(
                            packet,
                            "truncated ACK packet id");
                    }
                    bunch.AckPacketId = value;
                }

                packet.Bunches.push_back(bunch);
                continue;
            }

            bunch.Kind = BunchKind::Data;

            bool hasOpenClose = false;
            if (!reader.ReadBit(hasOpenClose))
            {
                return FinishPartialPacket(
                    packet,
                    "truncated open/close presence flag");
            }

            if (hasOpenClose)
            {
                if (!reader.ReadBit(bunch.Open) ||
                    !reader.ReadBit(bunch.Close))
                {
                    return FinishPartialPacket(
                        packet,
                        "truncated open/close flags");
                }
            }

            if (!reader.ReadBit(bunch.Reliable))
            {
                return FinishPartialPacket(
                    packet,
                    "truncated reliability flag");
            }
            // Newer APB/UE3 builds serialize bIsReplicationPaused between
            // open/close and bReliable. The older build-3908 parser omitted it,
            // shifting channel/type/length by one bit.
            if (!reader.ReadBit(bunch.ReplicationPaused))
            {
                return FinishPartialPacket(
                    packet,
                    "truncated replication-paused flag");
            }

            if (!reader.ReadBits(10, value))
            {
                return FinishPartialPacket(
                    packet,
                    "truncated channel index");
            }
            bunch.ChannelIndex = static_cast<std::uint16_t>(value);

            // V9: modern APB ControlChannel header probe.
            //
            // Two independent live packet-0 captures have the exact stable
            // layout after ChIndex=0:
            //     3 bits  = 1,0,0
            //     10 bits = 128
            //     12 bits = DataBitCount (208)
            //
            // This matches the newer Unreal bunch family where extra control
            // flags are followed (for open/reliable bunches) by a serialized
            // channel name rather than the old 3-bit ChType.  We deliberately
            // call the first three values ModernFlag0..2 until their APB-build
            // semantics are proven.  The 10-bit value 128 is the captured
            // Control-channel name token.
            //
            // Try this format only for channel 0 and only when the candidate
            // name token is exactly the value observed on the live client.
            // Otherwise fall back to the legacy/build-3908 parser below.
            bool parsedModernControlHeader = false;

            if (bunch.ChannelIndex == 0 &&
                (bunch.Open || bunch.Reliable))
            {
                BitReader modern = reader;

                bool hasPackageMapExports = false;
                bool hasMustBeMappedGUIDs = false;
                bool modernPartial = false;
                bool modernPartialInitial = false;
                bool modernPartialFinal = false;

                std::uint32_t modernSequence = 0;
                std::uint32_t modernChannelName = 0;
                std::uint32_t modernDataBits = 0;

                bool modernOk =
                    modern.ReadBit(hasPackageMapExports) &&
                    modern.ReadBit(hasMustBeMappedGUIDs) &&
                    modern.ReadBit(modernPartial);

                if (modernOk && bunch.Reliable)
                    modernOk = modern.ReadBits(10, modernSequence);

                if (modernOk && modernPartial)
                {
                    modernOk =
                        modern.ReadBit(modernPartialInitial) &&
                        modern.ReadBit(modernPartialFinal);
                }

                if (modernOk)
                    modernOk = modern.ReadBits(10, modernChannelName);

                if (modernOk)
                    modernOk = modern.ReadBits(12, modernDataBits);

                // 128 is stable across both live packet-0 captures. Requiring it
                // prevents legacy old-header packets from being misclassified.
                if (modernOk &&
                    modernChannelName == 128u &&
                    modernDataBits <= modern.Remaining())
                {
                    // For the initial HandshakeStart the bunch exactly reaches
                    // the packet trailer. For server self-tests and future
                    // packets, <= is retained so a packet may contain another
                    // bunch afterwards.
                    reader = modern;
                    bunch.ChannelSequence =
                        static_cast<std::uint16_t>(modernSequence);
                    bunch.ChannelType = 1; // semantic Control channel
                    value = modernDataBits;
                    parsedModernControlHeader = true;

                    (void)hasPackageMapExports;
                    (void)hasMustBeMappedGUIDs;
                    (void)modernPartial;
                    (void)modernPartialInitial;
                    (void)modernPartialFinal;
                }
            }

            if (!parsedModernControlHeader)
            {
                if (bunch.Reliable)
                {
                    if (!reader.ReadBits(10, value))
                    {
                        return FinishPartialPacket(
                            packet,
                            "truncated channel sequence");
                    }
                    bunch.ChannelSequence = static_cast<std::uint16_t>(value);
                }

                if (bunch.Reliable || bunch.Open)
                {
                    if (!reader.ReadBits(3, value))
                    {
                        return FinishPartialPacket(
                            packet,
                            "truncated channel type");
                    }
                    bunch.ChannelType = static_cast<std::uint8_t>(value);
                }

                if (!reader.ReadBits(kBunchLengthBits, value))
                {
                    return FinishPartialPacket(
                        packet,
                        "truncated bunch data length");
                }
            }

            bunch.DataBitCount = static_cast<std::uint16_t>(value);
            bunch.DataBitOffset = reader.Tell();

            if (bunch.DataBitCount > reader.Remaining())
            {
                // Preserve already-decoded bunches. The captured newer client
                // carries additional trailing framing the build-3908 parser
                // does not yet model; the first control bunch is still usable.
                packet.Error = "trailing bunch data exceeds packet payload";

                if (!packet.Bunches.empty())
                {
                    packet.Valid = true;
                    return true;
                }

                return false;
            }

            ExtractBits(
                data,
                bunch.DataBitOffset,
                bunch.DataBitCount,
                bunch.RawData);

            if (bunch.ChannelType == 1 && bunch.DataBitCount >= 32)
            {
                ParseControlStrings(
                    data,
                    bunch.DataBitOffset,
                    bunch.DataBitCount,
                    bunch.ControlStrings);
            }

            if (!reader.Skip(bunch.DataBitCount))
            {
                return FinishPartialPacket(
                    packet,
                    "failed to advance over bunch data");
            }

            packet.Bunches.push_back(bunch);
        }

        packet.Valid = true;
        return true;
    }

    bool ParseAuthCommand(
        const std::string& text,
        AuthCommand& auth)
    {
        auth = AuthCommand();

        if (text.size() < 5 || text.compare(0, 4, "AUTH") != 0)
        {
            auth.Error = "control string is not AUTH";
            return false;
        }

        std::string accountText;
        std::string keyText;

        if (!ReadToken(text, "ACCID=", accountText))
        {
            auth.Error = "AUTH is missing ACCID";
            return false;
        }

        if (!ReadToken(text, "AUTHKEY=", keyText))
        {
            auth.Error = "AUTH is missing AUTHKEY";
            return false;
        }

        if (keyText.size() != 40 ||
            !std::all_of(keyText.begin(), keyText.end(), IsHexCharacter))
        {
            auth.Error = "AUTHKEY is not 40 hexadecimal characters";
            return false;
        }

        char* end = nullptr;
        const unsigned long parsedAccount =
            std::strtoul(accountText.c_str(), &end, 10);

        if (end == accountText.c_str() ||
            *end != '\0' ||
            parsedAccount > std::numeric_limits<std::uint32_t>::max())
        {
            auth.Error = "ACCID is not a valid uint32";
            return false;
        }

        for (std::size_t index = 0; index < auth.AuthKey.size(); ++index)
        {
            const std::uint8_t high = HexNibble(keyText[index * 2]);
            const std::uint8_t low = HexNibble(keyText[index * 2 + 1]);

            if (high > 0x0f || low > 0x0f)
            {
                auth.Error = "AUTHKEY contains a non-hexadecimal nibble";
                return false;
            }

            auth.AuthKey[index] = static_cast<std::uint8_t>((high << 4) | low);
        }

        auth.AccountId = static_cast<std::uint32_t>(parsedAccount);
        auth.AuthKeyText = keyText;
        auth.Valid = true;
        return true;
    }

    std::vector<std::uint8_t> BuildAckPacket(
        std::uint16_t prefix,
        std::uint32_t serverPacketId,
        std::uint32_t acknowledgedPacketId)
    {
        BitWriter writer;
        // Verified against the client's UNetConnection::ReceivedPacket:
        //   PacketId = ReadInt(0x40000000)   -> a 30-bit field starting at bit 0
        // What older code modelled as a 16-bit "prefix" followed by a 14-bit id
        // is really this single 30-bit field. `prefix` is ignored.
        (void)prefix;
        writer.WriteBits(serverPacketId & 0x3FFFFFFFu, 30);

        // An ack bunch is [IsAck=1][bHasId][if bHasId: ReadInt(0x40000000)].
        // The old 14-bit ack id was 16 bits short and shifted everything that
        // followed it, which is why challenge bunches never parsed.
        writer.WriteBit(true);
        writer.WriteBit(true);
        writer.WriteBits(acknowledgedPacketId & 0x3FFFFFFFu, 30);
        return writer.FinishWithTrailer();
    }


    namespace
    {
        void WriteReliableControlBunch(
    BitWriter& writer,
    std::uint16_t channelSequence,
    const std::uint8_t* data,
    std::size_t dataSize)
        {
            // Заголовок подтверждён побитовым разбором клиентского packet 0:
            //   ack, bControl, [bOpen, bClose], bIsReplicationPaused,
            //   bReliable, ChIndex(10), [ChSequence(10)], ChType(3),
            //   DataBitCount(13)
            // Никаких PackageMapExports/Partial/name-токенов между ними нет.
            writer.WriteBit(false);  // not ACK
            writer.WriteBit(false);  // no open/close control flags
            writer.WriteBit(true);   // bReliable
            writer.WriteBit(false);  // bIsReplicationPaused
            writer.WriteBits(0, 10); // ChIndex
            writer.WriteBits(channelSequence % 1024u, 10);
            writer.WriteBits(1, 3);  // CHTYPE_Control
            writer.WriteBits(static_cast<std::uint32_t>(dataSize * 8u), kBunchLengthBits);
            writer.WriteBytes(data, dataSize);
        }

        std::vector<std::uint8_t> BuildControlPacketInternal(
            std::uint16_t prefix,
            std::uint32_t serverPacketId,
            bool includeAck,
            std::uint32_t acknowledgedPacketId,
            std::uint16_t channelSequence,
            const std::uint8_t* data,
            std::size_t dataSize)
        {
            BitWriter writer;
            // 30-bit packet id at bit 0 (see BuildAckPacket). `prefix` ignored.
            (void)prefix;
            writer.WriteBits(serverPacketId & 0x3FFFFFFFu, 30);

            if (includeAck)
            {
                writer.WriteBit(true);
                writer.WriteBit(true);
                writer.WriteBits(acknowledgedPacketId & 0x3FFFFFFFu, 30);
            }

            WriteReliableControlBunch(
                writer,
                channelSequence,
                data,
                dataSize);

            return writer.FinishWithTrailer();
        }

        void WriteRawFloat(BitWriter& payload, float value)
        {
            std::uint32_t bits = 0;
            std::memcpy(&bits, &value, sizeof(bits));
            payload.WriteBits(bits, 32);
        }

        void WriteNetQuat(BitWriter& payload, float x, float y, float z, float w)
        {
            const float lengthSquared = x * x + y * y + z * z + w * w;
            if (lengthSquared > 1e-8f)
            {
                const float inverse = 1.0f / std::sqrt(lengthSquared);
                x *= inverse; y *= inverse; z *= inverse; w *= inverse;
            }
            else
            {
                x = 0.0f; y = 0.0f; z = 0.0f; w = 1.0f;
            }

            if (w < 0.0f) { x = -x; y = -y; z = -z; }

            WriteRawFloat(payload, x);
            WriteRawFloat(payload, y);
            WriteRawFloat(payload, z);
        }
    }

    std::vector<std::uint8_t> BuildAckAndBinaryControlPacket(
        std::uint16_t prefix,
        std::uint32_t serverPacketId,
        std::uint32_t acknowledgedPacketId,
        std::uint16_t channelSequence,
        std::uint8_t messageType,
        const std::uint8_t* payload,
        std::size_t payloadSize)
    {
        std::vector<std::uint8_t> message;
        message.reserve(payloadSize + 1);
        message.push_back(messageType);
        if (payload != nullptr && payloadSize != 0)
            message.insert(message.end(), payload, payload + payloadSize);

        return BuildControlPacketInternal(
            prefix,
            serverPacketId,
            false,
            acknowledgedPacketId,
            channelSequence,
            message.data(),
            message.size());
    }

    std::vector<std::uint8_t> BuildBinaryControlPacket(
        std::uint16_t prefix,
        std::uint32_t serverPacketId,
        std::uint16_t channelSequence,
        std::uint8_t messageType,
        const std::uint8_t* payload,
        std::size_t payloadSize)
    {
        std::vector<std::uint8_t> message;
        message.reserve(payloadSize + 1);
        message.push_back(messageType);
        if (payload != nullptr && payloadSize != 0)
            message.insert(message.end(), payload, payload + payloadSize);

        return BuildControlPacketInternal(
            prefix,
            serverPacketId,
            false,
            0,
            channelSequence,
            message.data(),
            message.size());
    }

    std::vector<std::uint8_t> BuildAckAndTextControlPacket(
        std::uint16_t prefix,
        std::uint32_t serverPacketId,
        std::uint32_t acknowledgedPacketId,
        std::uint16_t channelSequence,
        const std::string& text)
    {
        const std::int32_t serializedLength =
            static_cast<std::int32_t>(text.size() + 1u);

        std::vector<std::uint8_t> message(4u + static_cast<std::size_t>(serializedLength), 0);
        message[0] = static_cast<std::uint8_t>(serializedLength);
        message[1] = static_cast<std::uint8_t>(serializedLength >> 8);
        message[2] = static_cast<std::uint8_t>(serializedLength >> 16);
        message[3] = static_cast<std::uint8_t>(serializedLength >> 24);
        std::copy(text.begin(), text.end(), message.begin() + 4);

        return BuildControlPacketInternal(
            prefix,
            serverPacketId,
            false,
            acknowledgedPacketId,
            channelSequence,
            message.data(),
            message.size());
    }

    // The APB control protocol is TEXT based. The client's
    // UNetPendingLevel::NotifyReceivedText reads each control bunch as an
    // FString and matches command words (UPGRADE, USES, UNLOAD, FAILURE,
    // USERFLAG, CHALLENGE, DLMGR, WELCOME). There are no binary NMT opcodes on
    // this build, so the handshake challenge must be sent as the FString
    //     "CHALLENGE VER=<ver> CHALLENGE=<value>"
    // with no ack bunch in front of it (an ack would shift the string and the
    // command word would never match).
    std::vector<std::uint8_t> BuildTextControlPacket(
        std::uint16_t prefix,
        std::uint32_t serverPacketId,
        std::uint16_t channelSequence,
        const std::string& text)
    {
        const std::int32_t serializedLength =
            static_cast<std::int32_t>(text.size() + 1u);

        std::vector<std::uint8_t> message(4u + static_cast<std::size_t>(serializedLength), 0);
        message[0] = static_cast<std::uint8_t>(serializedLength);
        message[1] = static_cast<std::uint8_t>(serializedLength >> 8);
        message[2] = static_cast<std::uint8_t>(serializedLength >> 16);
        message[3] = static_cast<std::uint8_t>(serializedLength >> 24);
        std::copy(text.begin(), text.end(), message.begin() + 4);

        return BuildControlPacketInternal(
            prefix,
            serverPacketId,
            false,
            0,
            channelSequence,
            message.data(),
            message.size());
    }


    // ------------------------------------------------------------------
    // Actor channel open bunch.
    //
    // UActorChannel::ReceivedBunch, when the channel has no actor yet, requires
    // bOpen and then reads a single object reference through
    // UPackageMapLevel::SerializeObject. It spawns NewActor->Class using that
    // object as the archetype, and if the result's NetPlayerIndex is 0 it binds
    // the actor to the connection's local player -- which is what makes the
    // client treat it as its own PlayerController.
    //
    // The property loop that follows runs only while bits remain, so an open
    // bunch carrying nothing but the archetype reference is well formed: the
    // actor is spawned entirely from archetype defaults.
    //
    // Bunch header layout (from UNetConnection::ReceivedPacket):
    //     [IsAck=0][bControl=1][bOpen=1][bClose=0][bReliable=1]
    //     [ChIndex   SerializeInt(0x3FF)]
    //     [ChSequence SerializeInt(0x400)]      (reliable)
    //     [ChType    SerializeInt(8)]           (reliable or open)
    //     [BunchDataBits SerializeInt(MaxPacket*8)]
    //     [payload]
    // ------------------------------------------------------------------
    namespace
    {
        std::vector<std::uint8_t> BuildActorOpenPacketInternal(
            std::uint32_t serverPacketId,
            std::uint16_t channelIndex,
            std::uint16_t channelSequence,
            std::uint32_t archetypeNetIndex,
            float spawnX,
            float spawnY,
            float spawnZ,
            bool writeZeroInitialRotation,
            bool writeNetPlayerIndex,
            std::uint8_t netPlayerIndex,
            const ActorInitialEnumByteFieldWire* fields,
            std::size_t fieldCount)
        {
            // Serialise the archetype reference on its own so the exact bit
            // count is known before the bunch header is written. The client
            // reads a compressed spawn location straight after the reference
            // and then consumes any remaining bits as the initial reflected
            // property stream.
            BitWriter payload;
            payload.WriteObjectByNetIndex(archetypeNetIndex);
            payload.WriteCompressedVector(spawnX, spawnY, spawnZ);

            // cAPBVehicle's archetype has bNetInitialRotation set. On actor
            // open the client therefore consumes a compressed rotator before
            // it starts reading the reflected property stream. A zero rotator
            // is encoded as three zero presence bits (Pitch, Yaw, Roll).
            if (writeZeroInitialRotation)
            {
                payload.WriteBit(false);
                payload.WriteBit(false);
                payload.WriteBit(false);
            }

            if (writeNetPlayerIndex)
                payload.WriteBits(netPlayerIndex, 8u);

            if (fields != nullptr)
            {
                for (std::size_t index = 0; index < fieldCount; ++index)
                {
                    const ActorInitialEnumByteFieldWire& field = fields[index];
                    payload.WriteBoundedInt(field.FieldIndex, field.FieldMax);
                    payload.WriteBoundedInt(
                        static_cast<std::uint32_t>(field.Value),
                        (std::max<std::uint32_t>)(field.EnumValueCount, 2u));
                }
            }

            const std::vector<std::uint8_t> payloadBytes = payload.Snapshot();
            const std::size_t payloadBits = payload.BitCount();

            BitWriter writer;
            writer.WriteBits(serverPacketId & 0x3FFFFFFFu, 30);

            writer.WriteBit(false);   // not an ack
            writer.WriteBit(true);    // bControl
            writer.WriteBit(true);    // bOpen   (в Close: false)
            writer.WriteBit(false);   // bClose  (в Close: true)
            writer.WriteBit(true);    // bReliable
            writer.WriteBit(false);   // bIsReplicationPaused

            writer.WriteBoundedInt(channelIndex, 0x3FFu);
            writer.WriteBoundedInt(channelSequence, 0x400u);
            writer.WriteBoundedInt(2u, 8u);          // CHTYPE_Actor

            writer.WriteBoundedInt(
                 static_cast<std::uint32_t>(payloadBits), kMaxBunchDataBits);

            writer.WriteBitsFrom(payloadBytes, payloadBits);

            return writer.FinishWithTrailer();
        }
    }

    std::vector<std::uint8_t> BuildActorOpenPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t archetypeNetIndex,
        float spawnX,
        float spawnY,
        float spawnZ)
    {
        return BuildActorOpenPacketInternal(
            serverPacketId,
            channelIndex,
            channelSequence,
            archetypeNetIndex,
            spawnX,
            spawnY,
            spawnZ,
            false,
            false,
            0,
            nullptr,
            0);
    }

    std::vector<std::uint8_t> BuildPlayerControllerOpenPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t archetypeNetIndex,
        float spawnX,
        float spawnY,
        float spawnZ,
        std::uint8_t netPlayerIndex)
    {
        // Default__cAPBPlayerController.bNetInitialRotation is FALSE in
        // APB 1.13.1, so no compressed rotator is written here.
        return BuildActorOpenPacketInternal(
            serverPacketId,
            channelIndex,
            channelSequence,
            archetypeNetIndex,
            spawnX,
            spawnY,
            spawnZ,
            false,
            true,
            netPlayerIndex,
            nullptr,
            0);
    }

    std::vector<std::uint8_t> BuildActorOpenPacketWithInitialEnumByteFields(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t archetypeNetIndex,
        float spawnX,
        float spawnY,
        float spawnZ,
        const ActorInitialEnumByteFieldWire* fields,
        std::size_t fieldCount)
    {
        return BuildActorOpenPacketInternal(
            serverPacketId,
            channelIndex,
            channelSequence,
            archetypeNetIndex,
            spawnX,
            spawnY,
            spawnZ,
            true,
            false,
            0,
            fields,
            fieldCount);
    }

    std::vector<std::uint8_t> BuildActorClosePacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence)
    {
        BitWriter writer;
        writer.WriteBits(serverPacketId & 0x3FFFFFFFu, 30);
        writer.WriteBit(false);   // not an ack
        writer.WriteBit(true);    // bControl
        writer.WriteBit(true);    // bOpen   (в Close: false)
        writer.WriteBit(false);   // bClose  (в Close: true)
        writer.WriteBit(true);    // bReliable
        writer.WriteBit(false);   // bIsReplicationPaused
        writer.WriteBoundedInt(channelIndex, 0x3FFu);
        writer.WriteBoundedInt(channelSequence, 0x400u);
        writer.WriteBoundedInt(2u, 8u);
        writer.WriteBoundedInt(0u, kMaxBunchDataBits);   // было 512u * 8u
        return writer.FinishWithTrailer();
    }


    // ------------------------------------------------------------------
    // Bunches on an already-open actor channel.
    //
    // UActorChannel::ReceivedBunch, once the channel has an actor, loops:
    //     SerializeInt(FieldIndex, ClassNetCache->GetMaxIndex())
    //     <field data>
    // until the bunch is exhausted. A property update and an RPC use the same
    // encoding -- the client decides which it is from the index.
    //
    // The bound comes from the live class net cache:
    //     cAPBPlayerController -> 634
    //     cAPBPawn             -> 110
    // ------------------------------------------------------------------
    namespace
    {
        void WriteActorBunchHeader(
            BitWriter& writer,
            std::uint32_t serverPacketId,
            std::uint16_t channelIndex,
            std::uint16_t channelSequence,
            std::size_t payloadBits)
        {
            writer.WriteBits(serverPacketId & 0x3FFFFFFFu, 30);
            writer.WriteBit(false);   // not an ack
            writer.WriteBit(false);   // no open/close flags
            writer.WriteBit(true);    // bReliable
            writer.WriteBit(false);   // bIsReplicationPaused
            writer.WriteBoundedInt(channelIndex, 0x3FFu);
            writer.WriteBoundedInt(channelSequence, 0x400u);
            writer.WriteBoundedInt(2u, 8u);   // CHTYPE_Actor
            writer.WriteBoundedInt(
                static_cast<std::uint32_t>(payloadBits), kMaxBunchDataBits);
        }
    }

    std::vector<std::uint8_t> BuildActorVehicleVStateFieldPacket(
    std::uint32_t serverPacketId,
    std::uint16_t channelIndex,
    std::uint16_t channelSequence,
    std::uint32_t fieldIndex,
    std::uint32_t fieldMax,
    const VehicleVStateWire& value)
    {
    BitWriter payload;
    payload.WriteBoundedInt(fieldIndex, fieldMax);
    const std::size_t handleBits = payload.BitCount();

    // RigidBodyState
    payload.WriteCompressedVector(value.PosX, value.PosY, value.PosZ);
    WriteNetQuat(payload, value.QuatX, value.QuatY, value.QuatZ, value.QuatW);
    payload.WriteCompressedVector(value.LinVelX, value.LinVelY, value.LinVelZ);
    payload.WriteCompressedVector(value.AngVelX, value.AngVelY, value.AngVelZ);
    payload.WriteBits(value.bNewData, 8);
    payload.WriteBit(value.bSleeping);
    payload.WriteBit(value.bForceState);

    // VehicleState
    payload.WriteBits(value.ServerBrake, 8);
    payload.WriteBits(value.ServerGas, 8);
    payload.WriteBits(value.ServerGear, 8);
    payload.WriteBits(value.ServerSteering, 8);
    payload.WriteBits(value.ServerRise, 8);
    payload.WriteBits(value.ServerSprint, 8);
    payload.WriteBit(value.bServerHandbrake);
    payload.WriteBits(static_cast<std::uint32_t>(value.ServerView), 32);

    const std::size_t dataBits = payload.BitCount() - handleBits;

    // Self-test. Нейтральное состояние с тремя нулевыми векторами обязано
    // дать ровно 220 бит: 11*3 вектора + 96 кватернион + 8 bNewData
    // + 1 + 1 + 48 шесть байт + 1 handbrake + 32 ServerView.
    // Иное число означает ошибку в билдере, а не в клиенте: отправлять
    // такой пакет нельзя, он сдвинет всю структуру.
    const bool neutralVectors =
        value.PosX == 0.0f && value.PosY == 0.0f && value.PosZ == 0.0f &&
        value.LinVelX == 0.0f && value.LinVelY == 0.0f && value.LinVelZ == 0.0f &&
        value.AngVelX == 0.0f && value.AngVelY == 0.0f && value.AngVelZ == 0.0f;

    if (neutralVectors && dataBits != 220)
        return {};

    BitWriter writer;
    WriteActorBunchHeader(
        writer,
        serverPacketId,
        channelIndex,
        channelSequence,
        payload.BitCount());
    writer.WriteBitsFrom(payload.Snapshot(), payload.BitCount());
    return writer.FinishWithTrailer();
    }

    // One replicated ObjectProperty carrying a single object reference,
    // e.g. Controller.Pawn or Pawn.Controller. RPC parameters use the separate
    // builder below because they have a top-level presence bit.
    std::vector<std::uint8_t> BuildActorObjectFieldPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        std::uint16_t referencedChannel)
    {
        BitWriter payload;
        payload.WriteBoundedInt(fieldIndex, fieldMax);
        payload.WriteObjectByChannel(referencedChannel);

        BitWriter writer;
        WriteActorBunchHeader(
            writer, serverPacketId, channelIndex, channelSequence,
            payload.BitCount());
        writer.WriteBitsFrom(payload.Snapshot(), payload.BitCount());
        return writer.FinishWithTrailer();
    }


    std::vector<std::uint8_t> BuildActorObjectRpcPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        std::uint16_t referencedChannel,
        std::size_t trailingDefaultParameterCount)
    {
        BitWriter payload;
        payload.WriteBoundedInt(fieldIndex, fieldMax);

        const bool objectPresent = referencedChannel != 0u;
        payload.WriteBit(objectPresent);
        if (objectPresent)
            payload.WriteObjectByChannel(referencedChannel);

        // Each omitted/default RPC parameter contributes one false
        // non-default marker. This is needed by functions such as:
        //   ClientSetViewTarget(Actor A,
        //       optional ViewTargetTransitionParams TransitionParams)
        for (std::size_t index = 0;
             index < trailingDefaultParameterCount;
             ++index)
        {
            payload.WriteBit(false);
        }

        BitWriter writer;
        WriteActorBunchHeader(
            writer, serverPacketId, channelIndex, channelSequence,
            payload.BitCount());
        writer.WriteBitsFrom(payload.Snapshot(), payload.BitCount());
        return writer.FinishWithTrailer();
    }

    std::vector<std::uint8_t> BuildActorDefaultRpcPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        std::size_t parameterCount)
    {
        BitWriter payload;
        payload.WriteBoundedInt(fieldIndex, fieldMax);
        for (std::size_t index = 0; index < parameterCount; ++index)
            payload.WriteBit(false);

        BitWriter writer;
        WriteActorBunchHeader(
            writer, serverPacketId, channelIndex, channelSequence,
            payload.BitCount());
        writer.WriteBitsFrom(payload.Snapshot(), payload.BitCount());
        return writer.FinishWithTrailer();
    }


    std::vector<std::uint8_t> BuildClientGotoStatePacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        const std::string& stateName)
    {
        BitWriter payload;
        payload.WriteBoundedInt(fieldIndex, fieldMax);

        // ClientGotoState(name NewState, optional name NewLabel).
        //
        // APB's UPackageMap::SerializeName FString path derives the FName
        // number from the transmitted string. Do not append a raw int32 here:
        // doing so is not part of the proven wire format used by this build.
        payload.WriteName(stateName);
        payload.WriteBit(false); // NewLabel = NAME_None

        BitWriter writer;
        WriteActorBunchHeader(
            writer, serverPacketId, channelIndex, channelSequence,
            payload.BitCount());
        writer.WriteBitsFrom(payload.Snapshot(), payload.BitCount());
        return writer.FinishWithTrailer();
    }


    std::vector<std::uint8_t> BuildUnreliableActorFloatFieldPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        float value)
    {
        BitWriter payload;
        payload.WriteBoundedInt(fieldIndex, fieldMax);

        // RPC float parameter outer non-default/presence bit.
        payload.WriteBit(true);

        std::uint32_t floatBits = 0;
        static_assert(
            sizeof(floatBits) == sizeof(value),
            "APB movement timestamp must be a 32-bit float");
        std::memcpy(&floatBits, &value, sizeof(floatBits));
        payload.WriteBits(floatBits, 32);

        // Unreliable bunch on an already-open actor channel:
        // PacketId, IsAck=0, no open/close flags, Reliable=0,
        // ChannelIndex, DataBits, Payload.
        BitWriter writer;
        writer.WriteBits(serverPacketId & 0x3FFFFFFFu, 30);
        writer.WriteBit(false);
        writer.WriteBit(false);
        writer.WriteBit(false);
        writer.WriteBoundedInt(channelIndex, 0x3FFu);
        writer.WriteBoundedInt(
            static_cast<std::uint32_t>(payload.BitCount()),
            512u * 8u);
        writer.WriteBitsFrom(
            payload.Snapshot(),
            payload.BitCount());

        return writer.FinishWithTrailer();
    }

    // One field carrying a list of 32 bit integers, e.g.
    // Receive_DS2GC_ANS_DISTRICT_ENTER(returnCode, districtUID, instanceNo).
    std::vector<std::uint8_t> BuildActorIntFieldPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        const std::int32_t* values,
        std::size_t valueCount)
    {
        BitWriter payload;
        payload.WriteBoundedInt(fieldIndex, fieldMax);
        for (std::size_t i = 0; i < valueCount; ++i)
            payload.WriteBits(static_cast<std::uint32_t>(values[i]), 32);

        BitWriter writer;
        WriteActorBunchHeader(
            writer, serverPacketId, channelIndex, channelSequence,
            payload.BitCount());
        writer.WriteBitsFrom(payload.Snapshot(), payload.BitCount());
        return writer.FinishWithTrailer();
    }



    std::vector<std::uint8_t> BuildActorEnumByteFieldPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        std::uint8_t value,
        std::uint32_t enumValueCount)
    {
        BitWriter payload;
        payload.WriteBoundedInt(fieldIndex, fieldMax);
        payload.WriteBoundedInt(
            static_cast<std::uint32_t>(value),
            (std::max<std::uint32_t>)(enumValueCount, 2u));

        BitWriter writer;
        WriteActorBunchHeader(
            writer,
            serverPacketId,
            channelIndex,
            channelSequence,
            payload.BitCount());
        writer.WriteBitsFrom(
            payload.Snapshot(),
            payload.BitCount());
        return writer.FinishWithTrailer();
    }

    std::vector<std::uint8_t> BuildActorVehicleStateFSMFieldPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        const std::string& actorState,
        std::uint8_t pseudoKinCompState)
    {
        if (actorState.empty() || pseudoKinCompState >= 7u)
            return {};

        BitWriter payload;
        payload.WriteBoundedInt(fieldIndex, fieldMax);

        // APBVehicleStateFSM.sActorState is skipped by the package-map
        // property filter used by UStructProperty::NetSerializeItem.  The
        // first wire bit therefore belongs directly to
        // ePseudoKinCompState.  Emitting even NAME_None's false selector here
        // shifts Dynamic (6, bits 0/1/1) into WithCollision (4, bits 0/0/1).
        //
        // UByteProperty::NetSerializeItem (0x10981D10) calls SerializeBits.
        // EPKCState has eight reflected enumerators including PKCSTATE_MAX,
        // so the client consumes exactly three bits.
        (void)actorState;
        payload.WriteBits(pseudoKinCompState, 3u);

        BitWriter writer;
        WriteActorBunchHeader(
            writer,
            serverPacketId,
            channelIndex,
            channelSequence,
            payload.BitCount());
        writer.WriteBitsFrom(payload.Snapshot(), payload.BitCount());
        return writer.FinishWithTrailer();
    }

    std::vector<std::uint8_t> BuildActorStaticObjectArrayElementFieldPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        std::uint32_t elementIndex,
        std::uint32_t elementCount,
        std::uint16_t referencedChannel)
    {
        BitWriter payload;
        payload.WriteBoundedInt(fieldIndex, fieldMax);

        // APB client UActorChannel::ReceivedBunch (0x10DE9A40) checks
        // UProperty::ArrayDim and, when it is not one, reads one complete
        // byte before calling NetSerializeItem for exactly one element.
        // That byte indexes both the ClassReps record and
        // Property->Offset + ArrayIndex * ElementSize.  It is not a
        // SerializeInt(ArrayIndex, ArrayDim), and the other elements are not
        // present in this field fragment.
        if (elementCount == 0u || elementIndex >= elementCount ||
            elementIndex > 0xffu)
        {
            return {};
        }

        payload.WriteBits(elementIndex, 8u);
        payload.WriteObjectByChannel(referencedChannel);

        BitWriter writer;
        WriteActorBunchHeader(
            writer, serverPacketId, channelIndex, channelSequence,
            payload.BitCount());
        writer.WriteBitsFrom(payload.Snapshot(), payload.BitCount());
        return writer.FinishWithTrailer();
    }


    std::vector<std::uint8_t> BuildActorVehicleUseDataFieldPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        const VehicleUseDataWire& data)
    {
        BitWriter payload;
        payload.WriteBoundedInt(fieldIndex, fieldMax);

        // APBGame.VehicleUseData field order from cAPBPawn.h. The UEnum has
        // five usable seats plus VehiclePositionIndex_MAX, so UE3 SerializeInt
        // uses 6 as the exclusive upper bound (three wire bits).
        payload.WriteBits(static_cast<std::uint32_t>(data.VehicleId), 32u);
        payload.WriteBits(data.UseId, 8u);
        payload.WriteBit(data.InsideVehicle);
        payload.WriteBoundedInt(data.SeatPosition, 6u);
        payload.WriteBit(data.SwitchingToAdjacentSeat);
        payload.WriteBit(data.TeleportIn);
        payload.WriteBit(data.OpenVehicleDoor);
        payload.WriteBit(data.CloseVehicleDoor);
        payload.WriteBit(data.GetInToVehicle);
        payload.WriteBit(data.GetOutOfVehicle);
        payload.WriteBit(data.BailOut);
        payload.WriteBit(data.RouteingToVAP);
        payload.WriteBit(data.EnteringVCP);
        payload.WriteBit(data.ExitingVCP);
        payload.WriteBit(data.ExitingVCPDeath);
        payload.WriteBit(data.Death);
        payload.WriteBit(data.LeaningOut);
        payload.WriteBit(data.EjectInitial);
        payload.WriteBit(data.EjectLater);
        payload.WriteBit(data.DoingDriverEjectFromPassengerSide);
        payload.WriteBit(data.CloseingDriverDoorFromInside);
        payload.WriteBit(data.CanDriveVehicle);
        payload.WriteBit(data.Enforcer);
        payload.WriteBits(static_cast<std::uint32_t>(data.NpcTypeDriver), 32u);
        payload.WriteBits(static_cast<std::uint32_t>(data.DriverAssetIndex), 32u);

        const float leavePosition[] = {
            data.LeaveVehicleX, data.LeaveVehicleY, data.LeaveVehicleZ
        };
        for (float value : leavePosition)
        {
            std::uint32_t bits = 0;
            static_assert(sizeof(bits) == sizeof(value),
                          "float must be 32 bits");
            std::memcpy(&bits, &value, sizeof(bits));
            payload.WriteBits(bits, 32u);
        }

        BitWriter writer;
        WriteActorBunchHeader(
            writer, serverPacketId, channelIndex, channelSequence,
            payload.BitCount());
        writer.WriteBitsFrom(payload.Snapshot(), payload.BitCount());
        return writer.FinishWithTrailer();
    }


    std::vector<std::uint8_t> BuildActorCompactGolemDescriptorFieldPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        const std::array<std::uint8_t, 48>& descriptor)
    {
        BitWriter payload;
        payload.WriteBoundedInt(fieldIndex, fieldMax);

        // APBGame.u export cGolemTypes.CompactGolemDescriptor contains three
        // Guid StructProperties at offsets 0x00, 0x10 and 0x20. The live
        // in-memory descriptor used successfully by the pawn handler is the
        // corresponding sequence of twelve FGuid DWORDs. Write each DWORD
        // explicitly so this path cannot accidentally use Windows GUID byte
        // layout or add an RPC-style presence bit.
        for (std::size_t dwordIndex = 0; dwordIndex < 12u; ++dwordIndex)
        {
            std::uint32_t value = 0;
            std::memcpy(
                &value,
                descriptor.data() + dwordIndex * sizeof(value),
                sizeof(value));
            payload.WriteBits(value, 32u);
        }

        BitWriter writer;
        WriteActorBunchHeader(
            writer,
            serverPacketId,
            channelIndex,
            channelSequence,
            payload.BitCount());
        writer.WriteBitsFrom(
            payload.Snapshot(),
            payload.BitCount());
        return writer.FinishWithTrailer();
    }


    std::vector<std::uint8_t> BuildActorRawFieldPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        const std::uint8_t* value,
        std::size_t valueSize,
        bool writeStructPresenceBit)
    {
        BitWriter payload;
        payload.WriteBoundedInt(fieldIndex, fieldMax);

        if (writeStructPresenceBit)
            payload.WriteBit(value != nullptr && valueSize != 0u);

        if (value != nullptr && valueSize != 0u)
            payload.WriteBytes(value, valueSize);

        BitWriter writer;
        WriteActorBunchHeader(
            writer,
            serverPacketId,
            channelIndex,
            channelSequence,
            payload.BitCount());
        writer.WriteBitsFrom(
            payload.Snapshot(),
            payload.BitCount());
        return writer.FinishWithTrailer();
    }

    std::vector<std::uint8_t> BuildActorParamsFieldPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        const std::vector<DebugParam>& params)
    {
        BitWriter payload;

        payload.WriteBoundedInt(fieldIndex, fieldMax);

        for (const DebugParam& p : params)
        {
            if (p.Kind == "object")
            {
                payload.WriteObjectByChannel(
                    static_cast<std::uint16_t>(p.A));
            }
            else if (p.Kind == "objectp")
            {
                payload.WriteBit(true);
                payload.WriteObjectByChannel(
                    static_cast<std::uint16_t>(p.A));
            }
            else if (p.Kind == "objecto")
            {
                payload.WriteBoundedInt(
                    static_cast<std::uint32_t>(p.A), 0x3FFu);
            }
			            else if (p.Kind == "object0")
            {
                payload.WriteBit(false);
                payload.WriteBoundedInt(
                    static_cast<std::uint32_t>(p.A), 0x3FFu);
            }
            else if (p.Kind == "object400")
            {
                payload.WriteBit(true);
                payload.WriteBoundedInt(
                    static_cast<std::uint32_t>(p.A), 0x400u);
            }
            else if (p.Kind == "objecto400")
            {
                payload.WriteBoundedInt(
                    static_cast<std::uint32_t>(p.A), 0x400u);
            }
			else if (p.Kind == "classp")
            {
                // RPC-параметр типа class<...>: presence-бит, затем ссылка
                // через package map (флаг 0 + SerializeInt(NetIndex, 0x80000000)).
                // A == 0 означает null: presence-бит 0 и ничего дальше.
                const bool present = (p.A != 0);
                payload.WriteBit(present);
                if (present)
                {
                    payload.WriteObjectByNetIndex(
                        static_cast<std::uint32_t>(p.A));
                }
            }
            else if (p.Kind == "enum")
            {
                payload.WriteBoundedInt(
                    static_cast<std::uint32_t>(p.A), p.B);
            }
            else if (p.Kind == "enump")
            {
                payload.WriteBit(true);
                payload.WriteBoundedInt(
                    static_cast<std::uint32_t>(p.A), p.B);
            }
            else if (p.Kind == "int")
            {
                payload.WriteBit(true);
                payload.WriteBits(
                    static_cast<std::uint32_t>(p.A), 32);
            }
            else if (p.Kind == "float")
            {
                // RPC scalar parameters carry their non-default/presence bit
                // before the raw IEEE-754 float payload, just like int.
                // DebugParseParams stores the float's bit pattern in A.
                payload.WriteBit(true);
                payload.WriteBits(
                    static_cast<std::uint32_t>(p.A), 32);
            }
            else if (p.Kind == "floato")
            {
                // Struct member: raw IEEE-754 float with no presence bit,
                // mirroring "into" for integers. DebugParseParams stores
                // the float's bit pattern in A.
                payload.WriteBits(
                    static_cast<std::uint32_t>(p.A), 32);
            }
            else if (p.Kind == "bool")
            {
                payload.WriteBit(p.A != 0);
            }
            else if (p.Kind == "skip")
            {
                payload.WriteBit(false);
            }
            else if (p.Kind == "into")
            {
                payload.WriteBits(
                    static_cast<std::uint32_t>(p.A), 32);
            }
        }

        BitWriter writer;

        WriteActorBunchHeader(
            writer,
            serverPacketId,
            channelIndex,
            channelSequence,
            payload.BitCount());

        writer.WriteBitsFrom(
            payload.Snapshot(),
            payload.BitCount());

        return writer.FinishWithTrailer();
    }

     bool ControlReader::ReadByte(std::uint8_t& value)
    {
        if (Remaining() < 1) return false;
        value = Data[Pos++];
        return true;
    }

    bool ControlReader::ReadInt32(std::int32_t& value)
    {
        if (Remaining() < 4) return false;
        value = static_cast<std::int32_t>(
            static_cast<std::uint32_t>(Data[Pos]) |
            (static_cast<std::uint32_t>(Data[Pos + 1]) << 8) |
            (static_cast<std::uint32_t>(Data[Pos + 2]) << 16) |
            (static_cast<std::uint32_t>(Data[Pos + 3]) << 24));
        Pos += 4;
        return true;
    }

    bool ControlReader::ReadUInt64(std::uint64_t& value)
    {
        if (Remaining() < 8) return false;
        value = 0;
        for (int i = 7; i >= 0; --i)
            value = (value << 8) | Data[Pos + static_cast<std::size_t>(i)];
        Pos += 8;
        return true;
    }

    // UE3 FString: INT длина. Положительная -> ANSI, отрицательная -> UCS2.
    // Длина включает терминатор.
    bool ControlReader::ReadFString(std::string& value)
    {
        value.clear();

        std::int32_t length = 0;
        if (!ReadInt32(length)) return false;
        if (length == 0) return true;

        if (length > 0)
        {
            if (Remaining() < static_cast<std::size_t>(length)) return false;
            value.assign(
                reinterpret_cast<const char*>(Data + Pos),
                static_cast<std::size_t>(length - 1));
            Pos += static_cast<std::size_t>(length);
            return true;
        }

        const std::size_t count = static_cast<std::size_t>(-length);
        if (Remaining() < count * 2u) return false;
        for (std::size_t i = 0; i + 1 < count; ++i)
            value.push_back(static_cast<char>(Data[Pos + i * 2]));
        Pos += count * 2u;
        return true;
    }

    bool OpenControlReader(const Bunch& bunch, ControlReader& reader)
    {
        if (bunch.Kind != BunchKind::Data ||
            bunch.ChannelType != 1 ||
            bunch.RawData.empty())
        {
            return false;
        }

        reader.Data = bunch.RawData.data();
        reader.Size = (std::min)(
            bunch.RawData.size(),
            static_cast<std::size_t>(bunch.DataBitCount) / 8u);
        reader.Pos = 0;
        return reader.Size > 0;
    }

    // One replicated BoolProperty. UE3 serializes a network bool as a
    // single payload bit after its ClassNetCache field index.
    std::vector<std::uint8_t> BuildActorBoolFieldPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        bool value)
    {
        BitWriter payload;
        payload.WriteBoundedInt(
            fieldIndex,
            fieldMax);
        payload.WriteBit(value);

        BitWriter writer;
        WriteActorBunchHeader(
            writer,
            serverPacketId,
            channelIndex,
            channelSequence,
            payload.BitCount());

        writer.WriteBitsFrom(
            payload.Snapshot(),
            payload.BitCount());

        return writer.FinishWithTrailer();
    }


    // One field carrying an FVector/Vector StructProperty.
    //
    // `compressed=false` writes three IEEE-754 floats, which is the likely
    // StructProperty(Vector) representation. `compressed=true` uses the same
    // FVector::SerializeCompressed encoding already proven for actor spawn
    // locations. The latter is retained as an experimental switch because
    // APB may use native vector NetSerialize for this property.
    std::vector<std::uint8_t> BuildActorVectorFieldPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        float x,
        float y,
        float z,
        bool compressed)
    {
        BitWriter payload;
        payload.WriteBoundedInt(fieldIndex, fieldMax);

        if (compressed)
        {
            payload.WriteCompressedVector(x, y, z);
        }
        else
        {
            const float values[3] = { x, y, z };
            for (float value : values)
            {
                std::uint32_t bits = 0;
                static_assert(sizeof(bits) == sizeof(value),
                              "float must be 32 bits");
                std::memcpy(&bits, &value, sizeof(bits));
                payload.WriteBits(bits, 32);
            }
        }

        BitWriter writer;
        WriteActorBunchHeader(
            writer, serverPacketId, channelIndex, channelSequence,
            payload.BitCount());
        writer.WriteBitsFrom(payload.Snapshot(), payload.BitCount());
        return writer.FinishWithTrailer();
    }

    // ClientUpdateLevelStreamingStatus(name PackageName, bool bShouldBeLoaded,
    //                                  bool bShouldBeVisible, bool bBlockOnLoad)
    // USES only registers a package with the package map; this is what makes
    // the client actually stream a sublevel in. Without it the persistent map
    // comes up but no block geometry is ever added to the world, which is why
    // the client sees only skydome and SpawnActor finds nowhere valid to spawn.
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
        int boolCount)
    {
        BitWriter payload;
        payload.WriteBoundedInt(fieldIndex, fieldMax);

        // NameProperty является top-level RPC parameter.
        // Сначала идёт delta/presence bit, затем SerializeName().
        const bool packageNamePresent = !packageName.empty();

        // Top-level NameProperty parameter delta/presence.
        payload.WriteBit(packageNamePresent);

        if (packageNamePresent)
        {
            // UPackageMap::SerializeName:
            // false = non-hardcoded name, FString follows.
            payload.WriteBit(false);

            // Plain name string.
            payload.WriteFString(
                packageName,
                true);

            // FName Number. Ordinary package name has Number == 0.
            payload.WriteBits(
                0u,
                32);
        }

        // The parameter tail is configurable because the client consumes fewer
        // bits than we write: leftover bits decode as a second field index
        // (field 88, ClientForceGarbageCollection, sits right next to 89) which
        // triggers a GC that unloads the level that just streamed in. That is
        // the one-frame flash of geometry.
        const bool values[4] =
            { shouldBeLoaded, shouldBeVisible, blockOnLoad, false };
        for (int i = 0; i < boolCount && i < 4; ++i)
            payload.WriteBit(values[i]);

        BitWriter writer;
        WriteActorBunchHeader(
            writer, serverPacketId, channelIndex, channelSequence,
            payload.BitCount());
        writer.WriteBitsFrom(payload.Snapshot(), payload.BitCount());
        return writer.FinishWithTrailer();
    }


    // Engine.PlayerController.ClientSetHUD(
    //     class<HUD> newHUDType,
    //     class<Scoreboard> newScoringType)
    //
    // Both parameters are ClassProperty values and therefore use
    // UPackageMapLevel::SerializeObject. A null scoreboard is encoded as the
    // package-map None reference (global net index zero).
    std::vector<std::uint8_t> BuildClientSetHudPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        std::uint32_t hudClassNetIndex,
        std::uint32_t scoringClassNetIndex)
    {
        BitWriter payload;
        payload.WriteBoundedInt(fieldIndex, fieldMax);

        // RPC ClassProperty/ObjectProperty parameters have an outer
        // non-null/non-default bit before the package-map object reference.
        //
        // v1.3.0 began directly with WriteObjectByNetIndex(), whose first bit
        // is the package-map/channel selector. The client consumed that zero
        // selector as "parameter is null", so ClientSetHUD received:
        //
        //   newHUDType     = None
        //   newScoringType = None
        //
        // A null parameter is represented by the single false bit. A non-null
        // parameter writes true and then the normal package-map reference.
        payload.WriteBit(hudClassNetIndex != 0u);
        if (hudClassNetIndex != 0u)
            payload.WriteObjectByNetIndex(hudClassNetIndex);

        payload.WriteBit(scoringClassNetIndex != 0u);
        if (scoringClassNetIndex != 0u)
            payload.WriteObjectByNetIndex(scoringClassNetIndex);

        BitWriter writer;
        WriteActorBunchHeader(
            writer,
            serverPacketId,
            channelIndex,
            channelSequence,
            payload.BitCount());

        writer.WriteBitsFrom(
            payload.Snapshot(),
            payload.BitCount());

        return writer.FinishWithTrailer();
    }


    // cAPBPlayerController.ClientSetInitialState(
    //     int nCharacterUID,
    //     byte Faction,
    //     byte Gender)
    //
    // Reflection on build 3908 proves a six-byte in-memory parameter
    // struct. Every top-level RPC parameter has a non-default/presence bit:
    //     nCharacterUID present-bit + int32
    //     Faction       present-bit + SerializeInt(value, 5)
    //     Gender        present-bit + SerializeInt(value, 5)
    std::vector<std::uint8_t> BuildClientSetInitialStatePacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        std::int32_t characterUid,
        std::uint8_t faction,
        std::uint8_t gender)
    {
        BitWriter payload;
        payload.WriteBoundedInt(fieldIndex, fieldMax);
        const bool characterUidPresent = characterUid != 0;
        payload.WriteBit(characterUidPresent);
        if (characterUidPresent)
        {
            payload.WriteBits(
                static_cast<std::uint32_t>(characterUid),
                32);
        }

        // Both ByteProperty parameters reference five-entry UEnums:
        //
        //   etFaction: None, Enforcer, Criminal, Both, MAX
        //   etGender:  None, Male, Female, Both, MAX
        constexpr std::uint32_t kFactionEnumCount = 5;
        constexpr std::uint32_t kGenderEnumCount = 5;

        payload.WriteBit(faction != 0u);
        if (faction != 0u)
        {
            payload.WriteBoundedInt(
                static_cast<std::uint32_t>(faction),
                kFactionEnumCount);
        }

        payload.WriteBit(gender != 0u);
        if (gender != 0u)
        {
            payload.WriteBoundedInt(
                static_cast<std::uint32_t>(gender),
                kGenderEnumCount);
        }

        BitWriter writer;
        WriteActorBunchHeader(
            writer,
            serverPacketId,
            channelIndex,
            channelSequence,
            payload.BitCount());

        writer.WriteBitsFrom(
            payload.Snapshot(),
            payload.BitCount());

        return writer.FinishWithTrailer();
    }



    // cAPBPlayerController.ClientReceiveCharacterInfo(
    //     cGameInfoCache.CharacterInfoPacket packet)
    //
    // Build-3908 reflection:
    //   CharacterInfoPacket property size = 45 bytes
    //   function parameter size           = 48 bytes (tail padding)
    //
    //   0x00 int     m_nAccountUID
    //   0x04 int     m_nCharacterUID
    //   0x08 int     m_nClanUID
    //   0x0C int     m_nGroupID
    //   0x10 int     m_nSideID
    //   0x14 FString m_sCharacterName
    //   0x20 FString m_sClanName
    //   0x2C byte    m_eFaction (cSDD.etFaction)
    //
    // As with the proven HUDMarkerData RPC, the StructProperty parameter has
    // one top-level non-default bit. Its members are then serialized directly
    // in reflected offset order; there are no per-member delta bits.
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
        std::uint32_t factionValueMax)
    {
        BitWriter payload;
        payload.WriteBoundedInt(fieldIndex, fieldMax);

        payload.WriteBit(true); // packet StructProperty present

        payload.WriteBits(
            static_cast<std::uint32_t>(accountUid),
            32);
        payload.WriteBits(
            static_cast<std::uint32_t>(characterUid),
            32);
        payload.WriteBits(
            static_cast<std::uint32_t>(clanUid),
            32);
        payload.WriteBits(
            static_cast<std::uint32_t>(groupId),
            32);
        payload.WriteBits(
            static_cast<std::uint32_t>(sideId),
            32);

        payload.WriteFString(characterName, true);
        payload.WriteFString(clanName, true);

        payload.WriteBoundedInt(
            static_cast<std::uint32_t>(faction),
            (std::max<std::uint32_t>)(
                factionValueMax,
                2u));

        BitWriter writer;
        WriteActorBunchHeader(
            writer,
            serverPacketId,
            channelIndex,
            channelSequence,
            payload.BitCount());

        writer.WriteBitsFrom(
            payload.Snapshot(),
            payload.BitCount());

        return writer.FinishWithTrailer();
    }


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
        const std::string& text)
    {
        BitWriter payload;

        payload.WriteBoundedInt(fieldIndex, fieldMax);
        payload.WriteBit(true);   
        payload.WriteFString(text);

        BitWriter writer;

        WriteActorBunchHeader(
            writer,
            serverPacketId,
            channelIndex,
            channelSequence,
            payload.BitCount());

        writer.WriteBitsFrom(
            payload.Snapshot(),
            payload.BitCount());

        return writer.FinishWithTrailer();
    }


    // cAPBPlayerController.ClientReceiveCharacterData(
    //     CharacterData playerCharacterData)
    //
    // Build-3908 reflection:
    //   CharacterData property size = 108 bytes
    //   function parameter size     = 108 bytes
    //
    // Offset layout:
    //   0x00 int[4]  character function mods
    //   0x10 int     primary weapon
    //   0x14 int[3]  primary weapon function mods
    //   0x20 int     secondary weapon
    //   0x24 int[3]  secondary weapon function mods
    //   0x30 int     grenade
    //   0x34 FString graffiti symbol name
    //   0x40 FString theme name
    //   0x4C FGuid   graffiti customisation GUID
    //   0x5C FGuid   theme GUID
    //
    // Like CharacterInfoPacket, the RPC has one top-level StructProperty
    // non-default bit and then direct member serialization in offset order.
    std::vector<std::uint8_t> BuildClientReceiveCharacterDataPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        const CharacterDataPayload& data,
        bool explicitPayload)
    {
        BitWriter payload;
        payload.WriteBoundedInt(fieldIndex, fieldMax);

        payload.WriteBit(explicitPayload);

        if (explicitPayload)
        {
            for (const std::int32_t value :
                 data.CharacterFnMods)
            {
                payload.WriteBits(
                    static_cast<std::uint32_t>(value),
                    32);
            }

            payload.WriteBits(
                static_cast<std::uint32_t>(
                    data.WeaponPrimary),
                32);

            for (const std::int32_t value :
                 data.WeaponPrimaryFnMods)
            {
                payload.WriteBits(
                    static_cast<std::uint32_t>(value),
                    32);
            }

            payload.WriteBits(
                static_cast<std::uint32_t>(
                    data.WeaponSecondary),
                32);

            for (const std::int32_t value :
                 data.WeaponSecondaryFnMods)
            {
                payload.WriteBits(
                    static_cast<std::uint32_t>(value),
                    32);
            }

            payload.WriteBits(
                static_cast<std::uint32_t>(
                    data.WeaponGrenade),
                32);

            payload.WriteFString(
                data.GraffitiSymbolName,
                true);
            payload.WriteFString(
                data.ThemeName,
                true);

            for (const std::uint32_t value :
                 data.GraffitiCustomisationGuid)
            {
                payload.WriteBits(value, 32);
            }

            for (const std::uint32_t value :
                 data.ThemeGuid)
            {
                payload.WriteBits(value, 32);
            }
        }

        BitWriter writer;
        WriteActorBunchHeader(
            writer,
            serverPacketId,
            channelIndex,
            channelSequence,
            payload.BitCount());

        writer.WriteBitsFrom(
            payload.Snapshot(),
            payload.BitCount());

        return writer.FinishWithTrailer();
    }


    std::uint32_t FloatToWireBits(float value)
    {
        std::uint32_t bits = 0;
        static_assert(
            sizeof(bits) == sizeof(value),
            "float wire size mismatch");
        std::memcpy(&bits, &value, sizeof(bits));
        return bits;
    }

    // cAPBPlayerController.ClientReceiveCharacterStats(
    //     CharacterStats playerCharacterStats)
    //
    // Reflected struct layout:
    //   0x00 float m_fTotalTimeInSeconds
    //   0x04 int   m_nTotalKills
    //   0x08 float m_fSessionTimeInSeconds
    //   0x0C int   m_nSessionKills
    //   0x10 int   m_nSessionMissionWon
    //   0x14 int   m_nSessionMissionLost
    //   0x18 int   m_nSessionPlayerArrested
    //   0x1C int   m_nSessionPlayerFreed
    //   0x20 int   m_nSessionMedals
    std::vector<std::uint8_t> BuildClientReceiveCharacterStatsPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        const CharacterStatsPayload& stats,
        bool explicitPayload)
    {
        BitWriter payload;
        payload.WriteBoundedInt(fieldIndex, fieldMax);
        payload.WriteBit(explicitPayload);

        if (explicitPayload)
        {
            payload.WriteBits(
                FloatToWireBits(stats.TotalTimeInSeconds),
                32);
            payload.WriteBits(
                static_cast<std::uint32_t>(stats.TotalKills),
                32);
            payload.WriteBits(
                FloatToWireBits(stats.SessionTimeInSeconds),
                32);
            payload.WriteBits(
                static_cast<std::uint32_t>(stats.SessionKills),
                32);
            payload.WriteBits(
                static_cast<std::uint32_t>(
                    stats.SessionMissionsWon),
                32);
            payload.WriteBits(
                static_cast<std::uint32_t>(
                    stats.SessionMissionsLost),
                32);
            payload.WriteBits(
                static_cast<std::uint32_t>(
                    stats.SessionPlayersArrested),
                32);
            payload.WriteBits(
                static_cast<std::uint32_t>(
                    stats.SessionPlayersFreed),
                32);
            payload.WriteBits(
                static_cast<std::uint32_t>(
                    stats.SessionMedals),
                32);
        }

        BitWriter writer;
        WriteActorBunchHeader(
            writer,
            serverPacketId,
            channelIndex,
            channelSequence,
            payload.BitCount());

        writer.WriteBitsFrom(
            payload.Snapshot(),
            payload.BitCount());

        return writer.FinishWithTrailer();
    }


    // cAPBPlayerController.ClientReceiveCharacterRolesData(
    //     CharacterRolesData RolesData)
    //
    // The only struct member is a fixed byte[99]. APB's RPC serializer emits
    // one StructProperty presence bit followed by the 99 raw array elements.
    std::vector<std::uint8_t> BuildClientReceiveCharacterRolesDataPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        const CharacterRolesDataPayload& roles,
        bool explicitPayload)
    {
        BitWriter payload;
        payload.WriteBoundedInt(fieldIndex, fieldMax);
        payload.WriteBit(explicitPayload);

        if (explicitPayload)
        {
            for (const std::uint8_t value :
                 roles.RoleMilestones)
            {
                payload.WriteBits(
                    static_cast<std::uint32_t>(value),
                    8);
            }
        }

        BitWriter writer;
        WriteActorBunchHeader(
            writer,
            serverPacketId,
            channelIndex,
            channelSequence,
            payload.BitCount());

        writer.WriteBitsFrom(
            payload.Snapshot(),
            payload.BitCount());

        return writer.FinishWithTrailer();
    }


    // cAPBPlayerController.ClientPrecacheCustomisation(
    //     Guid TheGuid,
    //     cEnums.etPlayerCustomisation eType,
    //     bool bLocalPlayer)
    //
    // The live build-3908 ClassNetCache maps this RPC to field 279.
    // Reflection/decompilation proves a 16-byte Guid, a ByteProperty enum,
    // and a BoolProperty. The Guid is a non-default StructProperty parameter:
    // one presence bit followed by FGuid A/B/C/D. Character customisation is
    // enum value zero, so its top-level delta marker is false. bLocalPlayer
    // is true and therefore serialises as one true bit.
    std::vector<std::uint8_t> BuildClientPrecacheCustomisationPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        const std::array<std::uint32_t, 4>& guid,
        std::uint8_t customisationType,
        bool localPlayer)
    {
        BitWriter payload;
        payload.WriteBoundedInt(fieldIndex, fieldMax);

        const bool guidPresent =
            guid[0] != 0u ||
            guid[1] != 0u ||
            guid[2] != 0u ||
            guid[3] != 0u;

        payload.WriteBit(guidPresent);
        if (guidPresent)
        {
            payload.WriteBits(guid[0], 32);
            payload.WriteBits(guid[1], 32);
            payload.WriteBits(guid[2], 32);
            payload.WriteBits(guid[3], 32);
        }

        // cEnums.etPlayerCustomisation:
        //   0 character, 1 vehicle, 2 graffiti.
        // Value zero is the default and is represented by a false delta bit.
        payload.WriteBit(customisationType != 0u);
        if (customisationType != 0u)
        {
            constexpr std::uint32_t kCustomisationEnumCount = 5;   // ← 1.13.1, ваш замер Num=5
            payload.WriteBoundedInt(
                static_cast<std::uint32_t>(customisationType),
                kCustomisationEnumCount);
        }

        // BoolProperty RPC parameter: its network value is the delta bit.
        payload.WriteBit(localPlayer);

        BitWriter writer;
        WriteActorBunchHeader(
            writer,
            serverPacketId,
            channelIndex,
            channelSequence,
            payload.BitCount());

        writer.WriteBitsFrom(
            payload.Snapshot(),
            payload.BitCount());

        return writer.FinishWithTrailer();
    }


    // APBGame.cCustomisationReplicator.ClientReceiveData(
    //     int nCount,
    //     byte packet[256])
    //
    // Reflection on build 3908 proves a 260-byte parameter struct:
    //   0x000 int32 nCount
    //   0x004 byte  packet[256]
    //
    // A static array is one reflected UByteProperty with ArrayDim=256.
    // APB's RPC parameter serializer writes one non-default marker for that
    // property and then serializes all 256 array elements contiguously:
    //
    //   nCount non-default bit + int32
    //   packet property non-default bit
    //   packet[256] raw bytes
    //
    // v3.7 incorrectly emitted one delta bit per byte. The crash dump showed
    // the client inside ClientReceiveData with a corrupted parameter-copy
    // source pointer, which is consistent with that bitstream misalignment.
    //
    // PerElementDelta and Raw remain available only as diagnostics.
    std::vector<std::uint8_t> BuildClientReceiveDataPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        std::int32_t count,
        const std::array<std::uint8_t, 256>& packet,
        FixedByteArrayWireMode wireMode)
    {
        BitWriter payload;
        payload.WriteBoundedInt(fieldIndex, fieldMax);

        const bool countPresent = count != 0;
        payload.WriteBit(countPresent);
        if (countPresent)
        {
            payload.WriteBits(
                static_cast<std::uint32_t>(count),
                32);
        }

        switch (wireMode)
        {
        case FixedByteArrayWireMode::SinglePresenceRaw:
        {
            const bool present =
                std::any_of(
                    packet.begin(),
                    packet.end(),
                    [](std::uint8_t value)
                    {
                        return value != 0u;
                    });

            payload.WriteBit(present);
            if (present)
            {
                payload.WriteBytes(
                    packet.data(),
                    packet.size());
            }
            break;
        }

        case FixedByteArrayWireMode::PerElementDelta:
            // Diagnostic only. This encoding crashed build 3908 because the
            // fixed array has one property marker, not 256 element markers.
            for (std::uint8_t value : packet)
            {
                const bool present = value != 0u;
                payload.WriteBit(present);
                if (present)
                    payload.WriteBits(value, 8);
            }
            break;

        case FixedByteArrayWireMode::Raw:
            payload.WriteBytes(
                packet.data(),
                packet.size());
            break;
        }

        BitWriter writer;
        WriteActorBunchHeader(
            writer,
            serverPacketId,
            channelIndex,
            channelSequence,
            payload.BitCount());

        writer.WriteBitsFrom(
            payload.Snapshot(),
            payload.BitCount());

        return writer.FinishWithTrailer();
    }



    // cAPBPlayerController.ClientGoToSpawnZoneSelectScreen(
    //     cSDD.etFaction eFaction)
    //
    // Reflection proves one ByteProperty parameter whose UEnum contains five
    // entries. Network serialization is SerializeInt(eFaction, 5).
    std::vector<std::uint8_t>
    BuildClientGoToSpawnZoneSelectScreenPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        std::uint8_t faction)
    {
        constexpr std::uint32_t kFactionEnumCount = 5;

        BitWriter payload;
        payload.WriteBoundedInt(fieldIndex, fieldMax);

        // ByteProperty RPC parameters use a leading non-default bit. The
        // v1.3.0 payload [1,0] for faction Enforcer was decoded as:
        //
        //   present = 1
        //   faction = 0
        //
        // Write the presence bit explicitly, then SerializeInt(value, 5).
        payload.WriteBit(faction != 0u);
        if (faction != 0u)
        {
            payload.WriteBoundedInt(
                static_cast<std::uint32_t>(faction),
                kFactionEnumCount);
        }

        BitWriter writer;
        WriteActorBunchHeader(
            writer,
            serverPacketId,
            channelIndex,
            channelSequence,
            payload.BitCount());

        writer.WriteBitsFrom(
            payload.Snapshot(),
            payload.BitCount());

        return writer.FinishWithTrailer();
    }


    namespace
    {
        void WriteFloatBits(BitWriter& writer, float value)
        {
            std::uint32_t bits = 0;
            static_assert(sizeof(bits) == sizeof(value),
                          "float must be 32 bits");
            std::memcpy(&bits, &value, sizeof(bits));
            writer.WriteBits(bits, 32);
        }

        void WriteHudMarkerByte(
            BitWriter& writer,
            std::uint8_t value,
            std::uint32_t valueMax,
            bool rawByteEncoding)
        {
            if (rawByteEncoding)
            {
                writer.WriteBits(value, 8);
                return;
            }

            // RPC function parameters are serialized directly through the
            // reflected ByteProperty. Enum-backed bytes use SerializeInt
            // with the enum's value count; there is no default-value or
            // presence bit inside a StructProperty parameter.
            writer.WriteBoundedInt(
                static_cast<std::uint32_t>(value),
                (std::max<std::uint32_t>)(valueMax, 2u));
        }
    }

    // cAPBPlayerController.ClientReplicateHUDMarker(
    //     HUDMarkerData markerData, int nServerMarkerID)
    //
    // Reflected parameter size is 0x28: the first 0x20 bytes are the script
    // struct and the marker id follows at offset 0x20. Script locals are not
    // serialized. Each member is written through its UE3 property serializer.
    std::vector<std::uint8_t> BuildClientReplicateHudMarkerPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax,
        const HUDMarkerWireData& marker)
    {
        BitWriter payload;
        payload.WriteBoundedInt(fieldIndex, fieldMax);

        // UE3 RPC parameters are delta-serialized against their zero/default
        // value.  Every top-level CPF_Parm begins with a one-bit "present"
        // flag.  The v2.3 packet omitted this flag for markerData, causing the
        // first pLinkedActor selector bit to be consumed as the parameter flag.
        // The live v0.2 path probe also proved that ClientDeleteHUDMarker reads
        // its IntProperty starting one bit after the field handle.
        payload.WriteBit(true); // markerData is present/non-default

        if (marker.LinkedActorByChannel &&
            marker.LinkedActorReference != 0u)
        {
            payload.WriteObjectByChannel(
                marker.LinkedActorReference);
        }
        else
        {
            // Package-map object zero is UObject None. This also permits a
            // configured static-level export NetIndex once it is known.
            payload.WriteObjectByNetIndex(
                marker.LinkedActorReference);
        }

        if (marker.CompressedLocation)
        {
            payload.WriteCompressedVector(
                marker.LocationX,
                marker.LocationY,
                marker.LocationZ);
        }
        else
        {
            WriteFloatBits(payload, marker.LocationX);
            WriteFloatBits(payload, marker.LocationY);
            WriteFloatBits(payload, marker.LocationZ);
        }

        // APBGame.u metadata for cHUDMarkerManager.HUDMarkerData:
        //   eOffsetOverride     ByteProperty, Enum=None  -> raw 8 bits
        //   eCSAAutoRouteData  ByteProperty, Enum=None  -> raw 8 bits
        //   eType              ByteProperty, Enum=None  -> raw 8 bits
        //   eState             ByteProperty, Enum=etHUDMarkerState
        //                                          -> SerializeInt(value, 19)
        // The previous all-bounded encoding shifted the archive by 13 bits
        // and made the client reject the RPC as an irrational FString size.
        payload.WriteBits(marker.OffsetOverride, 8);
        payload.WriteBits(marker.AutoRouteData, 8);
        payload.WriteBits(marker.Type, 8);
        if (marker.RawByteEncoding)
            payload.WriteBits(marker.State, 8);
        else
            payload.WriteBoundedInt(
                static_cast<std::uint32_t>(marker.State),
                (std::max<std::uint32_t>)(marker.StateMax, 2u));

        payload.WriteBit(marker.IsBeingModified);
        payload.WriteBits(
            static_cast<std::uint32_t>(marker.UserData), 32);
        payload.WriteBits(
            static_cast<std::uint32_t>(marker.UserData2), 32);

        // nServerMarkerID is a second top-level RPC parameter, so it has its
        // own presence bit before the IntProperty payload.  Omitting this bit
        // left one-bit-shifted tail data that the actor channel interpreted as
        // unrelated RPC fields.
        const bool markerIdPresent = marker.ServerMarkerId != 0;
        payload.WriteBit(markerIdPresent);
        if (markerIdPresent)
        {
            payload.WriteBits(
                static_cast<std::uint32_t>(marker.ServerMarkerId), 32);
        }

        BitWriter writer;
        WriteActorBunchHeader(
            writer, serverPacketId, channelIndex, channelSequence,
            payload.BitCount());
        writer.WriteBitsFrom(payload.Snapshot(), payload.BitCount());
        return writer.FinishWithTrailer();
    }


    // An RPC with no parameters: just the field index. Used for
    // ClientFlushLevelStreaming, which forces pending streaming requests to
    // commit instead of waiting for the streaming tick to pick them up.
    std::vector<std::uint8_t> BuildActorVoidFieldPacket(
        std::uint32_t serverPacketId,
        std::uint16_t channelIndex,
        std::uint16_t channelSequence,
        std::uint32_t fieldIndex,
        std::uint32_t fieldMax)
    {
        BitWriter payload;
        payload.WriteBoundedInt(fieldIndex, fieldMax);

        BitWriter writer;
        WriteActorBunchHeader(
            writer, serverPacketId, channelIndex, channelSequence,
            payload.BitCount());
        writer.WriteBitsFrom(payload.Snapshot(), payload.BitCount());
        return writer.FinishWithTrailer();
    }


    bool DecodeActorFieldIndex(
        const Bunch& bunch,
        std::uint32_t fieldMax,
        std::uint32_t& fieldIndex,
        std::size_t& parameterBits,
        std::string& error)
    {
        fieldIndex = 0;
        parameterBits = 0;
        error.clear();

        if (bunch.Kind != BunchKind::Data ||
            bunch.RawData.empty() ||
            bunch.DataBitCount == 0)
        {
            error = "actor bunch has no data";
            return false;
        }

        BitReader reader(
            bunch.RawData.data(),
            0,
            bunch.DataBitCount);

        if (!reader.ReadBoundedInt(
                fieldMax,
                fieldIndex))
        {
            error = "truncated actor field index";
            return false;
        }

        parameterBits = reader.Remaining();
        return true;
    }


    bool DecodeCSAKeyPressedRpc(
        const Bunch& bunch,
        std::uint32_t fieldMax,
        std::uint32_t expectedField,
        CSAKeyPressedRpc& rpc,
        std::string& error)
    {
        rpc = CSAKeyPressedRpc{};
        error.clear();
        if (bunch.Kind != BunchKind::Data || bunch.RawData.empty())
        {
            error = "CSA key-pressed bunch has no data";
            return false;
        }

        BitReader reader(bunch.RawData.data(), 0, bunch.DataBitCount);
        std::uint32_t field = 0;
        if (!reader.ReadBoundedInt(fieldMax, field) || field != expectedField)
        {
            error = "not the expected CSA key-pressed field";
            return false;
        }

        const auto readIntParameter =
            [&](std::int32_t& result) -> bool
            {
                bool present = false;
                std::uint32_t raw = 0;
                if (!reader.ReadBit(present))
                    return false;
                if (present && !reader.ReadBits(32, raw))
                    return false;
                result = static_cast<std::int32_t>(raw);
                return true;
            };

        if (!readIntParameter(rpc.InputMapping) ||
            !readIntParameter(rpc.AimRotation))
        {
            error = "truncated CSA key-pressed integer parameter";
            return false;
        }

        bool cameraPresent = false;
        std::uint32_t cameraRaw = 0;
        if (!reader.ReadBit(cameraPresent) ||
            (cameraPresent && !reader.ReadBits(32, cameraRaw)))
        {
            error = "truncated CSA key-pressed camera parameter";
            return false;
        }
        if (cameraPresent)
            std::memcpy(&rpc.CameraCollidePercent, &cameraRaw, sizeof(float));

        // Like the preceding RPC parameters, the object starts with a
        // non-default/presence bit. The old decoder treated that bit as the
        // package-map selector and consequently reported channel 45 for the
        // actor that is actually on channel 22: (22 << 1) | 1 == 45.
        if (reader.Remaining() > 0)
        {
            if (!reader.ReadBit(rpc.TargetPresent))
            {
                error = "truncated CSA key-pressed target presence";
                return false;
            }

            if (rpc.TargetPresent &&
                (!reader.ReadBit(rpc.TargetByChannel) ||
                 !reader.ReadBoundedInt(
                     rpc.TargetByChannel ? 0x3FFu : 0x80000000u,
                     rpc.TargetReference)))
            {
                error = "truncated CSA key-pressed target reference";
                return false;
            }
        }

        rpc.Matched = true;
        rpc.ConsumedBits = reader.Tell();
        return true;
    }


    bool DecodeActorIntRpc(
        const Bunch& bunch,
        std::uint32_t fieldMax,
        std::uint32_t expectedField,
        std::int32_t& value,
        std::size_t& trailingBits,
        std::string& error)
    {
        value = 0;
        trailingBits = 0;
        error.clear();

        if (bunch.Kind != BunchKind::Data ||
            bunch.RawData.empty() ||
            bunch.DataBitCount == 0)
        {
            error = "actor bunch has no data";
            return false;
        }

        BitReader reader(
            bunch.RawData.data(),
            0,
            bunch.DataBitCount);

        std::uint32_t fieldIndex = 0;
        if (!reader.ReadBoundedInt(
                fieldMax,
                fieldIndex))
        {
            error = "truncated actor field index";
            return false;
        }

        if (fieldIndex != expectedField)
        {
            error = "actor field does not match expected int RPC";
            return false;
        }

        bool present = false;
        if (!reader.ReadBit(present))
        {
            error = "truncated int parameter presence bit";
            return false;
        }

        if (!present)
        {
            error = "int parameter was serialized as default/absent";
            return false;
        }

        std::uint32_t rawValue = 0;
        if (!reader.ReadBits(32, rawValue))
        {
            error = "truncated int parameter value";
            return false;
        }

        value = static_cast<std::int32_t>(rawValue);
        trailingBits = reader.Remaining();
        return true;
    }


    bool DecodeControllerMovementRpc(
        const Bunch& bunch,
        std::uint32_t fieldMax,
        std::uint32_t dualServerMoveField,
        std::uint32_t oldServerMoveField,
        std::uint32_t serverMoveField,
        ControllerMovementRpc& movement,
        std::string& error)
    {
        movement = ControllerMovementRpc();
        error.clear();

        if (bunch.Kind != BunchKind::Data ||
            bunch.RawData.empty() ||
            bunch.DataBitCount == 0)
        {
            return false;
        }

        BitReader reader(
            bunch.RawData.data(),
            0,
            bunch.DataBitCount);

        auto readFloatParameter =
            [&](const char* name,
                bool& present,
                float& value) -> bool
            {
                present = false;
                value = 0.0f;

                if (!reader.ReadBit(present))
                {
                    error =
                        std::string("truncated ") +
                        name +
                        " presence bit";
                    return false;
                }

                if (!present)
                    return true;

                std::uint32_t raw = 0;
                if (!reader.ReadBits(32, raw))
                {
                    error =
                        std::string("truncated ") +
                        name +
                        " float";
                    return false;
                }

                std::memcpy(
                    &value,
                    &raw,
                    sizeof(value));

                if (!std::isfinite(value))
                {
                    error =
                        std::string(name) +
                        " is not finite";
                    return false;
                }

                return true;
            };

        auto readByteParameter =
            [&](const char* name,
                bool& present,
                std::uint8_t& value) -> bool
            {
                present = false;
                value = 0;

                if (!reader.ReadBit(present))
                {
                    error =
                        std::string("truncated ") +
                        name +
                        " presence bit";
                    return false;
                }

                if (!present)
                    return true;

                std::uint32_t raw = 0;
                if (!reader.ReadBits(8, raw))
                {
                    error =
                        std::string("truncated ") +
                        name +
                        " byte";
                    return false;
                }

                value =
                    static_cast<std::uint8_t>(raw);
                return true;
            };

        auto readIntParameter =
            [&](const char* name,
                bool& present,
                std::uint32_t& value) -> bool
            {
                present = false;
                value = 0;

                if (!reader.ReadBit(present))
                {
                    error =
                        std::string("truncated ") +
                        name +
                        " presence bit";
                    return false;
                }

                if (!present)
                    return true;

                if (!reader.ReadBits(32, value))
                {
                    error =
                        std::string("truncated ") +
                        name +
                        " int";
                    return false;
                }

                return true;
            };

        auto readCompressedVectorParameter =
            [&](const char* name,
                bool& present,
                std::int32_t& x,
                std::int32_t& y,
                std::int32_t& z) -> bool
            {
                present = false;
                x = 0;
                y = 0;
                z = 0;

                if (!reader.ReadBit(present))
                {
                    error =
                        std::string("truncated ") +
                        name +
                        " presence bit";
                    return false;
                }

                if (!present)
                    return true;

                std::uint32_t bitsMinusOne = 0;
                if (!reader.ReadBoundedInt(
                        20,
                        bitsMinusOne))
                {
                    error =
                        std::string("truncated ") +
                        name +
                        " bit width";
                    return false;
                }

                const std::uint32_t bits =
                    bitsMinusOne + 1u;

                if (bits > 20u)
                {
                    error =
                        std::string(name) +
                        " has invalid bit width";
                    return false;
                }

                const std::uint32_t bias =
                    1u << bits;
                const std::uint32_t maximum =
                    1u << (bits + 1u);

                std::uint32_t encodedX = 0;
                std::uint32_t encodedY = 0;
                std::uint32_t encodedZ = 0;

                if (!reader.ReadBoundedInt(
                        maximum,
                        encodedX) ||
                    !reader.ReadBoundedInt(
                        maximum,
                        encodedY) ||
                    !reader.ReadBoundedInt(
                        maximum,
                        encodedZ))
                {
                    error =
                        std::string("truncated ") +
                        name +
                        " vector";
                    return false;
                }

                x =
                    static_cast<std::int32_t>(
                        encodedX) -
                    static_cast<std::int32_t>(
                        bias);
                y =
                    static_cast<std::int32_t>(
                        encodedY) -
                    static_cast<std::int32_t>(
                        bias);
                z =
                    static_cast<std::int32_t>(
                        encodedZ) -
                    static_cast<std::int32_t>(
                        bias);

                return true;
            };

        const std::size_t firstFieldBegin =
            reader.Tell();

        while (reader.Remaining() > 0)
        {
            const std::size_t fieldBegin =
                reader.Tell();

            std::uint32_t fieldIndex = 0;
            if (!reader.ReadBoundedInt(
                    fieldMax,
                    fieldIndex))
            {
                error =
                    "truncated movement field index";
                return false;
            }

            const bool isDual =
                fieldIndex == dualServerMoveField;
            const bool isOld =
                fieldIndex == oldServerMoveField;
            const bool isServer =
                fieldIndex == serverMoveField;

            if (!isDual &&
                !isOld &&
                !isServer)
            {
                // A different RPC follows the movement call in this bunch.
                // Preserve its full field index and parameters as trailing bits.
                movement.TrailingBits =
                    bunch.DataBitCount -
                    fieldBegin;
                movement.ConsumedBits =
                    fieldBegin;
                return movement.Matched;
            }

            if (!movement.Matched)
            {
                movement.Matched = true;
                movement.FieldIndex = fieldIndex;
                movement.FieldIndexBits =
                    reader.Tell() -
                    firstFieldBegin;
                movement.ParameterBits =
                    bunch.DataBitCount -
                    reader.Tell();
            }

            ++movement.RpcCount;

            if (isOld)
            {
                movement.IsOldServerMove = true;
                ++movement.OldServerMoveCount;

                bool oldTimePresent = false;
                float oldTimeStamp = 0.0f;
                bool oldAccelXPresent = false;
                bool oldAccelYPresent = false;
                bool oldAccelZPresent = false;
                bool oldFlagsPresent = false;
                std::uint8_t oldAccelX = 0;
                std::uint8_t oldAccelY = 0;
                std::uint8_t oldAccelZ = 0;
                std::uint8_t oldFlags = 0;

                if (!readFloatParameter(
                        "OldTimeStamp",
                        oldTimePresent,
                        oldTimeStamp) ||
                    !readByteParameter(
                        "OldAccelX",
                        oldAccelXPresent,
                        oldAccelX) ||
                    !readByteParameter(
                        "OldAccelY",
                        oldAccelYPresent,
                        oldAccelY) ||
                    !readByteParameter(
                        "OldAccelZ",
                        oldAccelZPresent,
                        oldAccelZ) ||
                    !readByteParameter(
                        "OldMoveFlags",
                        oldFlagsPresent,
                        oldFlags))
                {
                    return false;
                }

                movement.OldAccelerationPresent =
                    oldAccelXPresent ||
                    oldAccelYPresent ||
                    oldAccelZPresent;
                movement.OldAccelX = oldAccelX;
                movement.OldAccelY = oldAccelY;
                movement.OldAccelZ = oldAccelZ;
                movement.OldMoveFlagsPresent =
                    oldFlagsPresent;
                movement.OldMoveFlags =
                    oldFlags;
                continue;
            }

            if (isServer)
            {
                movement.IsServerMove = true;
                ++movement.ServerMoveCount;

                bool timePresent = false;
                float timeStamp = 0.0f;
                bool accelPresent = false;
                std::int32_t accelX = 0;
                std::int32_t accelY = 0;
                std::int32_t accelZ = 0;
                bool locationPresent = false;
                std::int32_t locationX = 0;
                std::int32_t locationY = 0;
                std::int32_t locationZ = 0;
                bool flagsPresent = false;
                std::uint8_t flags = 0;
                bool rollPresent = false;
                std::uint8_t roll = 0;
                bool viewPresent = false;
                std::uint32_t view = 0;

                if (!readFloatParameter(
                        "TimeStamp",
                        timePresent,
                        timeStamp) ||
                    !readCompressedVectorParameter(
                        "InAccel",
                        accelPresent,
                        accelX,
                        accelY,
                        accelZ) ||
                    !readCompressedVectorParameter(
                        "ClientLoc",
                        locationPresent,
                        locationX,
                        locationY,
                        locationZ) ||
                    !readByteParameter(
                        "MoveFlags",
                        flagsPresent,
                        flags) ||
                    !readByteParameter(
                        "ClientRoll",
                        rollPresent,
                        roll) ||
                    !readIntParameter(
                        "View",
                        viewPresent,
                        view))
                {
                    return false;
                }

                if (timePresent)
                {
                    movement.TimeStampPresent = true;
                    movement.HasTimeStamp = true;
                    movement.TimeStamp =
                        timeStamp;
                }

                movement.AccelerationPresent =
                    accelPresent;
                movement.AccelerationX =
                    accelX;
                movement.AccelerationY =
                    accelY;
                movement.AccelerationZ =
                    accelZ;

                movement.ClientLocationPresent =
                    locationPresent;
                movement.ClientLocationX =
                    locationX;
                movement.ClientLocationY =
                    locationY;
                movement.ClientLocationZ =
                    locationZ;

                movement.MoveFlagsPresent =
                    flagsPresent;
                movement.MoveFlags =
                    flags;
                movement.ClientRollPresent =
                    rollPresent;
                movement.ClientRoll =
                    roll;
                movement.ViewPresent =
                    viewPresent;
                movement.View =
                    view;
                continue;
            }

            // DualServerMove
            movement.IsDualServerMove = true;
            ++movement.DualServerMoveCount;

            bool timeStamp0Present = false;
            float timeStamp0 = 0.0f;
            bool accel0Present = false;
            std::int32_t accel0X = 0;
            std::int32_t accel0Y = 0;
            std::int32_t accel0Z = 0;
            bool pendingFlagsPresent = false;
            std::uint8_t pendingFlags = 0;
            bool view0Present = false;
            std::uint32_t view0 = 0;

            bool timePresent = false;
            float timeStamp = 0.0f;
            bool accelPresent = false;
            std::int32_t accelX = 0;
            std::int32_t accelY = 0;
            std::int32_t accelZ = 0;
            bool locationPresent = false;
            std::int32_t locationX = 0;
            std::int32_t locationY = 0;
            std::int32_t locationZ = 0;
            bool flagsPresent = false;
            std::uint8_t flags = 0;
            bool rollPresent = false;
            std::uint8_t roll = 0;
            bool viewPresent = false;
            std::uint32_t view = 0;

            if (!readFloatParameter(
                    "TimeStamp0",
                    timeStamp0Present,
                    timeStamp0) ||
                !readCompressedVectorParameter(
                    "InAccel0",
                    accel0Present,
                    accel0X,
                    accel0Y,
                    accel0Z) ||
                !readByteParameter(
                    "PendingFlags",
                    pendingFlagsPresent,
                    pendingFlags) ||
                !readIntParameter(
                    "View0",
                    view0Present,
                    view0) ||
                !readFloatParameter(
                    "TimeStamp",
                    timePresent,
                    timeStamp) ||
                !readCompressedVectorParameter(
                    "InAccel",
                    accelPresent,
                    accelX,
                    accelY,
                    accelZ) ||
                !readCompressedVectorParameter(
                    "ClientLoc",
                    locationPresent,
                    locationX,
                    locationY,
                    locationZ) ||
                !readByteParameter(
                    "NewFlags",
                    flagsPresent,
                    flags) ||
                !readByteParameter(
                    "ClientRoll",
                    rollPresent,
                    roll) ||
                !readIntParameter(
                    "View",
                    viewPresent,
                    view))
            {
                return false;
            }

            if (timePresent)
            {
                movement.TimeStampPresent = true;
                movement.HasTimeStamp = true;
                movement.TimeStamp =
                    timeStamp;
            }
            else if (timeStamp0Present)
            {
                movement.TimeStampPresent = true;
                movement.HasTimeStamp = true;
                movement.TimeStamp =
                    timeStamp0;
            }

            // Prefer the newest move's parameters; if they are default,
            // retain the first move's active input/flags for diagnostics.
            movement.AccelerationPresent =
                accelPresent ||
                accel0Present;
            movement.AccelerationX =
                accelPresent
                    ? accelX
                    : accel0X;
            movement.AccelerationY =
                accelPresent
                    ? accelY
                    : accel0Y;
            movement.AccelerationZ =
                accelPresent
                    ? accelZ
                    : accel0Z;

            movement.ClientLocationPresent =
                locationPresent;
            movement.ClientLocationX =
                locationX;
            movement.ClientLocationY =
                locationY;
            movement.ClientLocationZ =
                locationZ;

            movement.MoveFlagsPresent =
                flagsPresent ||
                pendingFlagsPresent;
            movement.MoveFlags =
                flagsPresent
                    ? flags
                    : pendingFlags;
            movement.ClientRollPresent =
                rollPresent;
            movement.ClientRoll =
                roll;
            movement.ViewPresent =
                viewPresent ||
                view0Present;
            movement.View =
                viewPresent
                    ? view
                    : view0;
        }

        movement.ConsumedBits =
            reader.Tell();
        movement.TrailingBits =
            reader.Remaining();

        return movement.Matched;
    }


    bool DecodeControllerActorFields(
        const Bunch& bunch,
        std::uint32_t fieldMax,
        std::uint32_t serverUpdateLevelVisibilityField,
        std::uint32_t serverNotifyClientLoadedField,
        std::uint32_t serverSelectSpawnZoneField,
        std::vector<ControllerActorField>& fields,
        std::string& error)
    {
        fields.clear();
        error.clear();

        if (bunch.Kind != BunchKind::Data)
        {
            error = "not a data bunch";
            return false;
        }

        if (bunch.RawData.empty() ||
            bunch.DataBitCount == 0)
        {
            error = "empty actor bunch";
            return false;
        }

        BitReader reader(
            bunch.RawData.data(),
            0,
            bunch.DataBitCount);

        while (reader.Remaining() > 0)
        {
            ControllerActorField field{};
            field.BeginBit = reader.Tell();

            std::uint32_t fieldIndex = 0;

            if (!reader.ReadBoundedInt(
                    fieldMax,
                    fieldIndex))
            {
                std::ostringstream stream;
                stream
                    << "truncated field index at bit "
                    << field.BeginBit;

                error = stream.str();
                return !fields.empty();
            }

            field.FieldIndex = fieldIndex;

            // Exact build-3908 wire index from the inherited
            // cAPBPlayerController ClassNetCache:
            //
            //   376 NewServerDrive(float TimeStamp, byte Inputs)
            //
            // Both parameters use UE3's ordinary non-default marker. This
            // produces the observed total widths:
            //
            //   11 bits  both parameters default
            //   43 bits  TimeStamp present, Inputs default (zero)
            //   51 bits  TimeStamp and Inputs both present
            constexpr std::uint32_t kNewServerDriveField = 376;

            if (fieldIndex == kNewServerDriveField)
            {
                if (!reader.ReadBit(field.DriveTimeStampPresent))
                {
                    error =
                        "truncated TimeStamp presence bit for "
                        "NewServerDrive";
                    return !fields.empty();
                }

                if (field.DriveTimeStampPresent)
                {
                    std::uint32_t timeStampBits = 0;
                    if (!reader.ReadBits(32, timeStampBits))
                    {
                        error =
                            "truncated TimeStamp value for NewServerDrive";
                        return !fields.empty();
                    }

                    static_assert(
                        sizeof(timeStampBits) == sizeof(field.DriveTimeStamp),
                        "APB drive timestamp must be a 32-bit float");
                    std::memcpy(
                        &field.DriveTimeStamp,
                        &timeStampBits,
                        sizeof(field.DriveTimeStamp));
                }

                if (!reader.ReadBit(field.DriveInputsPresent))
                {
                    error =
                        "truncated Inputs presence bit for NewServerDrive";
                    return !fields.empty();
                }

                if (field.DriveInputsPresent)
                {
                    std::uint32_t inputs = 0;
                    if (!reader.ReadBits(8, inputs))
                    {
                        error =
                            "truncated Inputs value for NewServerDrive";
                        return !fields.empty();
                    }

                    field.DriveInputs =
                        static_cast<std::uint8_t>(inputs);
                }

                field.IsNewServerDrive = true;
                field.EndBit = reader.Tell();
                fields.push_back(field);
                continue;
            }

            // Field 78 is emitted continuously by this client build.
            // Every standalone occurrence is exactly 66 bits total:
            //
            //   10 bits  bounded field index
            //   56 bits  parameters
            //
            // Field 78 is a high-frequency fixed-width update. Field 484 is a
            // separate fixed-width call embedded between the second and third
            // visibility RPCs in the reliable post-stream batch.
            constexpr std::uint32_t
                kKnownFrequentFixedWidthField = 78;
            constexpr std::size_t
                kKnownFrequentFixedWidthFieldTotalBits = 66;

            // The reliable post-stream batch is laid out as:
            //
            //   field 90 artprops                       356 bits
            //   field 90 terrain                        484 bits
            //   field 484                               168 bits total
            //   ten remaining field-90 visibility RPCs 2928 bits
            //
            // 356 + 484 + 168 + 2928 = 3936 exactly.
            //
            // Important: UE3 SerializeInt is value-dependent. Field 484's
            // bounded index consumes 9 bits in this build, not 10. Therefore
            // its parameters occupy 159 bits. Store total field widths and
            // subtract the number of index bits actually consumed instead of
            // assuming a fixed index width.
            constexpr std::uint32_t
                kKnownPostStreamFixedWidthField = 484;
            constexpr std::size_t
                kKnownPostStreamFixedWidthFieldTotalBits = 168;

            // Captured immediately after the now-proven wire field 372
            // ServerNotifyClientLoaded invocation. BeginStartUpSequence then
            // calls NotifyServerLfgStateChanged; the remaining invocation is
            // 21 bits total in this build:
            //
            //   field index 530 = 10 bits
            //   parameters      = 11 bits
            constexpr std::uint32_t
                kKnownStartupFollowupField = 530;
            constexpr std::size_t
                kKnownStartupFollowupFieldTotalBits = 21;

            std::size_t fixedTotalBits = 0;

            if (fieldIndex ==
                    kKnownFrequentFixedWidthField)
            {
                fixedTotalBits =
                    kKnownFrequentFixedWidthFieldTotalBits;
            }
            else if (fieldIndex ==
                         kKnownPostStreamFixedWidthField)
            {
                fixedTotalBits =
                    kKnownPostStreamFixedWidthFieldTotalBits;
            }
            else if (fieldIndex ==
                         kKnownStartupFollowupField)
            {
                fixedTotalBits =
                    kKnownStartupFollowupFieldTotalBits;
            }
            if (fixedTotalBits != 0)
            {
                const std::size_t indexBits =
                    reader.Tell() - field.BeginBit;

                if (indexBits > fixedTotalBits)
                {
                    std::ostringstream stream;
                    stream
                        << "fixed-width controller field "
                        << fieldIndex
                        << " consumed "
                        << indexBits
                        << " index bits, exceeding total width "
                        << fixedTotalBits;

                    error = stream.str();
                    return !fields.empty();
                }

                std::size_t fixedParameterBits =
                    fixedTotalBits - indexBits;

                if (reader.Remaining() <
                        fixedParameterBits)
                {
                    std::ostringstream stream;
                    stream
                        << "truncated fixed-width controller field "
                        << fieldIndex
                        << " at bit "
                        << field.BeginBit
                        << "; indexBits="
                        << indexBits
                        << " parameterBits="
                        << fixedParameterBits
                        << " remaining="
                        << reader.Remaining();

                    error = stream.str();
                    return !fields.empty();
                }

                while (fixedParameterBits >= 32)
                {
                    std::uint32_t ignored = 0;

                    if (!reader.ReadBits(32, ignored))
                    {
                        error =
                            "failed to skip fixed-width controller "
                            "field parameters";
                        return !fields.empty();
                    }

                    fixedParameterBits -= 32;
                }

                if (fixedParameterBits != 0)
                {
                    std::uint32_t ignored = 0;

                    if (!reader.ReadBits(
                            fixedParameterBits,
                            ignored))
                    {
                        error =
                            "failed to skip trailing fixed-width "
                            "controller field parameters";
                        return !fields.empty();
                    }
                }

                field.EndBit = reader.Tell();
                fields.push_back(field);
                continue;
            }

            if (fieldIndex ==
                    serverNotifyClientLoadedField)
            {
                // Reliable server RPC with ParmsSize=0. The bounded field
                // index is the complete invocation.
                field.IsServerNotifyClientLoaded = true;
                field.EndBit = reader.Tell();
                fields.push_back(field);
                continue;
            }

            if (fieldIndex ==
                    serverSelectSpawnZoneField)
            {
                bool parameterPresent = false;
                bool byChannel = false;
                std::uint32_t reference = 0;

                // ServerSelectSpawnZone has one UObject RPC parameter. The
                // first bit is the top-level non-default/presence flag; only
                // then does UPackageMapLevel::SerializeObject read its selector.
                if (!reader.ReadBit(parameterPresent))
                {
                    error =
                        "truncated SpawnZone parameter-presence bit for "
                        "ServerSelectSpawnZone";
                    return !fields.empty();
                }

                if (parameterPresent)
                {
                    if (!reader.ReadBit(byChannel))
                    {
                        error =
                            "truncated object-reference selector for "
                            "ServerSelectSpawnZone";
                        return !fields.empty();
                    }

                    if (!reader.ReadBoundedInt(
                            byChannel ? 0x3FFu : 0x80000000u,
                            reference))
                    {
                        error =
                            "truncated SpawnZone object reference for "
                            "ServerSelectSpawnZone";
                        return !fields.empty();
                    }
                }

                field.IsServerSelectSpawnZone = true;
                field.ObjectReferenceByChannel = byChannel;
                field.ObjectReferenceValue = reference;
                field.EndBit = reader.Tell();
                fields.push_back(field);
                continue;
            }


            // Exact live cAPBPlayerController cache:
            //   489 ServerRequestCharacterData(int nCharacterUID)
            constexpr std::uint32_t
                kServerRequestCharacterDataField = 489;

            if (fieldIndex ==
                    kServerRequestCharacterDataField)
            {
                bool characterUidPresent = false;

                if (!reader.ReadBit(
                        characterUidPresent))
                {
                    error =
                        "truncated CharacterUID presence bit for "
                        "ServerRequestCharacterData";
                    return !fields.empty();
                }

                std::uint32_t characterUid = 0;

                if (characterUidPresent &&
                    !reader.ReadBits(
                        32,
                        characterUid))
                {
                    error =
                        "truncated CharacterUID for "
                        "ServerRequestCharacterData";
                    return !fields.empty();
                }

                field.IsServerRequestCharacterData = true;
                field.RequestedCharacterUid =
                    static_cast<std::int32_t>(
                        characterUid);
                field.EndBit = reader.Tell();
                fields.push_back(field);
                continue;
            }

            // Opening PlayerInfo in build 3908 emits both requests in one
            // reliable controller bunch:
            //
            //   491 ServerRequestCharacterStats(int nCharacterUID)
            //   498 ServerRequestCharacterRolesData(int nCharacterUID)
            //
            // Each parameter is one RPC delta/presence bit plus int32.
            constexpr std::uint32_t
                kServerRequestCharacterStatsField = 491;
            constexpr std::uint32_t
                kServerRequestCharacterRolesDataField = 498;

            if (fieldIndex ==
                    kServerRequestCharacterStatsField)
            {
                bool characterUidPresent = false;

                if (!reader.ReadBit(
                        characterUidPresent))
                {
                    error =
                        "truncated CharacterUID presence bit for "
                        "ServerRequestCharacterStats";
                    return !fields.empty();
                }

                std::uint32_t characterUid = 0;

                if (characterUidPresent &&
                    !reader.ReadBits(
                        32,
                        characterUid))
                {
                    error =
                        "truncated CharacterUID for "
                        "ServerRequestCharacterStats";
                    return !fields.empty();
                }

                field.IsServerRequestCharacterStats = true;
                field.RequestedCharacterStatsUid =
                    static_cast<std::int32_t>(
                        characterUid);
                field.EndBit = reader.Tell();
                fields.push_back(field);
                continue;
            }

            if (fieldIndex ==
                    kServerRequestCharacterRolesDataField)
            {
                bool characterUidPresent = false;

                if (!reader.ReadBit(
                        characterUidPresent))
                {
                    error =
                        "truncated CharacterUID presence bit for "
                        "ServerRequestCharacterRolesData";
                    return !fields.empty();
                }

                std::uint32_t characterUid = 0;

                if (characterUidPresent &&
                    !reader.ReadBits(
                        32,
                        characterUid))
                {
                    error =
                        "truncated CharacterUID for "
                        "ServerRequestCharacterRolesData";
                    return !fields.empty();
                }

                field.IsServerRequestCharacterRolesData = true;
                field.RequestedCharacterRolesUid =
                    static_cast<std::int32_t>(
                        characterUid);
                field.EndBit = reader.Tell();
                fields.push_back(field);
                continue;
            }

            if (fieldIndex !=
                    serverUpdateLevelVisibilityField)
            {
                field.EndBit = reader.Tell();
                fields.push_back(field);

                std::ostringstream stream;
                stream
                    << "unknown controller field "
                    << fieldIndex
                    << " at bit "
                    << field.BeginBit
                    << "; parameter size is unknown";

                error = stream.str();
                return true;
            }

            bool stringNameFollows = false;

            if (!reader.ReadBit(stringNameFollows))
            {
                error =
                    "truncated FName selector for "
                    "ServerUpdateLevelVisibility";
                return false;
            }

            if (stringNameFollows)
            {
                if (!reader.ReadFString(
                        field.PackageName))
                {
                    error =
                        "invalid FString package name for "
                        "ServerUpdateLevelVisibility";
                    return false;
                }
            }
            else
            {
                field.PackageName = "None";
            }

            bool visible = false;

            if (!reader.ReadBit(visible))
            {
                error =
                    "truncated bIsVisible for "
                    "ServerUpdateLevelVisibility";
                return false;
            }

            field.IsServerUpdateLevelVisibility = true;
            field.IsVisible = visible;
            field.EndBit = reader.Tell();

            fields.push_back(std::move(field));
        }

        return !fields.empty();
    }


    bool ReadBinaryControlMessage(
    const Bunch& bunch,
    std::uint8_t& messageType,
    std::vector<std::uint8_t>& payload)
    {
        messageType = 0;
        payload.clear();

        if (bunch.Kind != BunchKind::Data ||
            bunch.ChannelType != 1 ||
            bunch.DataBitCount < 8 ||
            bunch.RawData.empty())
        {
            return false;
        }

        // DataBitCount читается как 13 бит (SerializeInt(NumBits, 1024*8)),
        // поэтому payload начинается на границе байта сообщения и никакого
        // сдвига на бит больше не требуется. Старый одно-битный shift был
        // компенсацией 12-битного чтения длины.
        messageType = bunch.RawData[0];

        const std::size_t payloadBytes = bunch.DataBitCount / 8u;
        if (payloadBytes > 1u)
        {
            payload.assign(
                bunch.RawData.begin() + 1,
                bunch.RawData.begin() + payloadBytes);
        }

        return true;
    }

    std::string DescribePacket(const Packet& packet)
    {
        std::ostringstream stream;
        stream << "prefix=0x"
               << std::hex << std::uppercase << std::setw(4) << std::setfill('0')
               << packet.Prefix
               << std::dec << " packetId=" << packet.PacketId
               << " payloadBits=" << packet.PayloadBitCount
               << " bunches=" << packet.Bunches.size();

        if (!packet.Valid)
            stream << " invalid=" << packet.Error;
        else if (!packet.Error.empty())
            stream << " partialTail=" << packet.Error;

        for (std::size_t index = 0; index < packet.Bunches.size(); ++index)
        {
            const Bunch& bunch = packet.Bunches[index];
            stream << " | #" << index;

            if (bunch.Kind == BunchKind::Ack)
            {
                stream << " ACK(" << bunch.AckPacketId << ")";
                continue;
            }

            stream << " DATA"
                   << " open=" << (bunch.Open ? 1 : 0)
                   << " close=" << (bunch.Close ? 1 : 0)
                   << " paused=" << (bunch.ReplicationPaused ? 1 : 0)
                   << " rel=" << (bunch.Reliable ? 1 : 0)
                   << " ch=" << bunch.ChannelIndex
                   << " seq=" << bunch.ChannelSequence
                   << " type=" << static_cast<unsigned int>(bunch.ChannelType)
                   << " bits=" << bunch.DataBitCount;

            for (const std::string& text : bunch.ControlStrings)
                stream << " text=[" << text << "]";

            if (bunch.ChannelType == 1 &&
                bunch.ControlStrings.empty() &&
                !bunch.RawData.empty())
            {
                stream << " controlMessage="
                       << static_cast<unsigned int>(bunch.RawData[0]);
            }
        }

        return stream.str();
    }

    std::string Hex(
        const std::uint8_t* data,
        std::size_t size,
        std::size_t maximum)
    {
        if (data == nullptr || size == 0)
            return std::string();

        const std::size_t outputSize = std::min(size, maximum);
        std::ostringstream stream;
        stream << std::hex << std::uppercase << std::setfill('0');

        for (std::size_t index = 0; index < outputSize; ++index)
        {
            if (index != 0)
                stream << ' ';
            stream << std::setw(2) << static_cast<unsigned int>(data[index]);
        }

        if (outputSize < size)
            stream << " ...";

        return stream.str();
    }

    bool RunSelfTest(std::string& details)
    {
        const std::uint8_t fixture[] = {
            0x00,0x00,0x00,0x80,0x05,0x20,0x80,0x60,0xC9,0x11,0x00,0x00,
            0x40,0x50,0x15,0x15,0x12,0x48,0xD0,0xD0,0x50,0x12,0x51,0x0F,
            0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x4C,0x0C,0x48,0x50,
            0x15,0x15,0xD2,0x52,0x51,0x56,0x4F,0x8E,0x91,0x0D,0x0C,0x4D,
            0x8D,0x91,0x0D,0x4E,0x4D,0xCD,0x0C,0x4E,0x4D,0x4C,0x91,0x10,
            0xD1,0xCC,0x4D,0x4E,0x8E,0x4C,0xCD,0x0C,0xCC,0x4D,0x8E,0x10,
            0x4E,0x91,0x8C,0x8D,0x4D,0x11,0xCE,0x90,0x10,0x0E,0x11,0x40
        };

        Packet packet;
        if (!ParsePacket(fixture, sizeof(fixture), packet))
        {
            details = "fixture parse failed: " + packet.Error;
            return false;
        }

        if (packet.Prefix != 0 ||
            packet.PacketId != 0 ||
            packet.Bunches.size() != 1)
        {
            details = "fixture packet header did not match";
            return false;
        }

        const Bunch& bunch = packet.Bunches[0];
        if (!bunch.Open || !bunch.Reliable ||
            bunch.ChannelIndex != 0 ||
            bunch.ChannelSequence != 1 ||
            bunch.ChannelType != 1 ||
            bunch.DataBitCount != 600 ||
            bunch.ControlStrings.size() != 1)
        {
            details = "fixture bunch did not match expected UE3 control framing";
            return false;
        }

        AuthCommand auth;
        if (!ParseAuthCommand(bunch.ControlStrings[0], auth))
        {
            details = "fixture AUTH parse failed: " + auth.Error;
            return false;
        }

        if (auth.AccountId != 1 ||
            auth.AuthKeyText != "9F6045F68553851EBD3799253079B8E266E8CB8D")
        {
            details = "fixture AUTH values did not match";
            return false;
        }

        // Ack packet: 30-bit packet id + [IsAck=1][bHasId=1][30-bit ack id]
        // plus the terminator bit = 62 bits -> 8 bytes.
        const std::vector<std::uint8_t> ack = BuildAckPacket(0, 0, 0);
        if (ack.size() != 8)
        {
            details = "ACK builder produced unexpected byte length";
            return false;
        }

        // The real handshake challenge is a TEXT control message with no ack
        // bunch in front of it. Verify the FString round-trips and that the
        // packet contains exactly one control bunch.
        const std::string challengeText = "CHALLENGE VER=3908 CHALLENGE=305419896";
        const std::vector<std::uint8_t> challenge =
            BuildTextControlPacket(0, 0, 1, challengeText);

        Packet challengePacket;
        if (!ParsePacket(challenge.data(), challenge.size(), challengePacket) ||
            challengePacket.PacketId != 0 ||
            challengePacket.Bunches.size() != 1 ||
            challengePacket.Bunches[0].Kind != BunchKind::Data ||
            challengePacket.Bunches[0].ChannelType != 1 ||
            challengePacket.Bunches[0].ControlStrings.size() != 1 ||
            challengePacket.Bunches[0].ControlStrings[0] != challengeText)
        {
            details = "Text challenge builder self-test failed";
            return false;
        }

        // Captured build-3908 controller field 90:
        // ServerUpdateLevelVisibility(
        //   rworldsocialdistrict_beacons, true)
        const std::uint8_t visibilityFixture[] =
        {
            0x5A, 0xEC, 0x00, 0x00, 0x00, 0x90, 0xBB, 0x7B,
            0x93, 0x63, 0x23, 0x9B, 0x7B, 0x1B, 0x4B, 0x0B,
            0x63, 0x23, 0x4B, 0x9B, 0xA3, 0x93, 0x4B, 0x1B,
            0xA3, 0xFB, 0x12, 0x2B, 0x0B, 0x1B, 0x7B, 0x73,
            0x9B, 0x03, 0x08
        };

        Bunch visibilityBunch{};
        visibilityBunch.Kind = BunchKind::Data;
        visibilityBunch.ChannelIndex = 2;
        visibilityBunch.ChannelType = 2;
        visibilityBunch.DataBitCount = 276;
        visibilityBunch.RawData.assign(
            visibilityFixture,
            visibilityFixture +
                sizeof(visibilityFixture));

        std::vector<ControllerActorField> visibilityFields;
        std::string visibilityError;

        if (!DecodeControllerActorFields(
                visibilityBunch,
                634,
                90,
                372,
                371,
                visibilityFields,
                visibilityError) ||
            visibilityFields.size() != 1 ||
            visibilityFields[0].FieldIndex != 90 ||
            !visibilityFields[0].
                IsServerUpdateLevelVisibility ||
            visibilityFields[0].PackageName !=
                "rworldsocialdistrict_beacons" ||
            !visibilityFields[0].IsVisible)
        {
            details =
                "controller field-90 decoder self-test failed: " +
                visibilityError;
            return false;
        }

        // Captured standalone NewServerDrive(0.0f, 0), field 376. Both
        // parameters are left at their defaults, hence the 11-bit total.
        const std::uint8_t driveDefaultFixture[] = { 0x78, 0x01 };

        Bunch driveDefaultBunch{};
        driveDefaultBunch.Kind = BunchKind::Data;
        driveDefaultBunch.ChannelIndex = 2;
        driveDefaultBunch.ChannelType = 2;
        driveDefaultBunch.DataBitCount = 11;
        driveDefaultBunch.RawData.assign(
            driveDefaultFixture,
            driveDefaultFixture + sizeof(driveDefaultFixture));

        std::vector<ControllerActorField> driveDefaultFields;
        std::string driveDefaultError;

        if (!DecodeControllerActorFields(
                driveDefaultBunch,
                634,
                90,
                372,
                371,
                driveDefaultFields,
                driveDefaultError) ||
            !driveDefaultError.empty() ||
            driveDefaultFields.size() != 1 ||
            !driveDefaultFields[0].IsNewServerDrive ||
            driveDefaultFields[0].DriveTimeStampPresent ||
            driveDefaultFields[0].DriveInputsPresent ||
            driveDefaultFields[0].FieldIndex != 376 ||
            driveDefaultFields[0].BeginBit != 0 ||
            driveDefaultFields[0].EndBit != 11)
        {
            details =
                "default NewServerDrive decoder self-test failed: " +
                driveDefaultError;
            return false;
        }

        // Synthetic non-default form: timestamp plus Inputs=0x81. This is
        // the 51-bit layout emitted while a driving key is held and the high
        // bit reports that IsAbleToDrive() succeeded on the client.
        BitWriter driveActivePayload;
        driveActivePayload.WriteBoundedInt(376, 634);
        driveActivePayload.WriteBit(true);
        const float driveFixtureTimeStamp = 123.25f;
        std::uint32_t driveFixtureTimeStampBits = 0;
        std::memcpy(
            &driveFixtureTimeStampBits,
            &driveFixtureTimeStamp,
            sizeof(driveFixtureTimeStampBits));
        driveActivePayload.WriteBits(driveFixtureTimeStampBits, 32);
        driveActivePayload.WriteBit(true);
        driveActivePayload.WriteBits(0x81u, 8);

        Bunch driveActiveBunch{};
        driveActiveBunch.Kind = BunchKind::Data;
        driveActiveBunch.ChannelIndex = 2;
        driveActiveBunch.ChannelType = 2;
        driveActiveBunch.DataBitCount = driveActivePayload.BitCount();
        driveActiveBunch.RawData = driveActivePayload.Snapshot();

        std::vector<ControllerActorField> driveActiveFields;
        std::string driveActiveError;
        if (!DecodeControllerActorFields(
                driveActiveBunch,
                634,
                90,
                372,
                371,
                driveActiveFields,
                driveActiveError) ||
            !driveActiveError.empty() ||
            driveActiveFields.size() != 1 ||
            !driveActiveFields[0].IsNewServerDrive ||
            !driveActiveFields[0].DriveTimeStampPresent ||
            driveActiveFields[0].DriveTimeStamp != driveFixtureTimeStamp ||
            !driveActiveFields[0].DriveInputsPresent ||
            driveActiveFields[0].DriveInputs != 0x81u ||
            driveActiveFields[0].EndBit != 51u)
        {
            details =
                "active NewServerDrive decoder self-test failed: " +
                driveActiveError;
            return false;
        }

        const std::vector<std::uint8_t> selectSpawnPacket =
            BuildActorObjectRpcPacket(
                6, 2, 3, 371, 634, 5);

        Packet parsedSelectSpawnPacket;
        std::vector<ControllerActorField> selectSpawnFields;
        std::string selectSpawnError;
        if (!ParsePacket(
                selectSpawnPacket.data(), selectSpawnPacket.size(),
                parsedSelectSpawnPacket) ||
            parsedSelectSpawnPacket.Bunches.size() != 1 ||
            !DecodeControllerActorFields(
                parsedSelectSpawnPacket.Bunches[0],
                634, 90, 372, 371,
                selectSpawnFields, selectSpawnError) ||
            selectSpawnFields.size() != 1 ||
            !selectSpawnFields[0].IsServerSelectSpawnZone ||
            !selectSpawnFields[0].ObjectReferenceByChannel ||
            selectSpawnFields[0].ObjectReferenceValue != 5)
        {
            details =
                "ServerSelectSpawnZone decoder self-test failed: " +
                selectSpawnError;
            return false;
        }

        HUDMarkerWireData markerFixture{};
        markerFixture.LocationX = 33063.848f;
        markerFixture.LocationY = 37346.258f;
        markerFixture.LocationZ = 1328.0f;
        markerFixture.Type = 31;
        markerFixture.ServerMarkerId = 900001;

        const std::vector<std::uint8_t> markerPacket =
            BuildClientReplicateHudMarkerPacket(
                7, 2, 4, 392, 634, markerFixture);

        Packet parsedMarkerPacket;
        if (!ParsePacket(
                markerPacket.data(), markerPacket.size(),
                parsedMarkerPacket) ||
            parsedMarkerPacket.Bunches.size() != 1 ||
            parsedMarkerPacket.Bunches[0].ChannelIndex != 2 ||
            parsedMarkerPacket.Bunches[0].DataBitCount == 0)
        {
            details = "HUD-marker packet builder self-test failed";
            return false;
        }

        // Pawn field 78 with fieldMax 110 has a seven-bit cache index plus the
        // 223 reflected VehicleUseData bits. This protects against adding an
        // RPC presence bit or accidentally writing the 20 bools as bytes.
        VehicleUseDataWire vehicleUseFixture{};
        vehicleUseFixture.UseId = 2;
        vehicleUseFixture.SeatPosition = 0;
        vehicleUseFixture.RouteingToVAP = true;
        vehicleUseFixture.CanDriveVehicle = true;
        const std::vector<std::uint8_t> vehicleUsePacket =
            BuildActorVehicleUseDataFieldPacket(
                8, 4, 5, 78, 110, vehicleUseFixture);

        Packet parsedVehicleUsePacket;
        if (!ParsePacket(
                vehicleUsePacket.data(), vehicleUsePacket.size(),
                parsedVehicleUsePacket) ||
            parsedVehicleUsePacket.Bunches.size() != 1 ||
            parsedVehicleUsePacket.Bunches[0].ChannelIndex != 4 ||
            parsedVehicleUsePacket.Bunches[0].DataBitCount != 230)
        {
            details = "VehicleUseData packet builder self-test failed";
            return false;
        }

        // Vehicle lifecycle experiment: the ordinary actor-open payload is
        // preserved byte-for-bit, and the reflected initial property stream
        // is appended after the compressed spawn location. The two fields are
        // cAPBVehicle.SetupType=38 and Actor.Physics=PHYS_RigidBody.
        const std::vector<std::uint8_t> plainVehicleOpen =
            BuildActorOpenPacket(
                9, 22, 1, 44384, 139046.0f, 151633.0f, 50.0f);

        const ActorInitialEnumByteFieldWire vehicleInitialFields[] =
        {
            { 109u, 114u, 38u, 46u },
            { 12u, 114u, 6u, 9u }
        };

        const std::vector<std::uint8_t> initialVehicleOpen =
            BuildActorOpenPacketWithInitialEnumByteFields(
                9,
                22,
                1,
                44384,
                139046.0f,
                151633.0f,
                50.0f,
                vehicleInitialFields,
                sizeof(vehicleInitialFields) /
                    sizeof(vehicleInitialFields[0]));

        Packet parsedPlainVehicleOpen;
        Packet parsedInitialVehicleOpen;
        if (!ParsePacket(
                plainVehicleOpen.data(),
                plainVehicleOpen.size(),
                parsedPlainVehicleOpen) ||
            !ParsePacket(
                initialVehicleOpen.data(),
                initialVehicleOpen.size(),
                parsedInitialVehicleOpen) ||
            parsedPlainVehicleOpen.Bunches.size() != 1 ||
            parsedInitialVehicleOpen.Bunches.size() != 1 ||
            !parsedInitialVehicleOpen.Bunches[0].Open ||
            parsedInitialVehicleOpen.Bunches[0].ChannelIndex != 22)
        {
            details = "initial vehicle actor-open framing self-test failed";
            return false;
        }

        const Bunch& plainVehicleBunch =
            parsedPlainVehicleOpen.Bunches[0];
        const Bunch& initialVehicleBunch =
            parsedInitialVehicleOpen.Bunches[0];

        // The cAPBVehicle open path first consumes three zero presence bits
        // for its compressed initial rotator. Handles use seven bits each;
        // setup value uses six and Physics uses three, so the complete tail is
        // 3 + 23 = 26 bits.
        if (initialVehicleBunch.DataBitCount !=
                plainVehicleBunch.DataBitCount + 26u)
        {
            details = "initial vehicle actor-open bit count self-test failed";
            return false;
        }

        BitReader initialVehicleTail(
            initialVehicleBunch.RawData.data(),
            plainVehicleBunch.DataBitCount,
            initialVehicleBunch.DataBitCount);

        std::uint32_t setupHandle = 0;
        std::uint32_t setupValue = 0;
        std::uint32_t physicsHandle = 0;
        std::uint32_t physicsValue = 0;
        bool pitchPresent = true;
        bool yawPresent = true;
        bool rollPresent = true;

        if (!initialVehicleTail.ReadBit(pitchPresent) ||
            !initialVehicleTail.ReadBit(yawPresent) ||
            !initialVehicleTail.ReadBit(rollPresent) ||
            pitchPresent ||
            yawPresent ||
            rollPresent ||
            !initialVehicleTail.ReadBoundedInt(114u, setupHandle) ||
            !initialVehicleTail.ReadBoundedInt(46u, setupValue) ||
            !initialVehicleTail.ReadBoundedInt(114u, physicsHandle) ||
            !initialVehicleTail.ReadBoundedInt(9u, physicsValue) ||
            initialVehicleTail.Remaining() != 0 ||
            setupHandle != 109u ||
            setupValue != 38u ||
            physicsHandle != 12u ||
            physicsValue != 6u)
        {
            details = "initial vehicle actor-open field tail self-test failed";
            return false;
        }

        // cAPBVehicle.m_aSeatPawnsForWitnessing is a four-element static
        // ObjectProperty array. Its one ClassNetCache field (100/114) is
        // followed by an eight-bit array index and one UObject reference.
        const std::vector<std::uint8_t> seatWitnessPacket =
            BuildActorStaticObjectArrayElementFieldPacket(
                8, 22, 3, 100, 114, 0, 4, 4);
        Packet parsedSeatWitnessPacket;
        if (!ParsePacket(
                seatWitnessPacket.data(), seatWitnessPacket.size(),
                parsedSeatWitnessPacket) ||
            parsedSeatWitnessPacket.Bunches.size() != 1 ||
            parsedSeatWitnessPacket.Bunches[0].ChannelIndex != 22 ||
            parsedSeatWitnessPacket.Bunches[0].DataBitCount != 26)
        {
            details = "static object-array packet builder self-test failed";
            return false;
        }

        details = DescribePacket(packet) +
            " | ACK=" + Hex(ack.data(), ack.size()) +
            " | CHALLENGE=" + Hex(challenge.data(), challenge.size());
        return true;
    }
}
