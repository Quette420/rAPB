using FrameWork.NetWork;
using System;
namespace WorldServer.TCP.Packets
{
    [PacketHandlerAttribute(
        PacketHandlerType.TCP,
        (int)Opcodes.ASK_DISTRICT_ENTER,
        "onAskDistrictEnter")]
    public class DISTRICT_ENTER : IPacketHandler
    {
        public int HandlePacket(
            BaseClient client,
            PacketIn packet)
        {
            Send((WorldClient)client);
            return 0;
        }

        public static void Send(
            WorldClient cclient)
        {
            PacketOut Out =
                new PacketOut(
                    (uint)Opcodes.ANS_DISTRICT_ENTER);

            if (cclient.Reserved != null)
            {
                Out.WriteInt32(
                    (int)ResponseCodes.RC_SUCCESS);

                string[] result =
                    cclient.Reserved.IP.Split('.');

                foreach (string s in result)
                    Out.WriteByte(
                        Convert.ToByte(s));

                Out.WriteUInt16Reverse(
                    cclient.Reserved.Port);

                ulong timestamp =
                    (ulong)TCPManager.GetTimeStamp();

                Out.WriteUInt64Reverse(
                    timestamp);

                var timestampBytes =
                    BitConverter.GetBytes(
                        timestamp);

                var sha1 =
                    new Sha1Digest();

                sha1.BlockUpdate(
                    cclient.Crypto.Key,
                    0,
                    cclient.Crypto.Key.Length);

                sha1.BlockUpdate(
                    timestampBytes,
                    0,
                    timestampBytes.Length);

                var handshakeHash =
                    new byte[
                        sha1.GetDigestSize()];

                sha1.DoFinal(
                    handshakeHash,
                    0);

                byte[] hash =
                    new byte[
                        handshakeHash.Length];

                Buffer.BlockCopy(
                    handshakeHash,
                    0,
                    hash,
                    0,
                    handshakeHash.Length);

                sha1 =
                    new Sha1Digest();

                sha1.BlockUpdate(
                    cclient.Crypto.Key,
                    0,
                    cclient.Crypto.Key.Length);

                sha1.BlockUpdate(
                    handshakeHash,
                    0,
                    handshakeHash.Length);

                var encryptionHash =
                    new byte[
                        sha1.GetDigestSize()];

                sha1.DoFinal(
                    encryptionHash,
                    0);

                var encryptionKey =
                    new byte[16];

                Buffer.BlockCopy(
                    encryptionHash,
                    0,
                    encryptionKey,
                    0,
                    16);

                // ---------------------------------------------
                // Account handoff + district encryption key.
                // ---------------------------------------------

                SendAll(
                    cclient.Reserved.tcp.Client,
                    new byte[]
                    {
                        0x31,
                        Convert.ToByte(
                            cclient.Account.Index)
                    });

                SendAll(
                    cclient.Reserved.tcp.Client,
                    encryptionKey);

                // ---------------------------------------------
                // Appearance.
                // ---------------------------------------------

                byte[] appearance =
                    DecodeAppearance(
                        cclient.Character.Appearance);

                // ---------------------------------------------
                // Character profile handoff v2.
                //
                // 4 bytes CharacterUID
                // 1 byte  Faction
                // 1 byte  Gender
                // 1 byte  AppearanceVersion
                // 4 bytes AppearanceLength
                //
                // Total fixed header = 11 bytes.
                // ---------------------------------------------

                byte[] characterProfile =
                    new byte[11];

                byte[] characterUid =
                    BitConverter.GetBytes(
                        cclient.Character.Index);

                Buffer.BlockCopy(
                    characterUid,
                    0,
                    characterProfile,
                    0,
                    4);

                characterProfile[4] =
                    cclient.Character.Faction;

                characterProfile[5] =
                    cclient.Character.Gender;

                characterProfile[6] =
                    cclient.Character.Version;

                byte[] appearanceLength =
                    BitConverter.GetBytes(
                        (uint)appearance.Length);

                Buffer.BlockCopy(
                    appearanceLength,
                    0,
                    characterProfile,
                    7,
                    4);

                SendAll(
                    cclient.Reserved.tcp.Client,
                    characterProfile);

                SendAll(
                    cclient.Reserved.tcp.Client,
                    appearance);

                Console.WriteLine(
                    "District character handoff: " +
                    "UID={0} Faction={1} Gender={2} " +
                    "Version={3} AppearanceBytes={4}",
                    cclient.Character.Index,
                    cclient.Character.Faction,
                    cclient.Character.Gender,
                    cclient.Character.Version,
                    appearance.Length);
            }
            else
            {
                Out.WriteUInt32Reverse(
                    (uint)ResponseCodes
                        .RC_DISTRICT_RESERVE_DISTRICT_OFFLINE);
            }

            cclient.Send(Out);
        }

        private static byte[] DecodeAppearance(
            string encoded)
        {
            if (string.IsNullOrWhiteSpace(encoded))
                return Array.Empty<byte>();

            string[] values =
                encoded.Split('-');

            byte[] result =
                new byte[values.Length];

            for (int i = 0;
                 i < values.Length;
                 ++i)
            {
                if (values[i].Length == 0)
                {
                    result[i] = 0;
                    continue;
                }

                result[i] =
                    Convert.ToByte(
                        values[i],
                        16);
            }

            return result;
        }

        private static void SendAll(
            System.Net.Sockets.Socket socket,
            byte[] data)
        {
            if (data == null ||
                data.Length == 0)
            {
                return;
            }

            int offset = 0;

            while (offset < data.Length)
            {
                int sent =
                    socket.Send(
                        data,
                        offset,
                        data.Length - offset,
                        System.Net.Sockets
                            .SocketFlags.None);

                if (sent <= 0)
                {
                    throw new System.IO.IOException(
                        "District handoff socket closed " +
                        "while sending.");
                }

                offset += sent;
            }
        }
    }
}