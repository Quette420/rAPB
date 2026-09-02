using FrameWork.NetWork;
using System;
using MyDB;

namespace LobbyServer.TCP.Packets
{
    [PacketHandlerAttribute(
        PacketHandlerType.TCP,
        (int)Opcodes.ASK_CHARACTER_CREATE,
        "onAskCharacterCreate"
    )]
    public class CHARACTER_CREATE : IPacketHandler
    {
        public int HandlePacket(BaseClient client, PacketIn packet)
        {
            LobbyClient cclient = (LobbyClient)client;

            PacketOut Out = new PacketOut(
                (uint)Opcodes.ANS_CHARACTER_CREATE
            );

            byte freeSlot = GetFreeSlot(cclient);

            if (freeSlot == 0)
            {
                Out.WriteInt32Reverse(
                    (int)ResponseCodes.RC_FAILED
                );

                cclient.Send(Out);
                return 0;
            }

            // -------------------------------------------------
            // Character base information
            // -------------------------------------------------

            cclient.Pending.Slot = freeSlot;

            // Character must belong to currently logged-in account.
            cclient.Pending.AccountIndex = cclient.Account.Index;

            cclient.Pending.Faction = packet.GetUint8();
            cclient.Pending.Gender = packet.GetUint8();

            cclient.Pending.Version =
                (byte)packet.GetUint32Reversed();

            // Unknown/reserved fields in character-create packet.
            packet.GetUint32Reversed();
            packet.GetUint32Reversed();

            // -------------------------------------------------
            // Appearance
            // -------------------------------------------------

            long remaining =
                packet.Length - packet.Position;

            if (remaining < 0)
                remaining = 0;

            if (remaining > int.MaxValue)
                throw new InvalidOperationException(
                    "Character customization packet is too large: " + remaining
                );

            int customLength = (int)remaining;

            byte[] Custom =
                new byte[customLength];

            if (Custom.Length > 0)
            {
                packet.Read(
                    Custom,
                    0,
                    Custom.Length
                );
            }

            // The database representation used by this emulator
            // expects the 0x36 header before customization data.
            byte[] ActualCustom =
                new byte[Custom.Length + 4];

            ActualCustom[0] = 0x36;
            ActualCustom[1] = 0x00;
            ActualCustom[2] = 0x00;
            ActualCustom[3] = 0x00;

            if (Custom.Length > 0)
            {
                Buffer.BlockCopy(
                    Custom,
                    0,
                    ActualCustom,
                    4,
                    Custom.Length
                );
            }

            cclient.Pending.Appearance =
                BitConverter.ToString(ActualCustom);

            // -------------------------------------------------
            // Protect MyDB.GetObjects<T>() against DBNull
            // -------------------------------------------------

            if (cclient.Pending.Name == null)
                cclient.Pending.Name = "";

            if (cclient.Pending.Clan == null)
                cclient.Pending.Clan = "";

            if (cclient.Pending.Appearance == null)
                cclient.Pending.Appearance = "";

            // -------------------------------------------------
            // Default runtime/database state
            // -------------------------------------------------

            cclient.Pending.IsOnline = 0;
            cclient.Pending.DistrictID = 0;
            cclient.Pending.DistrictType = 0;
            cclient.Pending.LFG = 0;
            cclient.Pending.GroupStatus = 0;
            cclient.Pending.IsGroupPublic = 0;
            cclient.Pending.GroupInvite = 0;

            // -------------------------------------------------
            // Save
            // -------------------------------------------------

            Databases.CharacterTable.Add(
                cclient.Pending
            );

            // Keep the in-memory character list in sync.
            if (cclient.Characters == null)
            {
                cclient.Characters =
                    new System.Collections.Generic.List<CharacterEntry>();
            }

            cclient.Characters.Add(
                cclient.Pending
            );

            // -------------------------------------------------
            // Response
            // -------------------------------------------------

            Out.WriteInt32Reverse(
                (int)ResponseCodes.RC_SUCCESS
            );

            Out.WriteInt32Reverse(
                cclient.Pending.Slot
            );

            cclient.Send(Out);

            return 0;
        }

        public byte GetFreeSlot(LobbyClient client)
        {
            bool[] slots = new bool[8];

            // Fresh account may not have a character list yet.
            if (client.Characters != null)
            {
                foreach (CharacterEntry ch in client.Characters)
                {
                    // Protect against malformed database rows.
                    if (ch.Slot >= 1 && ch.Slot <= 8)
                    {
                        slots[ch.Slot - 1] = true;
                    }
                }
            }

            for (int i = 0; i < slots.Length; i++)
            {
                if (!slots[i])
                {
                    return (byte)(i + 1);
                }
            }

            // No free character slots.
            return 0;
        }
    }
}