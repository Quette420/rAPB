using FrameWork.NetWork;
using FrameWork.Logger;
using MyDB;

namespace LobbyServer.TCP.Packets
{
    [PacketHandlerAttribute(
        PacketHandlerType.TCP,
        (int)Opcodes.ASK_CHARACTER_NAME_CHECK,
        "onAskCharacterNameCheck"
    )]
    public class CHARACTER_NAME_CHECK : IPacketHandler
    {
        public int HandlePacket(BaseClient client, PacketIn packet)
        {
            LobbyClient cclient = (LobbyClient)client;

            uint worldUid = packet.GetUint32Reversed();
            string name = packet.GetParsedString();

            Log.Info(
                "CHARACTER_NAME_CHECK",
                "WorldUid=" + worldUid +
                ", Name='" + name + "'" +
                ", Account=" + cclient.Account.Index
            );

            PacketOut Out =
                new PacketOut(
                    (uint)Opcodes.ANS_CHARACTER_NAME_CHECK
                );

            if (Databases.CharacterTable.Count(
                    c => c.Name == name) == 0)
            {
                cclient.Pending =
                    new CharacterEntry();

                cclient.Pending.Index =
                    Databases.CharacterTable.GenerateIndex();

                cclient.Pending.AccountIndex =
                    cclient.Account.Index;

                cclient.Pending.Name =
                    name ?? "";

                cclient.Pending.World =
                    (int)worldUid;

                cclient.Pending.Rank = 1;
                cclient.Pending.Money = 0;
                cclient.Pending.JokerTickets = 0;
                cclient.Pending.Playtime = 0;

                cclient.Pending.Clan = "";

                cclient.Pending.IsOnline = 0;
                cclient.Pending.DistrictID = 0;
                cclient.Pending.DistrictType = 0;

                cclient.Pending.LFG = 0;
                cclient.Pending.GroupStatus = 0;
                cclient.Pending.IsGroupPublic = 0;
                cclient.Pending.GroupInvite = 0;

                Out.WriteUInt32Reverse(
                    (uint)ResponseCodes.RC_SUCCESS
                );

                Log.Info(
                    "CHARACTER_NAME_CHECK",
                    "Pending created: Index=" +
                    cclient.Pending.Index +
                    ", Account=" +
                    cclient.Pending.AccountIndex +
                    ", World=" +
                    cclient.Pending.World +
                    ", Name='" +
                    cclient.Pending.Name + "'"
                );
            }
            else
            {
                cclient.Pending =
                    default(CharacterEntry);

                Out.WriteUInt32Reverse(
                    (uint)ResponseCodes
                        .RC_CHARACTER_NAME_CHECK_IN_USE
                );

                Log.Info(
                    "CHARACTER_NAME_CHECK",
                    "Name already exists: " + name
                );
            }

            cclient.Send(Out);

            return 0;
        }
    }
}