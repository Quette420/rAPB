using FrameWork.NetWork;
using FrameWork.Logger;
using System.Collections.Generic;

namespace LobbyServer.TCP.Packets
{
    [PacketHandlerAttribute(
        PacketHandlerType.TCP,
        (int)Opcodes.ASK_WORLD_LIST,
        "onAskWorldList"
    )]
    public class WORLD_LIST : IPacketHandler
    {
        public int HandlePacket(
            BaseClient client,
            PacketIn packet
        )
        {
            LobbyClient cclient =
                (LobbyClient)client;

            SendWorldList(cclient);

            return 0;
        }

        public static void SendWorldList(
            LobbyClient cclient
        )
        {
            PacketOut Out =
                new PacketOut(
                    (uint)Opcodes.WORLD_LIST
                );

            Out.WriteInt32Reverse(
                (int)ResponseCodes.RC_SUCCESS
            );

            lock (Program.worldListener.Worlds)
            {
                Out.WriteUInt16Reverse(
                    (ushort)
                    Program.worldListener.Worlds.Count
                );

                foreach (
                    KeyValuePair<uint, World.World> entry
                    in Program.worldListener.Worlds)
                {
                    World.World info =
                        entry.Value;

                    Log.Info(
                        "WORLD_LIST",
                        "UID=" + entry.Key +
                        ", Name=" + info.Name +
                        ", Address=" +
                        info.IP1 + "." +
                        info.IP2 + "." +
                        info.IP3 + "." +
                        info.IP4 + ":" +
                        info.Port
                    );

                    Out.WriteUInt32Reverse(
                        entry.Key
                    );

                    Out.WriteParsedString(
                        info.Name,
                        32
                    );

                    Out.WriteByte(
                        (byte)info.Id
                    );

                    Out.WriteByte(
                        info.Population
                    );

                    Out.WriteByte(1);
                    Out.WriteByte(1);
                }
            }

            cclient.Send(Out);
        }
    }
}