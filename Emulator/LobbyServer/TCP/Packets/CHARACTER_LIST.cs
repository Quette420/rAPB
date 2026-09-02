using FrameWork.NetWork;
using FrameWork.Logger;
using System.Collections.Generic;
using MyDB;

namespace LobbyServer.TCP.Packets
{
    static public class CHARACTER_LIST
    {
        static public void Send(LobbyClient client)
        {
            List<CharacterEntry> characters =
                Databases.CharacterTable.Select(
                    c => c.AccountIndex ==
                         client.Account.Index
                );

            client.Characters = characters;

            PacketOut Out =
                new PacketOut(
                    (uint)Opcodes.CHARACTER_LIST
                );

            Out.WriteByte(
                (byte)characters.Count
            );

            lock (Program.worldListener.Worlds)
            {
                foreach (CharacterEntry chr
                         in characters)
                {
                    Out.WriteByte(chr.Slot);
                    Out.WriteByte(chr.Faction);

                    Out.WriteByte(1);

                    Out.WriteUInt32Reverse(
                        (uint)chr.World
                    );

                    World.World info = null;

                    Program.worldListener.Worlds
                        .TryGetValue(
                            (uint)chr.World,
                            out info
                        );

                    if (info != null)
                    {
                        Out.WriteParsedString(
                            info.Name,
                            32
                        );
                    }
                    else
                    {
                        Out.WriteParsedString(
                            "(undefined)",
                            32
                        );
                    }

                    Out.WriteParsedString(
                        chr.Name ?? "",
                        32
                    );
                }
            }

            Log.Info(
                "CHARACTER_LIST",
                "Characters=" +
                characters.Count
            );

            client.Send(Out);

            // New account needs a world selection.
            if (characters.Count <= 0)
            {
                Log.Info(
                    "CHARACTER_LIST",
                    "No characters, sending WORLD_LIST"
                );

                WORLD_LIST.SendWorldList(
                    client
                );
            }
        }
    }
}