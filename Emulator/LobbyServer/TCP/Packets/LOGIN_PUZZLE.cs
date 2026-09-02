using FrameWork.NetWork;

namespace LobbyServer.TCP.Packets
{
    static public class LOGIN_PUZZLE
    {
        static public void Send(LobbyClient client)
        {
            PacketOut Out = new PacketOut((uint)Opcodes.LOGIN_PUZZLE);

            // APB 1.13.1.647319
            Out.WriteInt32Reverse(1);
            Out.WriteInt32Reverse(13);
            Out.WriteInt32Reverse(1);
            Out.WriteInt32Reverse(647319);

            Out.WriteByte(0x05);

            for (int i = 0; i < client.ECrypt.Key.Length; i++)
                Out.WriteByte(client.ECrypt.Key[i]);

            Out.WriteUInt32Reverse(0);
            Out.WriteUInt32Reverse(0);
            Out.WriteUInt32Reverse(0);

            client.SendTCP(Out);
        }
    }
}