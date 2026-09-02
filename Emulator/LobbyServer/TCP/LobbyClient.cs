using FrameWork.NetWork;
using LobbyServer.SRP;
using LobbyServer.TCP.Packets;
using System.IO;
using System.Collections.Generic;
using FrameWork.Logger;
using MyDB;

namespace LobbyServer
{
    public class LobbyClient : BaseClient
    {
        private const int FrameHeaderSize = 4;
        private const int MinimumFrameSize = 8;
        private const int MaximumFrameSize = 16 * 1024 * 1024;

        // TCP is a byte stream. One Receive() is not guaranteed
        // to contain exactly one APB packet.
        private readonly List<byte> _receiveBuffer = new List<byte>();

        #region Database

        public AccountEntry Account;
        public List<CharacterEntry> Characters = null;
        public CharacterEntry Pending;

        #endregion

        #region SRP

        public byte[] Salt;
        public FrameWork.NetWork.Crypto.BigInteger Verifier;
        public ServerModulus serverModulus;
        public FrameWork.NetWork.Crypto.BigInteger clientModulus;
        public byte[] Proof;

        #endregion

        public TCP.Encryption ECrypt;
        public byte[] SessionId;

        public LobbyClient(TCPManager srv)
            : base(srv)
        {
        }

        public override void OnConnect()
        {
            Program.clients.Add(this);

            ECrypt = new TCP.Encryption();

            LOGIN_PUZZLE.Send(this);
        }

        public override void OnDisconnect()
        {
            lock (this)
            {
                _receiveBuffer.Clear();
            }

            Program.clients.Remove(this);

            Proof = null;
            Salt = null;
            Verifier = null;
            serverModulus = null;
            clientModulus = null;
            SessionId = null;
        }

        protected override void OnReceive(PacketIn packet)
        {
            lock (this)
            {
                byte[] incoming = packet.ToArray();

                if (incoming == null || incoming.Length == 0)
                    return;

                // Add received TCP bytes to our stream buffer.
                _receiveBuffer.AddRange(incoming);

                while (true)
                {
                    // Need at least 4 bytes for APB frame length.
                    if (_receiveBuffer.Count < FrameHeaderSize)
                        break;

                    // APB uses little-endian uint32 frame size.
                    int frameLength =
                        _receiveBuffer[0] |
                        (_receiveBuffer[1] << 8) |
                        (_receiveBuffer[2] << 16) |
                        (_receiveBuffer[3] << 24);

                    if (frameLength < MinimumFrameSize ||
                        frameLength > MaximumFrameSize)
                    {
                        Log.Error(
                            "LobbyClient.Frame",
                            "Invalid frame length: " +
                            frameLength +
                            ", buffered bytes: " +
                            _receiveBuffer.Count
                        );

                        _receiveBuffer.Clear();
                        Disconnect();
                        return;
                    }

                    // TCP packet is incomplete. Wait for more bytes.
                    if (_receiveBuffer.Count < frameLength)
                    {
                        Log.Debug(
                            "LobbyClient.Frame",
                            "Waiting for rest of frame. Need=" +
                            frameLength +
                            ", buffered=" +
                            _receiveBuffer.Count
                        );

                        break;
                    }

                    // Extract one complete APB frame.
                    byte[] frame = new byte[frameLength];

                    _receiveBuffer.CopyTo(
                        0,
                        frame,
                        0,
                        frameLength
                    );

                    _receiveBuffer.RemoveRange(
                        0,
                        frameLength
                    );

                    PacketIn framedPacket =
                        new PacketIn(
                            frame,
                            0,
                            frame.Length
                        );

                    // Decrypt exactly one complete APB frame.
                    PacketIn decrypted =
                        ECrypt.Decrypt(framedPacket);

                    // Log EVERY client -> server opcode here.
                    Log.Info(
                        "CLIENT OPCODE",
                        "Opcode = " +
                        decrypted.Opcode +
                        " / 0x" +
                        decrypted.Opcode.ToString("X") +
                        ", Length = " +
                        frameLength
                    );

                    // Dispatch decrypted packet.
                    Server.HandlePacket(
                        this,
                        decrypted
                    );

                    // There may already be another APB packet
                    // in the TCP receive buffer, so loop again.
                }
            }
        }

        public void Send(PacketOut packet)
        {
            byte[] toSend = ECrypt.Encrypt(packet);

            MemoryStream tcpOut = new MemoryStream();

            tcpOut.WriteByte(
                (byte)((toSend.Length & 0xffff) & 0xff)
            );

            tcpOut.WriteByte(
                (byte)((toSend.Length & 0xffff) >> 8)
            );

            tcpOut.WriteByte(
                (byte)((toSend.Length >> 16) & 0xff)
            );

            tcpOut.WriteByte(
                (byte)(toSend.Length >> 24)
            );

            tcpOut.Write(
                toSend,
                4,
                toSend.Length - 4
            );

            SendTCP(tcpOut.ToArray());

            tcpOut.Dispose();
            toSend = null;
        }
    }
}