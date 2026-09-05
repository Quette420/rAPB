using FrameWork.Logger;
using System;
using System.Net.Sockets;
using System.Collections.Generic;

namespace WorldServer.Districts
{
    class RegisterDistrict
    {
        public static void Register(District district, TcpClient tcpClient, int type, byte ID, LanguageCodes language, string ip, string port, string token)
        {
            switch ((DistrictTypes)type)
            {
                case DistrictTypes.FINANCIAL:
                    district = new FinancialDistrict(ID, language);
                    break;
                case DistrictTypes.SOCIAL:
                    district = new SocialDistrict(ID);
                    break;
                case DistrictTypes.TUTORIAL:
                    district = new TutorialDistrict(ID);
                    break;
                case DistrictTypes.WATERFRONT:
                    district = new WaterFrontDistrict(ID, language);
                    break;
                default:
                    Log.Error(
                        "RegisterDistrict",
                        "Unsupported district type " + type + "."
                    );
                    tcpClient.Client.Send(new byte[] { 0x30, 0x30 });
                    tcpClient.Close();
                    return;
            }

            district.tcp = tcpClient;

            Log.Info(
                "RegisterDistrict",
                district.ToString() + " tries to register."
            );

            if (ID != 0)
            {
                district.Id = ID;
                district.IP = ip;
                district.Port = Convert.ToUInt16(port);

                lock (Program.districtsListener.Districts)
                {
                    uint code = (uint)(district.Type << 24);
                    code += district.Id;

                    foreach (
                        KeyValuePair<uint, District> dist
                        in Program.districtsListener.Districts
                    )
                    {
                        if (
                            dist.Value.IP == ip &&
                            Program.districtsListener.Districts.ContainsKey(code)
                        )
                        {
                            district.tcp.Client.Send(
                                new byte[] { 0x30, 0x31 }
                            );

                            Program.districtsListener.Districts.Remove(code);
                            break;
                        }
                        else if (
                            dist.Value.IP != ip &&
                            Program.districtsListener.Districts.ContainsKey(code)
                        )
                        {
                            Log.Error(
                                "RegisterDistrict",
                                "Fail try of district registration that already exists!"
                            );

                            district.tcp.Client.Send(
                                new byte[] { 0x30, 0x32 }
                            );

                            return;
                        }
                    }

                    Program.districtsListener.Districts.Add(
                        code,
                        district
                    );

                    Program.districtsListener.DistrictsTcp.Add(
                        district.tcp,
                        code
                    );
                }

                Log.Succes(
                    "RegisterDistrict",
                    district + " was registered! (" +
                    ip + ":" + port + ")"
                );

                district.tcp.Client.Send(
                    new byte[] { 0x30, 0x33 }
                );
            }
            else
            {
                district.tcp.Client.Send(
                    new byte[] { 0x30, 0x34 }
                );

                district.tcp.Client.Disconnect(true);
                return;
            }
        }
    }
}
