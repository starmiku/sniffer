using System;
using SharpPcap;
using SharpPcap.LibPcap;
using SharpPcap.WinPcap;
using SharpPcap.AirPcap;
using PacketDotNet;

namespace 毕业设计
{
    public class Filter
    {
        public static void Main(string[] args)
        {
            //SharpPcap版本
            string ver = SharpPcap.Version.VersionString;
            Console.WriteLine("SharpPcap {0}", ver);

            ///<summary>
            ///功能选择
            /// </summary>


            Console.WriteLine("\n请选择你需要的功能：1.ping检测 2.端口扫描检测 3.分析保存的数据包 4.流量统计 5.监听指定端口: ");

            int func = 0;

            func = int.Parse(Console.ReadLine());

            if (0 == func || 5 < func)
            {
                Console.WriteLine("请输入正确的数字");
            }

            ///<summary>
            ///监听设备选择
            /// </summary>

            //设备列表
            var devices = CaptureDeviceList.Instance;

            //找不到设备
            if (devices.Count < 1)
            {
                Console.WriteLine("无可用设备");
                return;
            }

            Console.WriteLine("\n本机设备：\n");

            int i = 0;
            int devs = 0;

            //输出设备列表
            foreach (var dev in devices)
            {
                /* 设备信息 */
                Console.WriteLine("{0}) {1} {2}", i, dev.Name, dev.Description);
                i++; devs++;
            }

            Console.Write("\n选择需要监听的设备： ");

            i = int.Parse(Console.ReadLine());

            if (i > devs || i < 0)
            {
                Console.WriteLine("\n请输入正确的序号：");
                i = int.Parse(Console.ReadLine());
            }

            //选定的设备
            var device = devices[i] as WinPcapDevice;

            int readTimeoutMilliseconds = 1000;
            string tcpipfilter = "tcp and ip";

            ///<summary>
            ///执行功能
            /// </summary>

            switch (func)
            {

                case 1:
                    //PING检测
                    device.OnPacketArrival +=
                            new PacketArrivalEventHandler(PingDetect);

                    //混杂模式
                    device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);

                    //过滤icmp包
                    string icmpfilter = "icmp";
                    device.Filter = icmpfilter;

                    break;

                case 2:
                    //端口扫描检测
                    device.OnPacketArrival +=
                            new PacketArrivalEventHandler(ScanDetect);

                    //混杂模式
                    device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);

                    //过滤tcp和ip包
                    device.Filter = tcpipfilter;

                    break;

                case 3:
                    //测试模块
                    device.OnPacketArrival +=
                            new PacketArrivalEventHandler(Test);

                    //混杂模式
                    device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);

                    //过滤tcp和ip包
                    device.Filter = tcpipfilter;

                    break;

                case 4:
                    //流量统计
                    device.OnPcapStatistics +=
                           new SharpPcap.WinPcap.StatisticsModeEventHandler(Statistics);

                    //混杂模式
                    device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);

                    //统计模式
                    device.Mode = SharpPcap.WinPcap.CaptureMode.Statistics;

                    break;

                case 5:

                    break;

            }


            Console.WriteLine();
            Console.WriteLine("-- Listening on {0} {1}, hit 'Enter' to stop...",
                device.Name, device.Description);

            // Start the capturing process;
            device.StartCapture();

            // Wait for 'Enter' from the user.
            Console.ReadLine();

            // Stop the capturing process
            device.StopCapture();

            Console.WriteLine("-- Capture stopped.");

            // Print out the device statistics
            Console.WriteLine(device.Statistics.ToString());

            // Close the pcap device
            device.Close();
        }

        ///<summary>
        ///回调函数
        /// </summary>

        //测试模块
        /*
        private static void Test(object sender, CaptureEventArgs e)
        {
            var time = e.Packet.Timeval.Date;
            var len = e.Packet.Data.Length;

            var packet = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            var tcpPacket = (TcpPacket)packet.Extract(typeof(TcpPacket));

            byte a = tcpPacket.Header[4 + 4 + 4 + 1];
            int flag = int.Parse(System.Convert.ToString(a, 2));
            int result= ScanType(flag);

            if(1==result)
                Console.WriteLine("Found SYNSCAN");

            Console.WriteLine(packet.ToString());
            Console.WriteLine(packet.PrintHex());


            
            if (tcpPacket != null)
            {
                var ipPacket = (PacketDotNet.IpPacket)tcpPacket.ParentPacket;
                System.Net.IPAddress srcIp = ipPacket.SourceAddress;
                System.Net.IPAddress dstIp = ipPacket.DestinationAddress;
                int srcPort = tcpPacket.SourcePort;
                int dstPort = tcpPacket.DestinationPort;

                Console.WriteLine("{0}:{1}:{2},{3} Len={4} {5}:{6} -> {7}:{8}",
                    time.Hour, time.Minute, time.Second, time.Millisecond, len,
                    srcIp, srcPort, dstIp, dstPort);
                Console.WriteLine(ipPacket.ToString());
            }
            
        }
        */


        ///<summary>
        ///ping检测
        /// </summary>
        private static void PingDetect(object sender, CaptureEventArgs e)
        {
            var packet = PacketDotNet.Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            var ipPacket = (IpPacket)packet.Extract(typeof(IpPacket));

            //以太网帧报头长度14字节+IP协议报头长度20字节
            //ICMP协议首部前4字节为ICMP报文类型 0x00为响应应答 0x08为响应请求
            if (8 == packet.Bytes[14 + 20])
            {
                System.Net.IPAddress srcIp = ipPacket.SourceAddress;
                System.Net.IPAddress dstIp = ipPacket.DestinationAddress;
                Console.WriteLine("检测到来自{0}向{1}发起的PING请求", srcIp, dstIp);
            }
        }

        ///<summary>
        ///端口扫描检测
        /// </summary>
        private static void ScanDetect(object sender, CaptureEventArgs e)
        {
            var packet = PacketDotNet.Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            var tcpPacket = (TcpPacket)packet.Extract(typeof(TcpPacket));
            
            //端口4位+序号4位+确认号4位+数据偏移1位
            byte a = tcpPacket.Header[4 + 4 + 4 + 1];

            //将标志位的数据转换为二进制
            int flag = int.Parse(System.Convert.ToString(a, 2));
           
            int result = ScanType(flag);
            if (1 == result)
                Console.WriteLine("Found SYN scan");
            else if (2 == result)
                Console.WriteLine("Found FIN scan");
            else if (3 == result)
                Console.WriteLine("Found NULL scan");
        }

        private static int ScanType(int flag)
        {
            int ACK, PSH, RST, SYN, FIN;

            if (flag >= 100000)
                flag -= 100000;

            ACK = flag % 10000;
            flag -= ACK * 10000;

            PSH = flag % 1000;
            flag -= PSH * 1000;

            RST = flag % 100;
            flag -= RST * 100;

            SYN = flag % 10;
            flag -= SYN * 10;

            FIN = flag;

            if (0 == ACK && 1 == ACK)
                return 1;//SYN scan
            else if (2 == FIN)
                return 2;//FIN scan
            else if (0 == ACK && 0 == PSH && 0 == RST && 0 == SYN && 0 == FIN)
                return 3;//NULL scan

            return 0;
        }

        ///<summary>
        ///流量统计
        /// </summary>
        private static void Statistics(object sender, SharpPcap.WinPcap.StatisticsModeEventArgs e)
        {
            ulong oldSec = 0;
            ulong oldUsec = 0;
            // Calculate the delay in microseconds from the last sample.
            // This value is obtained from the timestamp that's associated with the sample.
            ulong delay = (e.Statistics.Timeval.Seconds - oldSec) * 1000000 - oldUsec + e.Statistics.Timeval.MicroSeconds;

            // Get the number of Bits per second
            ulong bps = ((ulong)e.Statistics.RecievedBytes * 8 * 1000000) / delay;

            // Get the number of Packets per second
            ulong pps = ((ulong)e.Statistics.RecievedPackets * 1000000) / delay;

            // Convert the timestamp to readable format
            var ts = e.Statistics.Timeval.Date.ToLongTimeString();

            String netflow = FlowConvert(bps);

            // Print Statistics
            Console.WriteLine("{0}  接收：{1}    数据包：{2}", ts, netflow, pps);

            //store current timestamp
            oldSec = e.Statistics.Timeval.Seconds;
            oldUsec = e.Statistics.Timeval.MicroSeconds;
        }

        private static string FlowConvert(ulong flow)
        {
            string netflow;

            if (flow < 1000)
            {
                netflow = String.Format("{0}b/s", flow);
            }
            else if (flow < 1000000)
            {
                flow /= 1000;
                netflow = String.Format("{0}Kb/s", flow);
            }
            else
            {
                flow /= 1000000;
                netflow = String.Format("{0}Mb/s", flow);
            }
            return netflow;
        }
    }
}