using System;
using SharpPcap;
using SharpPcap.LibPcap;
using SharpPcap.WinPcap;
using SharpPcap.AirPcap;
using PacketDotNet;
using System.Threading;

namespace 毕业设计
{
    //数据包类
    public class Capture
    {
        public Capture(object sender, CaptureEventArgs e)
        {
            this.sender = sender;
            this.capturEventArgs = e;
        }
        public Capture(object sender, StatisticsModeEventArgs e)
        {
            this.sender = sender;
            this.statisticsModeEventArgs = e;
        }
        public object sender { get; set; }
        public CaptureEventArgs capturEventArgs { get; set; }
        public StatisticsModeEventArgs statisticsModeEventArgs { get; set; }
    }

    //入侵参数类
    public class Invade
    {
        public Invade(System.Net.IPAddress srcIp, System.Net.IPAddress dstIp, int srcPort, int dstPort, string result,DateTime dateTime)
        {
            this.srcIp = srcIp;
            this.dstIp = dstIp;
            this.srcPort = srcPort;
            this.dstPort = dstPort;
            this.result = result;
            this.dateTime = dateTime;
        }
        public System.Net.IPAddress srcIp { get; set; }
        public System.Net.IPAddress dstIp { get; set; }
        public int srcPort { get; set; }
        public int dstPort { get; set; }
        public string result { get; set; }
        public DateTime dateTime { get; set; }
    }

    public class Filter
    {


        //入侵统计类
        public class Result
        {
            public static int times = 0;
            public static int port = 0;
            public static DateTime currentTime;
        }


        //主函数
        public static void Main(string[] args)
        {
            //SharpPcap版本
            string ver = SharpPcap.Version.VersionString;
            Console.WriteLine("SharpPcap版本 {0}", ver);

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

            Console.WriteLine();
            Console.WriteLine("-- Listening on {0} {1}, hit 'Enter' to stop...",
                device.Name, device.Description);

            int readTimeoutMilliseconds = 1000;

            device.OnPacketArrival +=
                    new PacketArrivalEventHandler(Scan);

            //混杂模式
            device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);

            string ipfilter = "ip";
            device.Filter = ipfilter;

            /*
            device.OnPcapStatistics +=
                    new SharpPcap.WinPcap.StatisticsModeEventHandler(Statistics);

            //混杂模式
            device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);

            //统计模式
            device.Mode = SharpPcap.WinPcap.CaptureMode.Statistics;
            */

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
        private static void Scan(object sender, CaptureEventArgs e)
        {
            var packet = PacketDotNet.Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            var ipPacket = (IpPacket)packet.Extract(typeof(IpPacket));

            if (null != ipPacket)
            {
                IPProtocolType protocol = ipPacket.Protocol;

                //ICMP
                if ((IPProtocolType)1 == protocol)
                {
                    object parameter = new Capture(sender, e);
                    ThreadPool.QueueUserWorkItem(new WaitCallback(PingDetect), parameter);
                }

                //TCP
                else if ((IPProtocolType)6 == protocol)
                {
                    object parameter = new Capture(sender, e);
                    ThreadPool.QueueUserWorkItem(new WaitCallback(ScanDetect), parameter);
                }

                //UDP
                else if ((IPProtocolType)17 == protocol)
                {
                    Console.WriteLine("UDP");
                }

            }

        }


        ///<summary>
        ///ping检测
        /// </summary>
        private static void PingDetect(object parameter)
        {
            Capture capture = (Capture)parameter;

            var time = capture.capturEventArgs.Packet.Timeval.Date;
            var len = capture.capturEventArgs.Packet.Data.Length;

            var packet = PacketDotNet.Packet.ParsePacket(capture.capturEventArgs.Packet.LinkLayerType, capture.capturEventArgs.Packet.Data);
            var ipPacket = (IpPacket)packet.Extract(typeof(IpPacket));

            //以太网帧报头长度14字节+IP协议报头长度20字节
            //ICMP协议首部前4字节为ICMP报文类型 0x00为响应应答 0x08为响应请求
            if (8 == packet.Bytes[14 + 20])
            {
                System.Net.IPAddress srcIp = ipPacket.SourceAddress;
                System.Net.IPAddress dstIp = ipPacket.DestinationAddress;

                Console.WriteLine("{0} 检测到 {1} 向 {2} 发起的PING请求",
                    time.AddHours(8), srcIp, dstIp);
            }
        }

        ///<summary>
        ///端口扫描检测
        /// </summary>
        private static void ScanDetect(object parameter)
        {
            Capture capture = (Capture)parameter;

            var time = capture.capturEventArgs.Packet.Timeval.Date;
            var len = capture.capturEventArgs.Packet.Data.Length;

            var packet = PacketDotNet.Packet.ParsePacket(capture.capturEventArgs.Packet.LinkLayerType, capture.capturEventArgs.Packet.Data);
            var tcpPacket = (TcpPacket)packet.Extract(typeof(TcpPacket));

            //tcpPacket.SourcePort
            //tcpPacket.DestinationPort

            //端口4位+序号4位+确认号4位+数据偏移1位
            byte a = tcpPacket.Header[4 + 4 + 4 + 1];

            //将标志位的数据转换为二进制
            int flag = int.Parse(System.Convert.ToString(a, 2));

            string result = ScanType(flag);
            if (null != result)
            {
                var ipPacket = (IpPacket)tcpPacket.ParentPacket;

                /*
                System.Net.IPAddress srcIp = ipPacket.SourceAddress;
                System.Net.IPAddress dstIp = ipPacket.DestinationAddress;

                int srcPort = tcpPacket.SourcePort;
                int dstPort = tcpPacket.DestinationPort;

                Console.WriteLine("{0} 检测到 {1}:{2} 对 {3}:{4} 的疑似 {5} 扫描",
                    time.AddHours(8), srcIp, srcPort, dstIp, dstPort, result);
                */

                object invade = new Invade(ipPacket.SourceAddress, ipPacket.DestinationAddress, tcpPacket.SourcePort, tcpPacket.DestinationPort, result, time);

                Thread warning = new Thread(new ParameterizedThreadStart(Warning));
                warning.Start(invade);
            }
        }

        private static string ScanType(int flag)
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
                return "SYN";//SYN scan
            else if (2 == FIN)
                return "FIN";//FIN scan
            else if (0 == ACK && 0 == PSH && 0 == RST && 0 == SYN && 0 == FIN)
                return "NULL";//NULL scan
            else
                return null;
        }

        ///<summary>
        ///警报模块
        /// </summary>
        private static void Warning(object invade)
        {
            Invade message = (Invade)invade;

            Result.times += 1;
            Result.port = message.dstPort;


        }

        ///<summary>
        ///流量统计
        /// </summary>
        private static void Statistics(object sender, StatisticsModeEventArgs e)
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