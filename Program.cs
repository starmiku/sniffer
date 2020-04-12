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
        public Invade(System.Net.IPAddress srcIp, System.Net.IPAddress dstIp, int srcPort, int dstPort, string result, DateTime dateTime)
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
        //入侵统计
        public class Result
        {
            public static int port = 0;
            public static int totalPort = 0;
            public static DateTime firstDetecedTime = DateTime.Now;
            public static DateTime currentDetecedTime = firstDetecedTime;
            public static DateTime warningTime = firstDetecedTime;
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
            Console.WriteLine("-- 开始监听 {0} {1}, 回车键停止监听",
                device.Name, device.Description);

            //超时时间1000毫秒
            int readTimeoutMilliseconds = 1000;

            device.OnPacketArrival +=
                    new PacketArrivalEventHandler(Scan);

            //混杂模式
            device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);

            //仅检测所有ip包
            string ipfilter = "ip";
            device.Filter = ipfilter;

            /*
            //统计流量
            device.OnPcapStatistics +=
                    new SharpPcap.WinPcap.StatisticsModeEventHandler(Statistics);

            //混杂模式
            device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);

            //统计模式
            device.Mode = SharpPcap.WinPcap.CaptureMode.Statistics;
            */

            //开启监听线程
            device.StartCapture();

            //等待用户输入回车
            Console.ReadLine();

            //停止监听线程
            device.StopCapture();

            Console.WriteLine("-- Capture stopped.");

            //Print out the device statistics
            Console.WriteLine(device.Statistics.ToString());

            //关闭监听
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

                //ICMP包处理线程
                if ((IPProtocolType)1 == protocol)
                {
                    object parameter = new Capture(sender, e);
                    ThreadPool.QueueUserWorkItem(new WaitCallback(PingDetect), parameter);
                }

                //TCP包处理线程
                else if ((IPProtocolType)6 == protocol)
                {
                    object parameter = new Capture(sender, e);
                    ThreadPool.QueueUserWorkItem(new WaitCallback(ScanDetect), parameter);
                }

                //UDP包处理暂时闲置
                else if ((IPProtocolType)17 == protocol)
                {
                    //Console.WriteLine("UDP");
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

            var packet = Packet.ParsePacket(capture.capturEventArgs.Packet.LinkLayerType, capture.capturEventArgs.Packet.Data);
            var ipPacket = (IpPacket)packet.Extract(typeof(IpPacket));

            //以太网帧报头长度14字节+IP协议报头长度20字节
            //ICMP协议首部前4字节为ICMP报文类型 0x00为响应应答 0x08为响应请求
            if (8 == packet.Bytes[14 + 20])
            {
                System.Net.IPAddress srcIp = ipPacket.SourceAddress;
                System.Net.IPAddress dstIp = ipPacket.DestinationAddress;

                //网络时间戳为格林乔治时间 北京时间需要加上8个小时
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

            //端口4位+序号4位+确认号4位+数据偏移1位
            byte a = tcpPacket.Header[4 + 4 + 4 + 1];

            //将标志位的数据转换为二进制
            int flag = int.Parse(System.Convert.ToString(a, 2));

            //Console.WriteLine(flag);//测试用

            string result = ScanType(flag);
            if (null != result)
            {
                var ipPacket = (IpPacket)tcpPacket.ParentPacket;

                //源IP、目的IP、源端口、目的端口、检测结果、时间戳（北京时间）
                //闲置部分参数备用
                object invade = new Invade(ipPacket.SourceAddress, ipPacket.DestinationAddress, tcpPacket.SourcePort, tcpPacket.DestinationPort, result, time.AddHours(8));

                //开启警报线程
                Thread warning = new Thread(new ParameterizedThreadStart(ScanWarning));
                warning.Start(invade);
            }
        }

        //扫描类型检测
        private static string ScanType(int flag)
        {
            int URG, ACK, PSH, RST, SYN, FIN;
            URG = ACK = PSH = RST = SYN = FIN = 0;

            //提取flag位的各个值
            if (flag < 1000000 && flag >= 100000)
            {
                URG = flag / 100000;
                flag -= URG * 100000;
            }
            if (flag < 100000 && flag >= 10000)
            {
                ACK = flag / 10000;
                flag -= ACK * 10000;
            }

            if (flag < 10000 && flag >= 1000)
            {
                PSH = flag / 1000;
                flag -= PSH * 1000;
            }

            if (flag < 1000 && flag >= 100)
            {
                RST = flag / 100;
                flag -= RST * 100;
            }

            if (flag < 100 & flag >= 10)
            {
                SYN = flag / 10;
                flag -= SYN * 10;
            }

            FIN = flag;

            //类型判断
            if (0 == ACK && 1 == SYN)
                return "SYN/TCP";
            else if (1 == ACK && 0 == PSH && 0 == RST && 0 == SYN && 0 == FIN)
                return "ACK";
            else if (1 == FIN && 0 == URG)
                return "FIN";
            else if (0 == ACK && 0 == PSH && 0 == RST && 0 == SYN && 0 == FIN)
                return "NULL";
            else if (1 == URG && 1 == PSH && 1 == FIN)
                return "Xmas";
            else
                return null;
        }

        ///<summary>
        ///警报模块
        /// </summary>

        //端口扫描警报
        private static void ScanWarning(object invade)
        {
            Invade message = (Invade)invade;

            //记录首次疑似的扫描
            if (0 == Result.totalPort)
            {
                Result.firstDetecedTime = message.dateTime;
                Result.port = message.dstPort;
                Result.totalPort += 1;
            }
            //记录随后到达的扫描
            else
            {
                Result.currentDetecedTime = message.dateTime;

                if (Result.port != message.dstPort)
                {
                    Result.totalPort += 1;
                }
            }

            //使用北京时间计算
            TimeSpan timeSpan = Result.currentDetecedTime - Result.firstDetecedTime;

            //Console.WriteLine(Result.firstDetecedTime);//测试
            
            //通过计算5秒内被访问的端口数量判断是否为扫描
            if (timeSpan.TotalSeconds < 10 && Result.totalPort >= 20 && (DateTime.Now-Result.warningTime).TotalSeconds>1)
            {
                Result.warningTime = DateTime.Now;

                Console.WriteLine("{0} 检测到{1}扫描", Result.warningTime, message.result);

                //发出警报后重置计数器
                Result.totalPort = 0;
                Result.firstDetecedTime = Result.currentDetecedTime = DateTime.Now;
            }
            else if (timeSpan.TotalSeconds >= 10)
            {
                //如果达不到触发条件则重置计数器
                Result.totalPort = 0;
                Result.firstDetecedTime = Result.currentDetecedTime = DateTime.Now;
            }

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