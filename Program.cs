using System;
using System.Net;
using System.Net.Mail;
using System.Threading;
using System.Text;
using SharpPcap;
using SharpPcap.LibPcap;
using SharpPcap.WinPcap;
using SharpPcap.AirPcap;
using PacketDotNet;


namespace 毕业设计
{
    //数据包类
    public class Capture
    {
        public Capture(object sender, CaptureEventArgs e)
        {
            this.Sender = sender;
            this.CapturEventArgs = e;
        }
        public Capture(object sender, StatisticsModeEventArgs e)
        {
            this.Sender = sender;
            this.StatisticsModeEventArgs = e;
        }
        public object Sender { get; set; }
        public CaptureEventArgs CapturEventArgs { get; set; }
        public StatisticsModeEventArgs StatisticsModeEventArgs { get; set; }
    }

    //入侵参数类
    public class Invade
    {
        public Invade(System.Net.IPAddress srcIp, System.Net.IPAddress dstIp, int srcPort, int dstPort, string result, DateTime dateTime)
        {
            this.SrcIp = srcIp;
            this.DstIp = dstIp;
            this.SrcPort = srcPort;
            this.DstPort = dstPort;
            this.Result = result;
            this.DateTime = dateTime;
        }
        public System.Net.IPAddress SrcIp { get; set; }
        public System.Net.IPAddress DstIp { get; set; }
        public int SrcPort { get; set; }
        public int DstPort { get; set; }
        public string Result { get; set; }
        public DateTime DateTime { get; set; }
    }

    public class Filter
    {
        static object locker = new object();

        //入侵统计
        public static class Result
        {
            public static int port = 0;
            public static int totalPort = 0;
            public static DateTime firstDetecedTime = DateTime.Now;
            public static DateTime currentDetecedTime = firstDetecedTime;
            public static DateTime warningTime = firstDetecedTime;
        }

        //邮件数据统计
        public static class Email
        {
            public static System.Net.IPAddress invadeIP;
            public static int invadeTimes = 0;
            public static int whetherEmailSent = 0;
            public static DateTime sentTime;
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
        ///测试函数
        /// </summary>
        private static void Test(object sender, CaptureEventArgs e)
        {
            if (0 != e.Packet.LinkLayerType)
            {
                var packet = PacketDotNet.Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
                var ipPacket = (IpPacket)packet.Extract(typeof(IpPacket));

                if (null != ipPacket)
                {
                    //Console.WriteLine(ipPacket);

                    IPProtocolType protocol = ipPacket.Protocol;

                    //ICMP包处理线程
                    if ((IPProtocolType)1 == protocol)
                    {
                        var icmpv4Packet= (ICMPv4Packet)packet.Extract(typeof(ICMPv4Packet));
                        Console.WriteLine(icmpv4Packet);
                    }

                    //TCP包处理线程
                    else if ((IPProtocolType)6 == protocol)
                    {
                        var tcpPacket = (TcpPacket)packet.Extract(typeof(TcpPacket));
                        Console.WriteLine(tcpPacket);
                    }

                }
            }
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

            }

        }


        ///<summary>
        ///ping检测
        /// </summary>
        private static void PingDetect(object parameter)
        {
            Capture capture = (Capture)parameter;

            var time = capture.CapturEventArgs.Packet.Timeval.Date;
            var packet = Packet.ParsePacket(capture.CapturEventArgs.Packet.LinkLayerType, capture.CapturEventArgs.Packet.Data);
            var ipPacket = (IpPacket)packet.Extract(typeof(IpPacket));

            //以太网帧报头长度14字节+IP协议报头长度20字节
            //ICMP协议首部前4字节为ICMP报文类型 0x00为响应应答 0x08为响应请求
            if (8 == packet.Bytes[14 + 20])
            {
                System.Net.IPAddress srcIp = ipPacket.SourceAddress;
                System.Net.IPAddress dstIp = ipPacket.DestinationAddress;

                //网络时间戳为格林威治时间 北京时间需要加上8个小时
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

            var time = capture.CapturEventArgs.Packet.Timeval.Date;
            var packet = PacketDotNet.Packet.ParsePacket(capture.CapturEventArgs.Packet.LinkLayerType, capture.CapturEventArgs.Packet.Data);
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
            URG = ACK = PSH = RST = SYN = 0;

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
                Result.firstDetecedTime = message.DateTime;
                Result.port = message.DstPort;
                Result.totalPort++;
            }
            //记录随后到达的扫描
            else
            {
                Result.currentDetecedTime = message.DateTime;

                if (Result.port != message.DstPort)
                {
                    Result.totalPort += 1;
                }
            }

            //使用北京时间计算
            TimeSpan timeSpan = Result.currentDetecedTime - Result.firstDetecedTime;

            //Console.WriteLine(Result.firstDetecedTime);//测试

            //通过计算5秒内被访问的端口数量判断是否为扫描
            if (timeSpan.TotalSeconds < 10 && Result.totalPort >= 20 && (DateTime.Now - Result.warningTime).TotalSeconds > 1)
            {
                Result.warningTime = DateTime.Now;

                if (message.DstPort != 80 && message.DstPort != 3306)
                {
                    Console.WriteLine("{0} 检测到来自 {1} 的 {2} 疑似扫描", Result.warningTime, message.SrcIp, message.Result);
                    Email.invadeIP = message.SrcIp;
                }

                lock (locker)
                {
                    if (Email.whetherEmailSent == 0)
                    {
                        SendingEmail(message.SrcIp, message.Result);
                        Email.whetherEmailSent = 1;
                        Email.sentTime = DateTime.Now;
                    }
                }

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

            //重置邮件发送
            if (60 <= (DateTime.Now - Email.sentTime).TotalSeconds && 1 == Email.whetherEmailSent)
                Email.whetherEmailSent = 0;

        }


        ///<summary>
        ///发送邮件
        /// </summary>

        private static void SendingEmail(System.Net.IPAddress srcIP, string type)
        {
            string smtpService = "smtp.qq.com";
            string sendEmail = "xxxxxxxxx@qq.com";
            string sendpwd = "xxxxxxxxxxx";
            string sendText = "检测到来自 " + srcIP + " 的 " + type + "扫描";

            //确定smtp服务器地址 实例化一个Smtp客户端
            SmtpClient smtpclient = new SmtpClient
            {
                Host = smtpService
            };
            //smtpClient.Port = "";//qq邮箱可以不用端口

            //确定发件地址与收件地址
            MailAddress sendAddress = new MailAddress(sendEmail);
            MailAddress receiveAddress = new MailAddress("xxxxxxxxxx@qq.com");

            //构造一个Email的Message对象 内容信息
            MailMessage mailMessage = new MailMessage(sendAddress, receiveAddress)
            {
                Subject = "入侵警告" + DateTime.Now,
                SubjectEncoding = Encoding.UTF8,
                Body = sendText,
                BodyEncoding = Encoding.UTF8
            };

            //邮件发送方式  通过网络发送到smtp服务器
            smtpclient.DeliveryMethod = SmtpDeliveryMethod.Network;

            //如果服务器支持安全连接，则将安全连接设为true
            smtpclient.EnableSsl = true;
            try
            {
                //是否使用默认凭据，若为false，则使用自定义的证书
                smtpclient.UseDefaultCredentials = false;

                //指定邮箱账号和密码
                NetworkCredential networkCredential = new NetworkCredential(sendEmail, sendpwd);
                smtpclient.Credentials = networkCredential;

                //发送邮件
                smtpclient.Send(mailMessage);
                Console.WriteLine("发送邮件成功");

            }
            catch (System.Net.Mail.SmtpException ex)
            {
                Console.WriteLine(ex.Message, "发送邮件出错");
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