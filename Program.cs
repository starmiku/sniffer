using System;
using SharpPcap;
using SharpPcap.AirPcap;
using SharpPcap.LibPcap;
using SharpPcap.WinPcap;
using PacketDotNet;

namespace 毕业设计
{
    public class Filter
    {
        System.Collections.ArrayList srcIP = new System.Collections.ArrayList(); //ip source
        System.Collections.ArrayList destIP = new System.Collections.ArrayList();//ip destination
        public static void Main(string[] args)
        {

            

            //SharpPcap版本
            string ver = SharpPcap.Version.VersionString;
            Console.WriteLine("SharpPcap {0}", ver);

            ///<summary>
            ///功能选择
            /// </summary>


            Console.WriteLine("\n请选择你需要的功能：1.ping检测 2.监听流量 3.分析保存的数据包 4.流量统计 5.监听指定端口: ");

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
            int devs=0;

            //输出设备列表
            foreach (var dev in devices)
            {
                /* 设备信息 */
                Console.WriteLine("{0}) {1} {2}", i, dev.Name, dev.Description);
                i++; devs++;
            }

            Console.Write("\n选择需要监听的设备： ");

            i = int.Parse(Console.ReadLine());

            if(i>devs||i<0)
            {
                Console.WriteLine("\n请输入正确的序号：");
                i = int.Parse(Console.ReadLine());
            }

            //选定的设备
            var device = devices[i] as WinPcapDevice;

            int readTimeoutMilliseconds = 1000;

            ///<summary>
            ///执行功能
            /// </summary>

            switch (func)
            {             
                
                case 1:
                    //PING检测
                    device.OnPacketArrival +=
                            new PacketArrivalEventHandler(PingTest);

                    //混杂模式
                    device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);

                    //过滤icmp包
                    string icmpfilter = "icmp";
                    device.Filter = icmpfilter;

                    break;

                
                
                case 2:
                    //流量监控
                    device.OnPacketArrival +=
                            new PacketArrivalEventHandler(PacketSourceAndDestination);

                    //混杂模式
                    device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);

                    //过滤tcp和ip包
                    string tcpipfilter = "tcp and ip";
                    device.Filter = tcpipfilter;

                    break;

                case 3:
                    

                    device.OnPacketArrival +=
                            new PacketArrivalEventHandler(PacketDump);
                    break;

                case 4:
                    //流量统计
                    device.OnPcapStatistics +=
                           new SharpPcap.WinPcap.StatisticsModeEventHandler(Statistics);

                    //混杂模式
                    device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);

                    //统计模式
                    device.Mode = CaptureMode.Statistics;

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

        //流量监控
        private static void PacketSourceAndDestination(object sender, CaptureEventArgs e)
        {
            var time = e.Packet.Timeval.Date;
            var len = e.Packet.Data.Length;

            var packet = PacketDotNet.Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);

            Console.WriteLine(packet.ToString());
            
            /*
            var tcpPacket = (TcpPacket)packet.Extract(typeof(TcpPacket));
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
            */
        }

        //PING检测
        private static void PingTest(object sender, CaptureEventArgs e)
        {
            var time = e.Packet.Timeval.Date;
            var len = e.Packet.Data.Length;

            var packet = PacketDotNet.Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            var ipPacket = (IpPacket)packet.Extract(typeof(IpPacket));

            //以太网帧报头长度14字节+IP协议报头长度20字节
            //ICMP协议首部前4字节为ICMP报文类型 0x00为响应应答 0x08为响应请求
            if (8 == packet.Bytes[14 + 20])
            {
                System.Net.IPAddress srcIp = ipPacket.SourceAddress;
                System.Net.IPAddress dstIp = ipPacket.DestinationAddress;
                Console.WriteLine("检测到来自{0}向{1}发起的PING请求",srcIp,dstIp);
            }
        }

        private static void PacketDump(object sender, CaptureEventArgs e)
        {
            
        }

        //流量统计
        static ulong oldSec = 0;
        static ulong oldUsec = 0;
        private static void Statistics(object sender, SharpPcap.WinPcap.StatisticsModeEventArgs e)
        {
            // Calculate the delay in microseconds from the last sample.
            // This value is obtained from the timestamp that's associated with the sample.
            ulong delay = (e.Statistics.Timeval.Seconds - oldSec) * 1000000 - oldUsec + e.Statistics.Timeval.MicroSeconds;

            // Get the number of Bits per second
            ulong bps = ((ulong)e.Statistics.RecievedBytes * 8 * 1000000 ) / delay;

            // Get the number of Packets per second
            ulong pps = ((ulong)e.Statistics.RecievedPackets * 1000000) / delay;

            // Convert the timestamp to readable format
            var ts = e.Statistics.Timeval.Date.ToLongTimeString();

            String netflow = Convert(bps);

            // Print Statistics
            Console.WriteLine("{0}  接收：{1}    数据包：{2}", ts, netflow, pps);

            //store current timestamp
            oldSec = e.Statistics.Timeval.Seconds;
            oldUsec = e.Statistics.Timeval.MicroSeconds;
        }

        //流量转换
        private static string Convert(ulong flow)
        {
            string netflow;

            if(flow<1000)
            {
                netflow = String.Format("{0}b/s", flow);
            }
            else if(flow < 1000000)
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