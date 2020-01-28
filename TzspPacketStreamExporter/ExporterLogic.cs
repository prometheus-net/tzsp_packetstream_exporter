using Axinom.Toolkit;
using Prometheus;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace TzspPacketStreamExporter
{
    sealed class ExporterLogic
    {
        public string ListenInterface { get; set; } = "";
        public List<int> ListenPorts { get; set; } = new List<int>();
        public int PublishPort { get; set; } = Constants.DefaultPublishPort;

        private MetricServer? _metricServer;

        private string MakeTsharkFilterString() => $"(dst port {string.Join(" or dst port ", ListenPorts)}) and udp";

        public async Task RunAsync(CancellationToken cancel)
        {
            await VerifyTshark(cancel);

            try
            {
                _log.Info($"Will publish analysis results on http://server:{PublishPort}/metrics");

                _metricServer = new MetricServer(PublishPort);
                _metricServer.Start();
            }
            catch (Exception ex)
            {
                _log.Error($"Could not publish metrics on port {PublishPort}: {ex.Message}. Verify that the current user has the required permissions to accept connections on this port.");
                throw;
            }

            _log.Info("Starting TZSP packet stream processing.");

            // TShark will exit after N packets have been processed, to enable us to cleanup temp files.
            // We just run it in a loop until cancelled or until TShark fails.
            while (!cancel.IsCancellationRequested)
            {
                // Sometimes (not always) TShark cleans up on its own.
                // Better safe than sorry, though!
                DeleteTemporaryFiles();

                // We cancel processing if TShark exits or we get our own higher level CT signaled.
                using var cancelProcessingCts = CancellationTokenSource.CreateLinkedTokenSource(cancel);
                var stdoutFinished = new SemaphoreSlim(0, 1);
                var stderrFinished = new SemaphoreSlim(0, 1);

                void ConsumeStandardOutput(Stream stdout)
                {
                    // Text mode output, each line consisting of:
                    // 1. Hex string of packet bytes (starting with either outer UDP header or inner TZSP header)
                    // 2. A space character.
                    // 3. Type of the data ("eth:ethertype:ip:data" - UDP header, "eth:ethertype:ip:udp:data" - TZSP header)
                    // 4. A space character.
                    // 5. The destination UDP port of the TZSP protocol ("udp.dstport") but ONLY if type of data is TZSP header.
                    //    If type of data is UDP header, we need to parse the port ourselves.

                    try
                    {
                        var reader = new StreamReader(stdout, Encoding.UTF8, leaveOpen: true);

                        while (true)
                        {
                            var line = reader.ReadLineAsync()
                                .WithAbandonment(cancelProcessingCts.Token)
                                .WaitAndUnwrapExceptions();

                            if (line == null)
                                break; // End of stream.

                            string packetBytesHex;
                            string packetType;

                            var parts = line.Split(' ');
                            if (parts.Length != 3)
                                throw new NotSupportedException("Output line did not have expected number of components.");

                            // On some systems there are colons. On others there are not!
                            // Language/version differences? Whatever, get rid of them.
                            packetBytesHex = parts[0].Replace(":", "");
                            packetType = parts[1];

                            var packetBytes = Helpers.Convert.HexStringToByteArray(packetBytesHex);

                            try
                            {
                                if (packetType == "eth:ethertype:ip:data")
                                {
                                    ProcessTzspPacketWithUdpHeader(packetBytes);
                                }
                                else if (packetType == "eth:ethertype:ip:udp:data")
                                {
                                    var listenPort = ushort.Parse(parts[2]);
                                    ProcessTzspPacket(packetBytes, listenPort);
                                }
                                else
                                {
                                    throw new NotSupportedException("Unexpected packet type: " + packetType);
                                }
                            }
                            catch (Exception ex)
                            {
                                _log.Error("Ignoring unsupported packet: " + Helpers.Debug.GetAllExceptionMessages(ex));
                            }
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        // It's OK, we were cancelled because processing is finished.
                    }
                    catch (Exception ex)
                    {
                        // If we get here, something is fatally wrong with parsing logic or TShark output.
                        _log.Error(Helpers.Debug.GetAllExceptionMessages(ex));

                        // This should not happen, so stop everything. Gracefully, so we flush logs.
                        Environment.ExitCode = -1;
                        Program.MasterCancellation.Cancel();
                    }
                    finally
                    {
                        stdoutFinished.Release();
                    }
                };

                void ConsumeStandardError(Stream stderr)
                {
                    // Only errors should show up here. We will simply log them for now
                    // - only if tshark exits do we consider it a fatal error.

                    try
                    {
                        var reader = new StreamReader(stderr, Encoding.UTF8, leaveOpen: true);

                        while (true)
                        {
                            var line = reader.ReadLineAsync()
                                .WithAbandonment(cancelProcessingCts.Token)
                                .WaitAndUnwrapExceptions();

                            if (line == null)
                                break; // End of stream.

                            _log.Error(line);
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        // It's OK, we were cancelled because processing is finished.
                    }
                    finally
                    {
                        stderrFinished.Release();
                    }
                };

                var tsharkCommand = new ExternalTool
                {
                    ExecutablePath = Constants.TsharkExecutableName,
                    ResultHeuristics = ExternalToolResultHeuristics.Linux,
                    Arguments = @$"-i ""{ListenInterface}"" -f ""{MakeTsharkFilterString()}"" -p -T fields -e data.data -e frame.protocols -e udp.dstport -Eseparator=/s -Q -c {Constants.PacketsPerIteration}",
                    StandardOutputConsumer = ConsumeStandardOutput,
                    StandardErrorConsumer = ConsumeStandardError
                };

                var tshark = tsharkCommand.Start();
                var result = await tshark.GetResultAsync(cancel);
                cancelProcessingCts.Cancel();

                // Wait for output processing threads to finish, so error messages are printed to logs before we exit.
                _log.Debug("TShark finished iteration. Waiting for data processing threads to clean up and flush logs.");
                await stderrFinished.WaitAsync();
                await stdoutFinished.WaitAsync();

                if (!cancel.IsCancellationRequested && !result.Succeeded)
                {
                    _log.Error("TShark exited with an error result. Review logs above to understand the details of the failure.");
                    Environment.ExitCode = -1;
                    break;
                }
            }

            await _metricServer.StopAsync();
        }

        private static async Task VerifyTshark(CancellationToken cancel)
        {
            _log.Debug("Verifying that TShark is installed.");

            ExternalToolResult tsharkCheckResult;

            try
            {
                tsharkCheckResult = await ExternalTool.ExecuteAsync(Constants.TsharkExecutableName, "--version", cancel);
            }
            catch (Exception ex)
            {
                throw new EnvironmentException("This app requires TShark to be installed. Attempt to execute TShark failed: " + ex.Message, ex);
            }

            if (!tsharkCheckResult.StandardOutput.StartsWith("TShark (Wireshark)"))
                throw new NotSupportedException("Unrecognized TShark version/build.");
        }

        private static void DeleteTemporaryFiles()
        {
            var files = Directory.GetFiles(Path.GetTempPath(), "wireshark_*.pcapng");

            foreach (var file in files)
            {
                try
                {
                    File.Delete(file);
                    _log.Debug($"Deleted temporary file: {file}");
                }
                catch
                {
                    // It's fine - maybe it is in use by a parallel TShark instance!
                }
            }
        }

        private static readonly IPNetwork MulticastNetwork = IPNetwork.Parse("224.0.0.0/4");
        private static readonly IPNetwork[] PrivateUseNetworks = new[]
        {
            IPNetwork.Parse("10.0.0.0/8"),
            IPNetwork.Parse("172.16.0.0/12"),
            IPNetwork.Parse("192.168.0.0/16")
        };

        private static string DetermineIPv4AddressType(IPAddress address)
        {
            if (MulticastNetwork.Contains(address))
                return "multicast";
            else if (PrivateUseNetworks.Any(network => network.Contains(address)))
                return "private";
            else
                return "public";
        }

        /*
        
            Some example packets for manual testing and experimentation, if needed.
        
        // Starts with UDP header because it is incomplete (did not fit in 1500 Ethernet frame).
        // Identified by "frame.protocols": "eth:ethertype:ip:data"
        // Given that UDP header is not parsed due to incomplete packet, we do not get "udp.dstport" value for this type of packet.
        // Inside is UDP multicast packet.
        const string IncompleteUdpPacketHex = "1535153505f50000010000010101005e28500100155d04eb0e0800450005da457340001f1198cbc0a87802ef2850019595138905c61d71000001e55e27e764000e2d69323334350000000030313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334";

        // Seems to start with TZSP header because it is complete.
        // Identified by "frame.protocols": "eth:ethertype:ip:udp:data"
        // We get "udp.dstport" value for this because TShark can parse the full packet.
        // Inside is TCP packet.
        const string CompleteTcpPacketHex = "010000010100155d04eb0a00155d04eb0e080045000274655e40003f0661d0c0a87802c0a87902eba01451cf757cdc16f4d46680100480223300000101080acae8ac2922f45e949d2efd0c894fdee47ecc96c750f49ad526016ad8ff12a3a218d5d86dd9445876725583fba461df222d75e97e6983538f84bd6783d00a25e8dffd55b941ad2fb302b2aea6138dc84102b1bf6b3412fab8cf623b9f6c61884c5edd05a08b34538de70234fa8ffc3b92aefafde20cf89bdc5ad67bc637031296e117366c4c89f9338b2d2d1b2a69add863aaba70a2554cfc2cc7c363cbd5f9aced2f1839b9116c443f995f69020c4166b7fbd6595122567de919e0b4eeda60db097814c28a8007c91a66321c7373822a6e5883bf7ad93c64f21d18e1f779bc00f1d1c37b51ca446b307688a3e90acd58635117dd2a54411d715afe68d3ba68c48b2b40ddf5844826fbd0c9e4db973c3ee8541b12a85d2f19b72d818ae8e94e73158e500a1399300e69faf244912f8279839e8b2bfbbb44b2e8c53cd0ae8a44c31994ce2c2dfe3a97f82cdb895b5e02defc8e09f7494da93112e502c16f468488da52b40851ee9f491b7ad376d8d555d4635ecbacac74debe59e07fc926045100560608a7f4a7f10f22c486fa99dbcffd399aa9e50f87a4686723318d27838e7e8996257d3e168d60da135a74ee297127c41a0dd3a2b13b09d46d97fcf0257a79bb9ff6f9b683599096b40484dd75aca190b974326ab03b3e1dd23a0df7b486b3547cac0a00069a96ba9f1b9714c739a480add6ea5d12287ae46387dc170d8f6b8a3b758a411020fbaf3b93c302cc6882793e6cd750955135f8d9110fe6a07b70dbf0fa1d001b18af56ab735977dbdbf11948c86add199fd5f2b0e4d9505f492b504448505f6100b5";

        */

        private static void ProcessTzspPacketWithUdpHeader(byte[] packet)
        {
            using var stream = new MemoryStream(packet);
            using var reader = new MultiEndianBinaryReader(stream, ByteOrder.BigEndian);

            // source port (2)
            // destination port (2)
            // length (2)
            // checksum (2)

            stream.Position = 2;
            var listenPort = reader.ReadUInt16();

            ProcessTzspPacket(packet.Skip(8).ToArray(), listenPort);
        }

        private static void ProcessTzspPacket(byte[] packet, ushort listenPort)
        {
            // TZSP header
            // version (1) == 1
            // type (1) == 0
            // protocol (2) == 1
            // tags (N)
            //   type (1) == anything, but 1 means no more tags (not even the rest of the fields of this tag)
            //   length (1)
            //   data (N)
            // packetdata (...)
            //      Ethernet MAC header (14)
            //      IP header
            //        +0 version (0.5)
            //        +0.5 header length / 4 (0.5)
            //        +2 total length (2)
            //        +9 protocol (1)
            //        +12 source address (4)
            //        +16 destination address (4)
            //        ...options...
            //      inner packet

            using var stream = new MemoryStream(packet);
            using var reader = new MultiEndianBinaryReader(stream, ByteOrder.BigEndian);

            var tzspVersion = reader.ReadByte();
            if (tzspVersion != 1)
                throw new NotSupportedException("TZSP version != 1");

            var tzspType = reader.ReadByte();
            if (tzspType != 0)
                throw new NotSupportedException("TZSP type != 0");

            var tzspProtocol = reader.ReadUInt16();
            if (tzspProtocol != 1)
                throw new NotSupportedException("TZSP protocol != 1");

            while (true)
            {
                var tagType = reader.ReadByte();

                if (tagType == 1)
                    break;

                var tagLength = reader.ReadByte();
                stream.Position += tagLength; // Skip the tag.
            }

            stream.Position += 14; // Skip MAC header

            var firstByte = reader.ReadByte();

            var ipVersion = (firstByte & 0xF0) >> 4;

            if (ipVersion != 4)
                return; // We only support IPv4

            var headerLength = (firstByte & 0x0F) * 4;
            var positionAfterIpHeader = stream.Position - 1 + headerLength;

            stream.Position += 1; // Skip to total length.

            // Captured packet, ignoring any TZSP layers.
            var totalPacketLengthIncludingIpHeader = reader.ReadUInt16();

            stream.Position += 5; // Skip to protocol.

            var protocol = reader.ReadByte();

            stream.Position += 2; // Skip to source address.

            var sourceAddress = new IPAddress(reader.ReadBytesAndVerify(4));
            var destinationAddress = new IPAddress(reader.ReadBytesAndVerify(4));

            var sourceAddressString = sourceAddress.ToString();
            var destinationAddressString = destinationAddress.ToString();

            string sourceAddressType = DetermineIPv4AddressType(sourceAddress);
            string destinationAddressType = DetermineIPv4AddressType(destinationAddress);

            stream.Position = positionAfterIpHeader;

            int? sourcePort = null;
            int? destinationPort = null;

            if (protocol == 17 || protocol == 6)
            {
                // If UDP or TCP, source and destination port are next fields.
                sourcePort = reader.ReadUInt16();
                destinationPort = reader.ReadUInt16();
            }
            else
            {
                // unknown protocol
            }

            string protocolName = "unknown";

            if (Enum.IsDefined(typeof(ProtocolType), (int)protocol))
                protocolName = ((ProtocolType)protocol).ToString().ToLowerInvariant();

            BytesBase.WithLabels(sourceAddressString, sourceAddressType, destinationAddressString, destinationAddressType, protocolName, listenPort.ToString()).Inc(totalPacketLengthIncludingIpHeader);
            PacketsBase.WithLabels(sourceAddressString, sourceAddressType, destinationAddressString, destinationAddressType, protocolName, listenPort.ToString()).Inc();
        }

        private static readonly Counter BytesBase = Metrics.CreateCounter("tzsp_observed_bytes_total", "Total number of bytes that have been observed in the captured packet stream.", new CounterConfiguration
        {
            LabelNames = new[]
            {
                "from",
                "from_type",
                "to",
                "to_type",
                "protocol",
                "listen_port"
            }
        });

        private static readonly Counter PacketsBase = Metrics.CreateCounter("tzsp_observed_packets_total", "Total number of packets that have been observed in the captured packet stream.", new CounterConfiguration
        {
            LabelNames = new[]
            {
                "from",
                "from_type",
                "to",
                "to_type",
                "protocol",
                "listen_port"
            }
        });

        private static readonly LogSource _log = Log.Default;
    }
}
