using Axinom.Toolkit;
using Mono.Options;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;

namespace TzspPacketStreamExporter
{
    sealed class Program
    {
        // We signal this to shut down the service.
        public static CancellationTokenSource MasterCancellation = new CancellationTokenSource();

        private readonly LogSource _log = Log.Default;
        private readonly FilteringLogListener _filteringLogListener;

        private readonly ExporterLogic _logic = new ExporterLogic();

        private void Run(string[] args)
        {
            try
            {
                if (!ParseArguments(args))
                {
                    Environment.ExitCode = -1;
                    return;
                }

                _log.Info(GetVersionString());

                // Control+C will gracefully shut us down.
                Console.CancelKeyPress += (s, e) =>
                {
                    _log.Info("Canceling execution due to received signal.");
                    e.Cancel = true;
                    MasterCancellation.Cancel();
                };

                _logic.RunAsync(MasterCancellation.Token).WaitAndUnwrapExceptions();

                _log.Info("Application logic execution has completed.");
            }
            catch (OperationCanceledException)
            {
                if (MasterCancellation.IsCancellationRequested)
                {
                    // We really were cancelled. That's fine.
                }
                else
                {
                    _log.Error("Unexpected cancellation/timeout halted execution.");
                    Environment.ExitCode = -1;
                }
            }
            catch (Exception ex)
            {
                _log.Error(Helpers.Debug.GetAllExceptionMessages(ex));

                Environment.ExitCode = -1;
            }
        }

        private bool ParseArguments(string[] args)
        {
            var showHelp = false;
            var verbose = false;
            var debugger = false;

            var options = new OptionSet
            {
                GetVersionString(),
                "Usage: --interface eth0 --listen-port 19345 --listen-port 19346",
                "",
                "General",
                { "h|?|help", "Displays usage instructions.", val => showHelp = val != null },
                { "interface=", "Name or number of the network interface (e.g. 1 or eth5 or \"Ethernet 3\"). Must match an entry in the 'tshark -D' list.", val => _logic.ListenInterface = val?.Trim('"') ?? "" },
                { "listen-port|port=", "UDP port to listen on for an incoming TZSP packet stream. Use multiple times to listen on multiple ports.", (ushort val) => _logic.ListenPorts.Add(val) },
                { "publish-port|publish=", $"TCP port to publish Prometheus metrics on. Defaults to {_logic.PublishPort}.", (ushort val) => _logic.PublishPort = val },

                "",
                "Diagnostics",
                { "verbose", "Displays extensive diagnostic information.", val => verbose = val != null },
                { "debugger", "Requests a debugger to be attached before execution starts.", val => debugger = val != null, true },
            };

            List<string> remainingOptions;

            try
            {
                remainingOptions = options.Parse(args);

                if (showHelp || args.Length == 0)
                {
                    options.WriteOptionDescriptions(Console.Out);
                    return false;
                }

                if (verbose)
                    _filteringLogListener.MinimumSeverity = LogEntrySeverity.Debug;

                if (_logic.ListenInterface.Contains('"'))
                    throw new OptionException("The network interface name must not contain the double quote character.", "interface");

                if (_logic.ListenPorts.Count == 0)
                    throw new OptionException("You must specify at least one port to listen on.", "listen-port");

                if (_logic.ListenPorts.Count != _logic.ListenPorts.Distinct().Count())
                    throw new OptionException("You have specified duplicate ports to listen on. Did you make a typo?", "listen-port");

                if (string.IsNullOrWhiteSpace(_logic.ListenInterface))
                    throw new OptionException("The network interface name must be specified.", "interface");
            }
            catch (OptionException ex)
            {
                Console.WriteLine(ex.Message);
                Console.WriteLine("For usage instructions, use the --help command line parameter.");
                return false;
            }

            if (remainingOptions.Count != 0)
            {
                Console.WriteLine("Unknown command line parameters: {0}", string.Join(" ", remainingOptions.ToArray()));
                Console.WriteLine("For usage instructions, use the --help command line parameter.");
                return false;
            }

            if (debugger)
                Debugger.Launch();

            return true;
        }

        private string GetVersionString()
        {
            return $"{typeof(Program).Namespace} v{Constants.VersionString}";
        }

        private Program()
        {
            // We default to displaying Info or higher but allow this to be reconfiured later, if the user wishes.
            _filteringLogListener = new FilteringLogListener(new ConsoleLogListener())
            {
#if !DEBUG
                MinimumSeverity = LogEntrySeverity.Info
#endif
            };

            Log.Default.RegisterListener(_filteringLogListener);
        }

        private static void Main(string[] args)
        {
            new Program().Run(args);
        }
    }
}
