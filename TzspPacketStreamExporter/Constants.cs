using Axinom.Toolkit;

namespace TzspPacketStreamExporter
{
    static class Constants
    {
        // Will be replaced with real version string (AssemblyInfo number + build parameters) on automated build.
        public const string VersionString = "__BUILD_BUILDNUMBER__";

        public const ushort DefaultPublishPort = 9184;

        /// <summary>
        /// How many packets we process before we restart TShark.
        /// This is necessary because we want to clean up the temporary files TShark generates.
        /// 
        /// Why can't we just use the ring buffer options? Because at least on my Windows PC,
        /// TShark never deletes old files in the ring buffer... so it's not a ring buffer at all.
        /// </summary>
        public const int PacketsPerIteration = 1_000_000;

        public static string TsharkExecutableName
        {
            get
            {
                if (Helpers.Environment.IsMicrosoftOperatingSystem())
                    return "tshark.exe";
                else
                    return "tshark";
            }
        }
    }
}
