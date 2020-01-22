using Axinom.Toolkit;

namespace TzspPacketStreamExporter
{
    static class Constants
    {
        // Will be replaced with real version string (AssemblyInfo number + build parameters) on automated build.
        public const string VersionString = "__BUILD_BUILDNUMBER__";

        public const ushort DefaultPublishPort = 9184;

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
