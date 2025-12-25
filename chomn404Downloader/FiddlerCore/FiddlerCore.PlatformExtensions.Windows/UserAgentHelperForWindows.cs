using System.Runtime.InteropServices;

namespace FiddlerCore.PlatformExtensions.Windows;

internal static class UserAgentHelperForWindows
{
	private const uint URLMON_OPTION_USERAGENT = 268435457u;

	private const uint URLMON_OPTION_USERAGENT_REFRESH = 268435458u;

	[DllImport("urlmon.dll", CharSet = CharSet.Ansi, EntryPoint = "UrlMkSetSessionOption", SetLastError = true)]
	private static extern int UrlMkSetSessionOptionUA(uint dwOption, string sNewUA, uint dwLen, uint dwZero);

	public static void SetUserAgentStringForCurrentProcess(string userAgent)
	{
		UrlMkSetSessionOptionUA(268435457u, userAgent, (uint)userAgent.Length, 0u);
	}
}
