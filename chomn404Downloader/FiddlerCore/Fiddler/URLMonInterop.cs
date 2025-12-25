using FiddlerCore.PlatformExtensions;
using FiddlerCore.PlatformExtensions.API;

namespace Fiddler;

/// <summary>
/// URLMon Interop Class
/// </summary>
public static class URLMonInterop
{
	/// <summary>
	/// Set the user-agent string for the current process
	/// </summary>
	/// <param name="sUA">New UA string</param>
	public static void SetUAStringInProcess(string sUA)
	{
		IPlatformExtensions extensions = PlatformExtensionsFactory.Instance.CreatePlatformExtensions();
		extensions.SetUserAgentStringForCurrentProcess(sUA);
	}

	/// <summary>
	/// Query WinINET for the current process' proxy settings. Oddly, there's no way to UrlMkGetSessionOption for the current proxy.
	/// </summary>
	/// <returns>String of hex suitable for display</returns>
	public static string GetProxyInProcess()
	{
		IPlatformExtensions extensions = PlatformExtensionsFactory.Instance.CreatePlatformExtensions();
		return extensions.ProxyHelper.GetProxyForCurrentProcessAsHexView();
	}

	/// <summary>
	/// Configures the current process to use the system proxy for URLMon/WinINET traffic.
	/// </summary>
	public static void ResetProxyInProcessToDefault()
	{
		IPlatformExtensions extensions = PlatformExtensionsFactory.Instance.CreatePlatformExtensions();
		extensions.ProxyHelper.ResetProxyForCurrentProcess();
	}

	/// <summary>
	/// Configures the current process to use no Proxy for URLMon/WinINET traffic.
	/// </summary>
	public static void SetProxyDisabledForProcess()
	{
		IPlatformExtensions extensions = PlatformExtensionsFactory.Instance.CreatePlatformExtensions();
		extensions.ProxyHelper.DisableProxyForCurrentProcess();
	}

	/// <summary>
	/// Sets the proxy for the current process to the specified list. See http://msdn.microsoft.com/en-us/library/aa383996(VS.85).aspx
	/// </summary>
	/// <param name="sProxy">e.g. "127.0.0.1:8888" or "http=insecProxy:80;https=secProxy:444"</param>
	/// <param name="sBypassList">Semi-colon delimted list of hosts to bypass proxy; use &lt;local&gt; to bypass for Intranet</param>
	public static void SetProxyInProcess(string sProxy, string sBypassList)
	{
		IPlatformExtensions extensions = PlatformExtensionsFactory.Instance.CreatePlatformExtensions();
		extensions.ProxyHelper.SetProxyForCurrentProcess(sProxy, sBypassList);
	}
}
