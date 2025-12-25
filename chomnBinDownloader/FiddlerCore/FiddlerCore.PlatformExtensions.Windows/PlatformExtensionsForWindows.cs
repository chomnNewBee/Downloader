using FiddlerCore.PlatformExtensions.API;

namespace FiddlerCore.PlatformExtensions.Windows;

internal class PlatformExtensionsForWindows : BasePlatformExtensions, IWindowsSpecificPlatformExtensions, IPlatformExtensions
{
	private static PlatformExtensionsForWindows instance;

	public static PlatformExtensionsForWindows Instance
	{
		get
		{
			if (instance == null)
			{
				instance = new PlatformExtensionsForWindows();
			}
			return instance;
		}
	}

	public override bool HighResolutionTimersEnabled => TimeResolutionHelperForWindows.EnableHighResolutionTimers;

	public override IProxyHelper ProxyHelper => ProxyHelperForWindows.Instance;

	public IWinINetHelper WinINetHelper => FiddlerCore.PlatformExtensions.Windows.WinINetHelper.Instance;

	private PlatformExtensionsForWindows()
	{
	}

	public override bool TryMapPortToProcessId(int port, bool includeIPv6, out int processId, out string errorMessage)
	{
		return PortProcessMapperForWindows.TryMapLocalPortToProcessId(port, includeIPv6, out processId, out errorMessage);
	}

	public override bool TryGetListeningProcessOnPort(int port, out string processName, out int processId, out string errorMessage)
	{
		return PortProcessMapperForWindows.TryGetListeningProcess(port, out processName, out processId, out errorMessage);
	}

	public override bool TryChangeTimersResolution(bool increase)
	{
		TimeResolutionHelperForWindows.EnableHighResolutionTimers = increase;
		return TimeResolutionHelperForWindows.EnableHighResolutionTimers == increase;
	}

	public override IAutoProxy CreateAutoProxy(bool autoDiscover, string pacUrl, bool autoProxyRunInProcess, bool autoLoginIfChallenged)
	{
		return new WinHttpAutoProxy(autoDiscover, pacUrl, autoProxyRunInProcess, autoLoginIfChallenged);
	}

	public override byte[] DecompressXpress(byte[] data)
	{
		return XpressCompressionHelperForWindows.Decompress(data);
	}

	public override string PostProcessProcessName(int pid, string processName)
	{
		return ProcessHelperForWindows.DisambiguateWWAHostApps(pid, processName);
	}

	public override void SetUserAgentStringForCurrentProcess(string userAgent)
	{
		UserAgentHelperForWindows.SetUserAgentStringForCurrentProcess(userAgent);
	}

	public override bool TryGetUptimeInMilliseconds(out ulong milliseconds)
	{
		return UptimeHelperForWindows.TryGetUptimeInMilliseconds(out milliseconds);
	}
}
