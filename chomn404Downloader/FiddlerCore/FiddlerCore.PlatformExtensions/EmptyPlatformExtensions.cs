using System;
using FiddlerCore.PlatformExtensions.API;

namespace FiddlerCore.PlatformExtensions;

internal abstract class EmptyPlatformExtensions : BasePlatformExtensions, IPlatformExtensions
{
	public override bool HighResolutionTimersEnabled => false;

	public override IProxyHelper ProxyHelper => EmptyProxyHelper.Instance;

	public override bool TryMapPortToProcessId(int port, bool includeIPv6, out int processId, out string errorMessage)
	{
		processId = 0;
		errorMessage = "This method is not supported on your platform.";
		return false;
	}

	public override bool TryGetListeningProcessOnPort(int port, out string processName, out int processId, out string errorMessage)
	{
		processName = string.Empty;
		processId = 0;
		errorMessage = "This method is not supported on your platform.";
		return false;
	}

	public override bool TryChangeTimersResolution(bool increase)
	{
		return false;
	}

	public override IAutoProxy CreateAutoProxy(bool autoDiscover, string pacUrl, bool autoProxyRunInProcess, bool autoLoginIfChallenged)
	{
		throw new NotSupportedException("This method is not supported on your platform.");
	}

	public override byte[] DecompressXpress(byte[] data)
	{
		throw new NotSupportedException("This method is not supported on your platform.");
	}

	public override string PostProcessProcessName(int pid, string processName)
	{
		return processName;
	}

	public override void SetUserAgentStringForCurrentProcess(string userAgent)
	{
		throw new NotSupportedException("This method is not supported on your platform.");
	}

	public override bool TryGetUptimeInMilliseconds(out ulong milliseconds)
	{
		milliseconds = 0uL;
		return false;
	}
}
