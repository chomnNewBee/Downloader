using FiddlerCore.PlatformExtensions.API;

namespace FiddlerCore.PlatformExtensions.Unix;

internal abstract class PlatformExtensionsForUnix : EmptyPlatformExtensions, IPlatformExtensions
{
	public override bool TryMapPortToProcessId(int port, bool includeIPv6, out int processId, out string errorMessage)
	{
		return PortProcessMapperForUnix.TryMapLocalPortToProcessId(port, out processId, out errorMessage);
	}

	public override bool TryGetListeningProcessOnPort(int port, out string processName, out int processId, out string errorMessage)
	{
		return PortProcessMapperForUnix.TryGetListeningProcessOnPort(port, out processName, out processId, out errorMessage);
	}
}
