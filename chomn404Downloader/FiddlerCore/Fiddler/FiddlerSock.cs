using FiddlerCore.PlatformExtensions;
using FiddlerCore.PlatformExtensions.API;

namespace Fiddler;

internal static class FiddlerSock
{
	private static readonly IPlatformExtensions platformExtensions = PlatformExtensionsFactory.Instance.CreatePlatformExtensions();

	/// <summary>
	/// Map a local port number to the originating process ID
	/// </summary>
	/// <param name="iPort">The local port number</param>
	/// <returns>The originating process ID</returns>
	internal static int MapLocalPortToProcessId(int iPort)
	{
		if (!platformExtensions.TryMapPortToProcessId(iPort, CONFIG.EnableIPv6, out var processId, out var errorMessage))
		{
			FiddlerApplication.Log.LogString(errorMessage);
		}
		return processId;
	}

	/// <summary>
	/// Returns a string containing the process listening on a given port
	/// </summary>
	internal static string GetListeningProcess(int iPort)
	{
		if (!platformExtensions.TryGetListeningProcessOnPort(iPort, out var processName, out var processId, out var errorMessage))
		{
			FiddlerApplication.Log.LogString(errorMessage);
		}
		if (processId < 1)
		{
			return string.Empty;
		}
		return processName + ":" + processId;
	}
}
