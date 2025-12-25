using System;

namespace FiddlerCore.PlatformExtensions.API;

/// <summary>
/// Implement this interface in order to provide FiddlerCore with platform specific functionality.
/// </summary>
internal interface IPlatformExtensions
{
	/// <summary>
	/// Returns true if the system-wide timer's resolution is increased, false otherwise.
	/// </summary>
	bool HighResolutionTimersEnabled { get; }

	/// <summary>
	/// Gets a proxy helper, which can be used to manipulate proxy settings.
	/// </summary>
	IProxyHelper ProxyHelper { get; }

	/// <summary>
	/// This event is raised when a debug message is being spewed.
	/// </summary>
	event EventHandler<MessageEventArgs> DebugSpew;

	/// <summary>
	/// This event is raised when an error has occured.
	/// </summary>
	event EventHandler<MessageEventArgs> Error;

	/// <summary>
	/// This event is raised when a message is being logged.
	/// </summary>
	event EventHandler<MessageEventArgs> Log;

	/// <summary>
	/// Map a local port number to the originating process ID.
	/// </summary>
	/// <param name="port">The port number.</param>
	/// <param name="includeIPv6">true to include processes using IPv6 addresses in the mapping.</param>
	/// <param name="processId">Contains the originating process ID if the operation is successful.</param>
	/// <param name="errorMessage">Contains an error message if the operation fails.</param>
	/// <returns>true if the operation is successful, false otherwise.</returns>
	bool TryMapPortToProcessId(int port, bool includeIPv6, out int processId, out string errorMessage);

	/// <summary>
	/// Gets any process' name and ID which listens on a port.
	/// </summary>
	/// <param name="port">The port number.</param>
	/// <param name="processName">Contains the process name of a process if there is one listening on the port, otherwise contains an empty string.</param>
	/// <param name="processId">Contains the process ID of a process if there is one listening on the port, otherwise contains 0.</param>
	/// <param name="errorMessage">Contains an error message if the operation fails.</param>
	/// <returns>true if the operation is successful, false otherwise.</returns>
	bool TryGetListeningProcessOnPort(int port, out string processName, out int processId, out string errorMessage);

	/// <summary>
	/// Changes system-wide timer's resolution.
	/// </summary>
	/// <param name="increase">true to increase the resolution for better accuracy of timestamps, false to decrease it to the default value for the system.</param>
	/// <returns>true if the operation is successful, false otherwise.</returns>
	bool TryChangeTimersResolution(bool increase);

	/// <summary>
	/// Decompresses a byte[] that is compressed with XPRESS.
	/// </summary>
	/// <param name="data">The compressed byte[].</param>
	/// <returns>The decompressed byte[].</returns>
	byte[] DecompressXpress(byte[] data);

	/// <summary>
	/// This method is used to post-process the name of a process, in order to resolve it more accurately.
	/// </summary>
	/// <param name="pid">The ID of the process, whose name should be post-processed.</param>
	/// <param name="processName">The process name that should be post-processed.</param>
	/// <returns>The post-processed process name.</returns>
	string PostProcessProcessName(int pid, string processName);

	/// <summary>
	/// This method is used to set the user-agent string for the current process.
	/// </summary>
	/// <param name="userAgent">The user-agent string.</param>
	void SetUserAgentStringForCurrentProcess(string userAgent);

	/// <summary>
	/// This method is used to get the number of milliseconds since the system start.
	/// </summary>
	/// <param name="milliseconds">Contains the system uptime in milliseconds if the operation is successful.</param>
	/// <returns>true if the operation is successful, false otherwise.</returns>
	bool TryGetUptimeInMilliseconds(out ulong milliseconds);

	/// <summary>
	/// Creates <see cref="T:FiddlerCore.PlatformExtensions.API.IAutoProxy" />.
	/// </summary>
	/// <param name="autoDiscover">True if the <see cref="T:FiddlerCore.PlatformExtensions.API.IAutoProxy" /> must use the WPAD protocol, false otherwise.</param>
	/// <param name="pacUrl">URL of the Proxy Auto-Config file. Can be null.</param>
	/// <param name="autoProxyRunInProcess">True if the WPAD processing should be done in the current process, false otherwise.</param>
	/// <param name="autoLoginIfChallenged">Specifies whether the client's domain credentials should be automatically sent
	/// in response to an NTLM or Negotiate Authentication challenge when the <see cref="T:FiddlerCore.PlatformExtensions.API.IAutoProxy" /> requests the PAC file.</param>
	/// <returns><see cref="T:FiddlerCore.PlatformExtensions.API.IAutoProxy" /></returns>
	IAutoProxy CreateAutoProxy(bool autoDiscover, string pacUrl, bool autoProxyRunInProcess, bool autoLoginIfChallenged);
}
