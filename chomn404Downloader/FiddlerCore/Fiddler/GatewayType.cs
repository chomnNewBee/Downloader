using System;

namespace Fiddler;

/// <summary>
/// Type of Upstream Gateway
/// </summary>
[Obsolete("Use Telerik.NetworkConnections.NetworkConnectionsManager.GetCurrentProxySettingsForConnection(*) to get information for the current proxy settings.")]
public enum GatewayType : byte
{
	/// <summary>
	/// Traffic should be sent directly to the server
	/// </summary>
	None,
	/// <summary>
	/// Traffic should be sent to a manually-specified proxy
	/// </summary>
	Manual,
	/// <summary>
	/// Traffic should be sent to the System-configured proxy
	/// </summary>
	System,
	/// <summary>
	/// Proxy should be automatically detected
	/// </summary>
	WPAD
}
