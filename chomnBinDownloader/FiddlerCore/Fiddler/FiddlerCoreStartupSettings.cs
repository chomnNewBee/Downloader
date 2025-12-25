using System;
using System.ComponentModel;
using Telerik.NetworkConnections;

namespace Fiddler;

/// <summary>
/// Holds startup settings for FiddlerCore.
/// Use the <see cref="T:Fiddler.FiddlerCoreStartupSettingsBuilder" /> to build an instance of this class.
/// Then pass the instance to the <see cref="M:Fiddler.FiddlerApplication.Startup(Fiddler.FiddlerCoreStartupSettings)" /> method to start FiddlerCore.
/// </summary>
public class FiddlerCoreStartupSettings
{
	/// <summary>
	/// The port on which the FiddlerCore app will listen on. If 0, a random port will be used.
	/// </summary>
	public virtual ushort ListenPort { get; internal set; }

	/// <summary>
	/// If set to true, FiddlerCore registers as the system proxy.
	/// </summary>
	public virtual bool RegisterAsSystemProxy { get; internal set; }

	/// <summary>
	/// If set to true, FiddlerCore decrypts HTTPS Traffic.
	/// </summary>
	public virtual bool DecryptSSL { get; internal set; }

	/// <summary>
	/// If set to true, FiddlerCore accepts requests from remote computers or devices. WARNING: Security Impact.
	/// </summary>
	/// <remarks>
	/// Use caution when allowing Remote Clients to connect. If a hostile computer is able to proxy its traffic through your
	/// FiddlerCore instance, he could circumvent IPSec traffic rules, circumvent intranet firewalls, consume memory on your PC, etc.
	/// </remarks>
	public virtual bool AllowRemoteClients { get; internal set; }

	/// <summary>
	/// If set to true, FiddlerCore forwards requests to any upstream gateway.
	/// </summary>
	public virtual bool ChainToUpstreamGateway { get; internal set; }

	/// <summary>
	/// If set to true, FiddlerCore sets all connections to use it, otherwise only the Local LAN is pointed to FiddlerCore.
	/// </summary>
	public virtual bool MonitorAllConnections { get; internal set; }

	/// <summary>
	/// If set to true, FiddlerCore sets connections to use a self-generated PAC File.
	/// </summary>
	public virtual bool HookUsingPACFile { get; internal set; }

	/// <summary>
	/// If set to true, FiddlerCore passes the &lt;-loopback&gt; token to the proxy exception list.
	/// </summary>
	[Obsolete("Use the Telerik.NetworkConnections.NetworkConnectionsManager to register the FiddlerCore Proxy as proxy for each required connection and set the BypassHosts accordingly.")]
	public virtual bool CaptureLocalhostTraffic { get; internal set; }

	/// <summary>
	/// If set to true, FiddlerCore registers as the FTP proxy.
	/// </summary>
	public virtual bool CaptureFTP { get; internal set; }

	/// <summary>
	/// If set to true, FiddlerCore calls ThreadPool.SetMinThreads to improve performance.
	/// </summary>
	public virtual bool OptimizeThreadPool { get; internal set; }

	/// <summary>
	/// The upstream gateway which FiddlerCore will use in the format "address:port | protocol=address:port(;protocol=address:port)*".
	/// </summary>
	[Obsolete("Use the UpstreamProxySettings property instead.")]
	[EditorBrowsable(EditorBrowsableState.Never)]
	public virtual string UpstreamGateway { get; internal set; }

	/// <summary>
	/// The proxy settings which FiddlerCore uses to find the upstream proxy.
	/// </summary>
	public virtual ProxySettings UpstreamProxySettings { get; internal set; }

	/// <summary>
	/// List of hosts which should bypass the manually configured upstream gateway. Format: "example.com;*.another-example.com".
	/// </summary>
	public virtual string UpstreamGatewayBypassList { get; internal set; }

	/// <summary>
	/// Initializes a new instance of <see cref="T:Fiddler.FiddlerCoreStartupSettings" />.
	/// </summary>
	internal FiddlerCoreStartupSettings()
	{
	}
}
