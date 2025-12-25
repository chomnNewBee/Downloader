using System;
using Telerik.NetworkConnections;

namespace Fiddler;

/// <summary>
/// A generic builder class for <see cref="T:Fiddler.FiddlerCoreStartupSettings" />.
/// </summary>
/// <typeparam name="T"><see cref="T:Fiddler.FiddlerCoreStartupSettingsBuilder`2" /></typeparam>
/// <typeparam name="P"><see cref="T:Fiddler.FiddlerCoreStartupSettings" /></typeparam>
public abstract class FiddlerCoreStartupSettingsBuilder<T, P> : IFiddlerCoreStartupSettingsBuilder<T, P> where T : FiddlerCoreStartupSettingsBuilder<T, P> where P : FiddlerCoreStartupSettings
{
	/// <summary>
	/// The FiddlerCoreStartupSettings instance being built.
	/// </summary>
	protected P fiddlerCoreStartupSettings;

	/// <summary>
	/// Reference to this. Return this field instead of (T)this in your methods in order to avoid multiple casting.
	/// </summary>
	protected readonly T t;

	private bool fiddlerCoreStartupSettingsIsBuilt = false;

	/// <summary>
	/// Initializes a new instance of <see cref="T:Fiddler.FiddlerCoreStartupSettingsBuilder`2" />
	/// </summary>
	/// <param name="fiddlerCoreStartupSettings">The instance of FiddlerCoreStartupSettings which is going to be built.</param>
	internal FiddlerCoreStartupSettingsBuilder(P fiddlerCoreStartupSettings)
	{
		if (fiddlerCoreStartupSettings == null)
		{
			throw new ArgumentNullException("fiddlerCoreStartupSettings", "fiddlerCoreStartupSettings cannot be null.");
		}
		this.fiddlerCoreStartupSettings = fiddlerCoreStartupSettings;
		t = (T)this;
	}

	/// <summary>
	/// The port on which the FiddlerCore app will listen on. If 0, a random port will be used.
	/// </summary>
	/// <param name="port">The port on which the FiddlerCore app should listen on.</param>
	/// <returns><see cref="T:Fiddler.FiddlerCoreStartupSettingsBuilder`2" /></returns>
	public virtual T ListenOnPort(ushort port)
	{
		fiddlerCoreStartupSettings.ListenPort = port;
		return t;
	}

	/// <summary>
	/// Registers as the system proxy.
	/// </summary>
	/// <returns><see cref="T:Fiddler.FiddlerCoreStartupSettingsBuilder`2" /></returns>
	public virtual T RegisterAsSystemProxy()
	{
		fiddlerCoreStartupSettings.RegisterAsSystemProxy = true;
		return t;
	}

	/// <summary>
	/// Decrypts HTTPS Traffic.
	/// </summary>
	/// <returns><see cref="T:Fiddler.FiddlerCoreStartupSettingsBuilder`2" /></returns>
	public virtual T DecryptSSL()
	{
		fiddlerCoreStartupSettings.DecryptSSL = true;
		return t;
	}

	/// <summary>
	/// Accepts requests from remote computers or devices. WARNING: Security Impact
	/// </summary>
	/// <remarks>
	/// Use caution when allowing Remote Clients to connect. If a hostile computer is able to proxy its traffic through your
	/// FiddlerCore instance, he could circumvent IPSec traffic rules, circumvent intranet firewalls, consume memory on your PC, etc.
	/// </remarks>
	/// <returns><see cref="T:Fiddler.FiddlerCoreStartupSettingsBuilder`2" /></returns>
	public virtual T AllowRemoteClients()
	{
		fiddlerCoreStartupSettings.AllowRemoteClients = true;
		return t;
	}

	/// <summary>
	/// Forwards requests to any upstream gateway.
	/// </summary>
	/// <returns><see cref="T:Fiddler.FiddlerCoreStartupSettingsBuilder`2" /></returns>
	public virtual T ChainToUpstreamGateway()
	{
		fiddlerCoreStartupSettings.ChainToUpstreamGateway = true;
		return t;
	}

	/// <summary>
	/// Sets all connections to use FiddlerCore, otherwise only the Local LAN is pointed to FiddlerCore.
	/// </summary>
	/// <returns><see cref="T:Fiddler.FiddlerCoreStartupSettingsBuilder`2" /></returns>
	public virtual T MonitorAllConnections()
	{
		fiddlerCoreStartupSettings.MonitorAllConnections = true;
		return t;
	}

	/// <summary>
	/// Sets connections to use a self-generated PAC File.
	/// </summary>
	/// <returns><see cref="T:Fiddler.FiddlerCoreStartupSettingsBuilder`2" /></returns>
	public virtual T HookUsingPACFile()
	{
		fiddlerCoreStartupSettings.HookUsingPACFile = true;
		return t;
	}

	/// <summary>
	/// Passes the &lt;-loopback&gt; token to the proxy exception list.
	/// </summary>
	/// <returns><see cref="T:Fiddler.FiddlerCoreStartupSettingsBuilder`2" /></returns>
	[Obsolete("Use the Telerik.NetworkConnections.NetworkConnectionsManager to register the FiddlerCore Proxy as proxy for each required connection and set the BypassHosts accordingly.")]
	public virtual T CaptureLocalhostTraffic()
	{
		fiddlerCoreStartupSettings.CaptureLocalhostTraffic = true;
		return t;
	}

	/// <summary>
	/// Registers FiddlerCore as the FTP proxy.
	/// </summary>
	/// <returns><see cref="T:Fiddler.FiddlerCoreStartupSettingsBuilder`2" /></returns>
	public virtual T CaptureFTP()
	{
		fiddlerCoreStartupSettings.CaptureFTP = true;
		return t;
	}

	/// <summary>
	/// Calls ThreadPool.SetMinThreads for improved performance.
	/// </summary>
	/// <returns><see cref="T:Fiddler.FiddlerCoreStartupSettingsBuilder`2" /></returns>
	public virtual T OptimizeThreadPool()
	{
		fiddlerCoreStartupSettings.OptimizeThreadPool = true;
		return t;
	}

	/// <summary>
	/// Sets manual upstream gateway.
	/// </summary>
	/// <param name="upstreamGateway">The upstream gateway which FiddlerCore will use in the format "address:port | protocol=address:port(;protocol=address:port)*"</param>
	/// <returns><see cref="T:Fiddler.FiddlerCoreStartupSettingsBuilder`2" /></returns>
	[Obsolete("Please, use the SetUpstreamProxySettingsTo method.")]
	public virtual T SetUpstreamGatewayTo(string upstreamGateway)
	{
		return SetUpstreamGatewayTo(upstreamGateway, string.Empty);
	}

	/// <summary>
	/// Sets manual upstream gateway with a bypass list.
	/// </summary>
	/// <param name="upstreamGateway">The upstream gateway which FiddlerCore will use in the format "address:port | protocol=address:port(;protocol=address:port)*"</param>
	/// <param name="bypassList">List of hosts which should bypass the manually configured upstream gateway. Format: "example.com;*.another-example.com".</param>
	/// <returns><see cref="T:Fiddler.IFiddlerCoreStartupSettingsBuilder`2" /></returns>
	public virtual T SetUpstreamGatewayTo(string upstreamGateway, string bypassList)
	{
		fiddlerCoreStartupSettings.UpstreamGateway = upstreamGateway;
		fiddlerCoreStartupSettings.UpstreamGatewayBypassList = bypassList ?? string.Empty;
		return t;
	}

	/// <summary>
	/// Sets the proxy settings which FiddlerCore uses to find the upstream proxy.
	/// </summary>
	/// <param name="proxySettings"><see cref="T:Telerik.NetworkConnections.ProxySettings" /></param>
	/// <returns><see cref="T:Fiddler.IFiddlerCoreStartupSettingsBuilder`2" /></returns>
	public virtual T SetUpstreamProxySettingsTo(ProxySettings proxySettings)
	{
		fiddlerCoreStartupSettings.UpstreamProxySettings = proxySettings;
		return t;
	}

	/// <summary>
	/// Builds the FiddlerCoreStartupSettings instance.
	/// </summary>
	/// <returns>The instance of FiddlerCoreStartupSettings.</returns>
	public P Build()
	{
		if (fiddlerCoreStartupSettingsIsBuilt)
		{
			throw new InvalidOperationException("An instance of FiddlerCoreStartupSettingsBuilder is able to build FiddlerCoreStartupSettings only once.");
		}
		fiddlerCoreStartupSettingsIsBuilt = true;
		P result = fiddlerCoreStartupSettings;
		fiddlerCoreStartupSettings = null;
		return result;
	}
}
/// <summary>
/// A builder class for <see cref="T:Fiddler.FiddlerCoreStartupSettings" />.
/// </summary>
public sealed class FiddlerCoreStartupSettingsBuilder : FiddlerCoreStartupSettingsBuilder<FiddlerCoreStartupSettingsBuilder, FiddlerCoreStartupSettings>, IFiddlerCoreStartupSettingsBuilder<FiddlerCoreStartupSettingsBuilder, FiddlerCoreStartupSettings>
{
	/// <summary>
	/// Initializes a new instance of <see cref="T:Fiddler.FiddlerCoreStartupSettingsBuilder" />
	/// </summary>
	public FiddlerCoreStartupSettingsBuilder()
		: base(new FiddlerCoreStartupSettings())
	{
	}
}
