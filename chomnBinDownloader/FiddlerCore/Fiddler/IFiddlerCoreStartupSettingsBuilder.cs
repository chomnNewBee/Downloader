using System;
using Telerik.NetworkConnections;

namespace Fiddler;

/// <summary>
/// A generic builder interface for <see cref="T:Fiddler.FiddlerCoreStartupSettings" />.
/// </summary>
/// <typeparam name="T"><see cref="T:Fiddler.IFiddlerCoreStartupSettingsBuilder`2" /></typeparam>
/// <typeparam name="P"><see cref="T:Fiddler.FiddlerCoreStartupSettings" /></typeparam>
public interface IFiddlerCoreStartupSettingsBuilder<out T, out P> where T : IFiddlerCoreStartupSettingsBuilder<T, P> where P : FiddlerCoreStartupSettings
{
	/// <summary>
	/// The port on which the FiddlerCore app will listen on. If 0, a random port will be used.
	/// </summary>
	/// <param name="port">The port on which the FiddlerCore app should listen on.</param>
	/// <returns><see cref="T:Fiddler.IFiddlerCoreStartupSettingsBuilder`2" /></returns>
	T ListenOnPort(ushort port);

	/// <summary>
	/// Registers as the system proxy.
	/// </summary>
	/// <returns><see cref="T:Fiddler.IFiddlerCoreStartupSettingsBuilder`2" /></returns>
	T RegisterAsSystemProxy();

	/// <summary>
	/// Decrypts HTTPS Traffic.
	/// </summary>
	/// <returns><see cref="T:Fiddler.IFiddlerCoreStartupSettingsBuilder`2" /></returns>
	T DecryptSSL();

	/// <summary>
	/// Accepts requests from remote computers or devices. WARNING: Security Impact
	/// </summary>
	/// <remarks>
	/// Use caution when allowing Remote Clients to connect. If a hostile computer is able to proxy its traffic through your
	/// FiddlerCore instance, he could circumvent IPSec traffic rules, circumvent intranet firewalls, consume memory on your PC, etc.
	/// </remarks>
	/// <returns><see cref="T:Fiddler.IFiddlerCoreStartupSettingsBuilder`2" /></returns>
	T AllowRemoteClients();

	/// <summary>
	/// Forwards requests to any upstream gateway.
	/// </summary>
	/// <returns><see cref="T:Fiddler.IFiddlerCoreStartupSettingsBuilder`2" /></returns>
	[Obsolete("Please, use the SetUpstreamProxySettingsTo method to provide the upstream proxy for FiddlerCore.")]
	T ChainToUpstreamGateway();

	/// <summary>
	/// Sets all connections to use FiddlerCore, otherwise only the Local LAN is pointed to FiddlerCore.
	/// </summary>
	/// <returns><see cref="T:Fiddler.IFiddlerCoreStartupSettingsBuilder`2" /></returns>
	T MonitorAllConnections();

	/// <summary>
	/// Sets connections to use a self-generated PAC File.
	/// </summary>
	/// <returns><see cref="T:Fiddler.IFiddlerCoreStartupSettingsBuilder`2" /></returns>
	T HookUsingPACFile();

	/// <summary>
	/// Passes the &lt;-loopback&gt; token to the proxy exception list.
	/// </summary>
	/// <returns><see cref="T:Fiddler.IFiddlerCoreStartupSettingsBuilder`2" /></returns>
	[Obsolete("Use the Telerik.NetworkConnections.NetworkConnectionsManager to register the FiddlerCore Proxy as proxy for each required connection and set the BypassHosts accordingly.")]
	T CaptureLocalhostTraffic();

	/// <summary>
	/// Registers FiddlerCore as the FTP proxy.
	/// </summary>
	/// <returns><see cref="T:Fiddler.IFiddlerCoreStartupSettingsBuilder`2" /></returns>
	T CaptureFTP();

	/// <summary>
	/// Calls ThreadPool.SetMinThreads for improved performance.
	/// </summary>
	/// <returns><see cref="T:Fiddler.IFiddlerCoreStartupSettingsBuilder`2" /></returns>
	T OptimizeThreadPool();

	/// <summary>
	/// Sets manual upstream gateway.
	/// </summary>
	/// <param name="upstreamGateway">The upstream gateway which FiddlerCore will use in the format "address:port | protocol=address:port(;protocol=address:port)*"</param>
	/// <returns><see cref="T:Fiddler.IFiddlerCoreStartupSettingsBuilder`2" /></returns>
	[Obsolete("Please, use the SetUpstreamProxySettingsTo method.")]
	T SetUpstreamGatewayTo(string upstreamGateway);

	/// <summary>
	/// Sets the proxy settings which FiddlerCore uses to find the upstream proxy.
	/// </summary>
	/// <param name="proxySettings"><see cref="T:Telerik.NetworkConnections.ProxySettings" /></param>
	/// <returns><see cref="T:Fiddler.IFiddlerCoreStartupSettingsBuilder`2" /></returns>
	T SetUpstreamProxySettingsTo(ProxySettings proxySettings);

	/// <summary>
	/// Sets manual upstream gateway with a bypass list.
	/// </summary>
	/// <param name="upstreamGateway">The upstream gateway which FiddlerCore will use in the format "address:port | protocol=address:port(;protocol=address:port)*"</param>
	/// <param name="bypassList">List of hosts which should bypass the manually configured upstream gateway. Format: "example.com;*.another-example.com".</param>
	/// <returns><see cref="T:Fiddler.IFiddlerCoreStartupSettingsBuilder`2" /></returns>
	T SetUpstreamGatewayTo(string upstreamGateway, string bypassList);

	/// <summary>
	/// Builds the FiddlerCoreStartupSettings instance.
	/// </summary>
	/// <returns>The instance of FiddlerCoreStartupSettings.</returns>
	P Build();
}
