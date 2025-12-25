using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using FiddlerCore.Utilities;
using Microsoft.Win32;
using Telerik.NetworkConnections;
using Telerik.NetworkConnections.Linux;
using Telerik.NetworkConnections.Mac;
using Telerik.NetworkConnections.Windows;

namespace Fiddler;

/// <summary>
/// The core proxy object which accepts connections from clients and creates session objects from those connections.
/// </summary>
public class Proxy : IDisposable
{
	internal static string sUpstreamPACScript;

	private NetworkConnectionsManager connectionsManager;

	/// <summary>
	/// Hostname if this Proxy Endpoint is terminating HTTPS connections
	/// </summary>
	private string _sHTTPSHostname;

	/// <summary>
	/// Certificate if this Proxy Endpoint is terminating HTTPS connections
	/// </summary>
	private X509Certificate2 _oHTTPSCertificate;

	/// <summary>
	/// Per-connectoid information about each WinINET connectoid
	/// </summary>
	internal Connectoids oAllConnectoids = null;

	private ProxySettings fiddlerProxySettings = null;

	/// <summary>
	/// The upstream proxy settings.
	/// </summary>
	private ProxySettings upstreamProxySettings = null;

	/// <summary>
	/// The AutoProxy object, created if we're using WPAD or a PAC Script as a gateway
	/// </summary>
	private AutoProxy oAutoProxy = null;

	private IPEndPoint _ipepFtpGateway = null;

	private IPEndPoint _ipepHttpGateway = null;

	private IPEndPoint _ipepHttpsGateway = null;

	/// <summary>
	/// Allow binding to a specific egress adapter: "fiddler.network.egress.ip"
	/// </summary>
	internal IPEndPoint _DefaultEgressEndPoint = null;

	/// <summary>
	/// Watcher for Notification of Preference changes
	/// </summary>
	private PreferenceBag.PrefWatcher? watcherPrefNotify = null;

	/// <summary>
	/// Server connections may be pooled for performance reasons.
	/// </summary>
	internal static PipePool htServerPipePool = new PipePool();

	/// <summary>
	/// The Socket Endpoint on which this proxy receives requests
	/// </summary>
	private Socket oAcceptor;

	[Obsolete]
	private bool _bIsAttached = false;

	/// <summary>
	/// Flag indicating that Fiddler is in the process of detaching...
	/// </summary>
	private bool _bDetaching = false;

	/// <summary>
	/// List of hosts which should bypass the upstream gateway
	/// </summary>
	private ProxyBypassList oBypassList = null;

	private static readonly Regex PortRegex = new Regex(":(\\d+)$");

	/// <summary>
	/// Returns true if the proxy is listening on a port.
	/// </summary>
	public bool IsListening => oAcceptor != null && oAcceptor.IsBound;

	/// <summary>
	/// The port on which this instance is listening
	/// </summary>
	public int ListenPort
	{
		get
		{
			if (oAcceptor != null && oAcceptor.LocalEndPoint is IPEndPoint ipEP)
			{
				return ipEP.Port;
			}
			return 0;
		}
	}

	/// <summary>
	/// Returns true if Fiddler believes it is currently registered as the Local System proxy
	/// </summary>
	[Obsolete("Use Telerik.NetworkConnections.NetworkConnectionsManager.GetCurrentProxySettingsForConnection(*)/SetProxySettingsForConnections(*) to manipulate current proxy settings.")]
	public bool IsAttached
	{
		get
		{
			return _bIsAttached;
		}
		set
		{
			if (value)
			{
				Attach();
			}
			else
			{
				Detach();
			}
		}
	}

	/// <summary>
	/// This event handler fires when Fiddler detects that it is (unexpectedly) no longer the system's registered proxy
	/// </summary>
	[Obsolete("Use Telerik.NetworkConnections.NetworkConnectionsManager.ProxySettingsChanged event instead.")]
	public event EventHandler DetachedUnexpectedly;

	/// <summary>
	/// Returns a string of information about this instance and the ServerPipe reuse pool
	/// </summary>
	/// <returns>A multiline string</returns>
	public override string ToString()
	{
		return string.Format("Proxy instance is listening for requests on Port #{0}. HTTPS SubjectCN: {1}\n\n{2}", ListenPort, _sHTTPSHostname ?? "<None>", htServerPipePool.InspectPool());
	}

	[Obsolete("Use Telerik.NetworkConnections.NetworkConnectionsManager.ProxySettingsChanged event instead.")]
	protected virtual void OnDetachedUnexpectedly()
	{
		this.DetachedUnexpectedly?.Invoke(this, EventArgs.Empty);
	}

	internal Proxy(bool isPrimary, ProxySettings upstreamProxySettings)
	{
		this.upstreamProxySettings = upstreamProxySettings;
		InitializeNetworkConnections();
		if (isPrimary)
		{
			NetworkChange.NetworkAvailabilityChanged += NetworkChange_NetworkAvailabilityChanged;
			NetworkChange.NetworkAddressChanged += NetworkChange_NetworkAddressChanged;
			try
			{
				watcherPrefNotify = FiddlerApplication.Prefs.AddWatcher("fiddler.network", onNetworkPrefsChange);
				SetDefaultEgressEndPoint(FiddlerApplication.Prefs["fiddler.network.egress.ip"]);
				CONFIG.SetNoDecryptList(FiddlerApplication.Prefs["fiddler.network.https.NoDecryptionHosts"]);
				CONFIG.SetNoDecryptListInvert(FiddlerApplication.Prefs.GetBoolPref("fiddler.network.https.NoDecryptionHosts.Invert", bDefault: false));
				CONFIG.sFiddlerListenHostPort = string.Format("{0}:{1}", FiddlerApplication.Prefs.GetStringPref("fiddler.network.proxy.RegistrationHostName", "127.0.0.1").ToLower(), CONFIG.ListenPort);
				ClientChatter.s_cbClientReadBuffer = FiddlerApplication.Prefs.GetInt32Pref("fiddler.network.sockets.ClientReadBufferSize", ClientChatter.s_cbClientReadBuffer);
				ServerChatter.s_cbServerReadBuffer = FiddlerApplication.Prefs.GetInt32Pref("fiddler.network.sockets.ServerReadBufferSize", ServerChatter.s_cbServerReadBuffer);
				ClientChatter.s_SO_SNDBUF_Option = FiddlerApplication.Prefs.GetInt32Pref("fiddler.network.sockets.Client_SO_SNDBUF", ClientChatter.s_SO_SNDBUF_Option);
				ClientChatter.s_SO_RCVBUF_Option = FiddlerApplication.Prefs.GetInt32Pref("fiddler.network.sockets.Client_SO_RCVBUF", ClientChatter.s_SO_RCVBUF_Option);
				ServerChatter.s_SO_SNDBUF_Option = FiddlerApplication.Prefs.GetInt32Pref("fiddler.network.sockets.Server_SO_SNDBUF", ServerChatter.s_SO_SNDBUF_Option);
				ServerChatter.s_SO_RCVBUF_Option = FiddlerApplication.Prefs.GetInt32Pref("fiddler.network.sockets.Server_SO_RCVBUF", ServerChatter.s_SO_RCVBUF_Option);
			}
			catch (Exception)
			{
			}
		}
	}

	private void InitializeNetworkConnections()
	{
		//IL_0017: Unknown result type (might be due to invalid IL or missing references)
		//IL_0021: Expected O, but got Unknown
		//IL_0023: Unknown result type (might be due to invalid IL or missing references)
		//IL_002d: Expected O, but got Unknown
		//IL_0041: Unknown result type (might be due to invalid IL or missing references)
		//IL_004b: Expected O, but got Unknown
		//IL_008a: Unknown result type (might be due to invalid IL or missing references)
		//IL_0094: Expected O, but got Unknown
		//IL_005f: Unknown result type (might be due to invalid IL or missing references)
		//IL_0069: Expected O, but got Unknown
		List<INetworkConnectionsDetector> platformDetectors = new List<INetworkConnectionsDetector>();
		if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
		{
			platformDetectors.Add((INetworkConnectionsDetector)new WinINetNetworkConnectionsDetector());
			platformDetectors.Add((INetworkConnectionsDetector)new RasNetworkConnectionsDetector());
		}
		else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
		{
			platformDetectors.Add((INetworkConnectionsDetector)new MacNetworkConnectionsDetector());
		}
		else
		{
			if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
			{
				throw new PlatformNotSupportedException("Proxy cannot be used on '" + RuntimeInformation.OSDescription + "' platform.");
			}
			platformDetectors.Add((INetworkConnectionsDetector)new LinuxNetworkConnectionsDetector());
		}
		connectionsManager = new NetworkConnectionsManager((IEnumerable<INetworkConnectionsDetector>)platformDetectors);
	}

	/// <summary>
	/// Change the outbound IP address used to send traffic
	/// </summary>
	/// <param name="sEgressIP"></param>
	private void SetDefaultEgressEndPoint(string sEgressIP)
	{
		IPAddress theIP;
		if (string.IsNullOrEmpty(sEgressIP))
		{
			_DefaultEgressEndPoint = null;
		}
		else if (IPAddress.TryParse(sEgressIP, out theIP))
		{
			_DefaultEgressEndPoint = new IPEndPoint(theIP, 0);
		}
		else
		{
			_DefaultEgressEndPoint = null;
		}
	}

	/// <summary>
	/// Watch for relevent changes on the Preferences object
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="oPCE"></param>
	private void onNetworkPrefsChange(object sender, PrefChangeEventArgs oPCE)
	{
		if (oPCE.PrefName.OICStartsWith("fiddler.network.timeouts."))
		{
			if (oPCE.PrefName.OICEquals("fiddler.network.timeouts.serverpipe.send.initial"))
			{
				ServerPipe._timeoutSendInitial = FiddlerApplication.Prefs.GetInt32Pref("fiddler.network.timeouts.serverpipe.send.initial", -1);
			}
			else if (oPCE.PrefName.OICEquals("fiddler.network.timeouts.serverpipe.send.reuse"))
			{
				ServerPipe._timeoutSendReused = FiddlerApplication.Prefs.GetInt32Pref("fiddler.network.timeouts.serverpipe.send.reuse", -1);
			}
			else if (oPCE.PrefName.OICEquals("fiddler.network.timeouts.serverpipe.receive.initial"))
			{
				ServerPipe._timeoutReceiveInitial = FiddlerApplication.Prefs.GetInt32Pref("fiddler.network.timeouts.serverpipe.receive.initial", -1);
			}
			else if (oPCE.PrefName.OICEquals("fiddler.network.timeouts.serverpipe.receive.reuse"))
			{
				ServerPipe._timeoutReceiveReused = FiddlerApplication.Prefs.GetInt32Pref("fiddler.network.timeouts.serverpipe.receive.reuse", -1);
			}
			else if (oPCE.PrefName.OICEquals("fiddler.network.timeouts.serverpipe.reuse"))
			{
				PipePool.MSEC_PIPE_POOLED_LIFETIME = (uint)FiddlerApplication.Prefs.GetInt32Pref("fiddler.network.timeouts.serverpipe.reuse", 115000);
			}
			else if (oPCE.PrefName.OICEquals("fiddler.network.timeouts.clientpipe.receive.initial"))
			{
				ClientPipe._timeoutFirstReceive = FiddlerApplication.Prefs.GetInt32Pref("fiddler.network.timeouts.clientpipe.receive.initial", 45000);
			}
			else if (oPCE.PrefName.OICEquals("fiddler.network.timeouts.clientpipe.receive.loop"))
			{
				ClientPipe._timeoutReceiveLoop = FiddlerApplication.Prefs.GetInt32Pref("fiddler.network.timeouts.clientpipe.receive.loop", 60000);
			}
			else if (oPCE.PrefName.OICEquals("fiddler.network.timeouts.clientpipe.idle"))
			{
				ClientPipe._timeoutIdle = FiddlerApplication.Prefs.GetInt32Pref("fiddler.network.timeouts.clientpipe.idle", 115000);
			}
			else if (oPCE.PrefName.OICEquals("fiddler.network.timeouts.dnscache"))
			{
				DNSResolver.MSEC_DNS_CACHE_LIFETIME = (ulong)FiddlerApplication.Prefs.GetInt32Pref("fiddler.network.timeouts.dnscache", 150000);
			}
		}
		else if (oPCE.PrefName.OICEquals("fiddler.network.sockets.ClientReadBufferSize"))
		{
			ClientChatter.s_cbClientReadBuffer = FiddlerApplication.Prefs.GetInt32Pref("fiddler.network.sockets.ClientReadBufferSize", 8192);
		}
		else if (oPCE.PrefName.OICEquals("fiddler.network.sockets.ServerReadBufferSize"))
		{
			ServerChatter.s_cbServerReadBuffer = FiddlerApplication.Prefs.GetInt32Pref("fiddler.network.sockets.ServerReadBufferSize", 32768);
		}
		else if (oPCE.PrefName.OICEquals("fiddler.network.sockets.Server_SO_SNDBUF"))
		{
			ServerChatter.s_SO_SNDBUF_Option = FiddlerApplication.Prefs.GetInt32Pref("fiddler.network.sockets.Server_SO_SNDBUF", -1);
		}
		else if (oPCE.PrefName.OICEquals("fiddler.network.sockets.Server_SO_RCVBUF"))
		{
			ServerChatter.s_SO_RCVBUF_Option = FiddlerApplication.Prefs.GetInt32Pref("fiddler.network.sockets.Server_SO_RCVBUF", -1);
		}
		else if (oPCE.PrefName.OICEquals("fiddler.network.sockets.Client_SO_SNDBUF"))
		{
			ClientChatter.s_SO_SNDBUF_Option = FiddlerApplication.Prefs.GetInt32Pref("fiddler.network.sockets.Client_SO_SNDBUF", -1);
		}
		else if (oPCE.PrefName.OICEquals("fiddler.network.sockets.Client_SO_RCVBUF"))
		{
			ClientChatter.s_SO_RCVBUF_Option = FiddlerApplication.Prefs.GetInt32Pref("fiddler.network.sockets.Client_SO_RCVBUF", -1);
		}
		else if (oPCE.PrefName.OICEquals("fiddler.network.egress.ip"))
		{
			SetDefaultEgressEndPoint(oPCE.ValueString);
		}
		else if (oPCE.PrefName.OICEquals("fiddler.network.https.NoDecryptionHosts"))
		{
			CONFIG.SetNoDecryptList(oPCE.ValueString);
		}
		else if (oPCE.PrefName.OICEquals("fiddler.network.https.NoDecryptionHosts.Invert"))
		{
			CONFIG.SetNoDecryptListInvert(oPCE.ValueBool);
		}
		else
		{
			if (oPCE.PrefName.OICEquals("fiddler.network.https.DropSNIAlerts"))
			{
				ServerPipe._bEatTLSAlerts = oPCE.ValueBool;
			}
			if (oPCE.PrefName.OICEquals("fiddler.network.proxy.RegistrationHostName"))
			{
				CONFIG.sFiddlerListenHostPort = string.Format("{0}:{1}", FiddlerApplication.Prefs.GetStringPref("fiddler.network.proxy.RegistrationHostName", "127.0.0.1").ToLower(), CONFIG.ListenPort);
			}
		}
	}

	/// <summary>
	/// Called whenever Windows reports that the system's NetworkAddress has changed
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void NetworkChange_NetworkAddressChanged(object sender, EventArgs e)
	{
		try
		{
			DNSResolver.ClearCache();
			FiddlerApplication.Log.LogString("NetworkAddressChanged.");
			if (oAutoProxy != null)
			{
				oAutoProxy.iAutoProxySuccessCount = 0;
			}
			_DetermineGatewayIPEndPoints();
		}
		catch (Exception eX)
		{
			FiddlerApplication.Log.LogString(eX.ToString());
		}
	}

	/// <summary>
	/// Called by Windows whenever network availability goes up or down.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void NetworkChange_NetworkAvailabilityChanged(object sender, NetworkAvailabilityEventArgs e)
	{
		try
		{
			PurgeServerPipePool();
			FiddlerApplication.Log.LogFormat("fiddler.network.availability.change> Network Available: {0}", e.IsAvailable);
		}
		catch (Exception)
		{
		}
	}

	[CodeDescription("Send a custom request through the proxy, blocking until it completes (or aborts).")]
	public Session SendRequestAndWait(HTTPRequestHeaders oHeaders, byte[] arrRequestBodyBytes, StringDictionary oNewFlags, EventHandler<StateChangeEventArgs> onStateChange)
	{
		ManualResetEvent oMRE = new ManualResetEvent(initialState: false);
		EventHandler<StateChangeEventArgs> ehStateChange = delegate(object o, StateChangeEventArgs scea)
		{
			if (scea.newState >= SessionStates.Done)
			{
				FiddlerApplication.DebugSpew("SendRequestAndWait Session #{0} reached state {1}", (o as Session).id, scea.newState);
				oMRE.Set();
			}
			if (onStateChange != null)
			{
				onStateChange(o, scea);
			}
		};
		Session oNewSession = SendRequest(oHeaders, arrRequestBodyBytes, oNewFlags, ehStateChange);
		oMRE.WaitOne();
		return oNewSession;
	}

	/// <summary>
	/// Directly inject a session into the Fiddler pipeline, returning a reference to it.
	/// NOTE: This method will THROW any exceptions to its caller.
	/// </summary>
	/// <param name="oHeaders">HTTP Request Headers</param>
	/// <param name="arrRequestBodyBytes">HTTP Request body (or null)</param>
	/// <param name="oNewFlags">StringDictionary of Session Flags (or null)</param>
	/// <returns>The new Session</returns>
	[CodeDescription("Send a custom request through the proxy. Hook the OnStateChanged event of the returned Session to monitor progress")]
	public Session SendRequest(HTTPRequestHeaders oHeaders, byte[] arrRequestBodyBytes, StringDictionary oNewFlags)
	{
		return SendRequest(oHeaders, arrRequestBodyBytes, oNewFlags, null);
	}

	/// <summary>
	/// Directly inject a session into the Fiddler pipeline, returning a reference to it.
	/// NOTE: This method will THROW any exceptions to its caller.
	/// </summary>
	/// <param name="oHeaders">HTTP Request Headers</param>
	/// <param name="arrRequestBodyBytes">HTTP Request body (or null)</param>
	/// <param name="oNewFlags">StringDictionary of Session Flags (or null)</param>
	/// <param name="onStateChange">Event Handler to notify when the session changes state</param>
	/// <returns>The new Session</returns>
	[CodeDescription("Send a custom request through the proxy. Hook the OnStateChanged event of the returned Session to monitor progress")]
	public Session SendRequest(HTTPRequestHeaders oHeaders, byte[] arrRequestBodyBytes, StringDictionary oNewFlags, EventHandler<StateChangeEventArgs> onStateChange)
	{
		if (oHeaders.ExistsAndContains("Fiddler-Encoding", "base64"))
		{
			oHeaders.Remove("Fiddler-Encoding");
			if (!Utilities.IsNullOrEmpty(arrRequestBodyBytes))
			{
				arrRequestBodyBytes = Convert.FromBase64String(Encoding.ASCII.GetString(arrRequestBodyBytes));
				if (oNewFlags == null)
				{
					oNewFlags = new StringDictionary();
				}
				oNewFlags["x-Builder-FixContentLength"] = "CFE-required";
			}
		}
		if (oHeaders.Exists("Fiddler-Host"))
		{
			if (oNewFlags == null)
			{
				oNewFlags = new StringDictionary();
			}
			oNewFlags["x-OverrideHost"] = oHeaders["Fiddler-Host"];
			oNewFlags["X-IgnoreCertCNMismatch"] = "Overrode HOST";
			oHeaders.Remove("Fiddler-Host");
		}
		if (oNewFlags != null && oNewFlags.ContainsKey("x-Builder-FixContentLength"))
		{
			if (arrRequestBodyBytes != null && !oHeaders.ExistsAndContains("Transfer-Encoding", "chunked"))
			{
				if (!Utilities.HTTPMethodAllowsBody(oHeaders.HTTPMethod) && arrRequestBodyBytes.Length == 0)
				{
					oHeaders.Remove("Content-Length");
				}
				else
				{
					oHeaders["Content-Length"] = arrRequestBodyBytes.LongLength.ToString();
				}
			}
			else
			{
				oHeaders.Remove("Content-Length");
			}
		}
		Session newSession = new Session((HTTPRequestHeaders)oHeaders.Clone(), arrRequestBodyBytes);
		newSession.SetBitFlag(SessionFlags.RequestGeneratedByFiddler, b: true);
		if (onStateChange != null)
		{
			newSession.OnStateChanged += onStateChange;
		}
		if (oNewFlags != null && oNewFlags.Count > 0)
		{
			foreach (DictionaryEntry oDE in oNewFlags)
			{
				newSession.oFlags[(string)oDE.Key] = oNewFlags[(string)oDE.Key];
			}
		}
		if (newSession.oFlags.ContainsKey("x-AutoAuth"))
		{
			string sAuthHeader = newSession.oRequest.headers["Authorization"];
			if (sAuthHeader.OICContains("NTLM") || sAuthHeader.OICContains("Negotiate") || sAuthHeader.OICContains("Digest"))
			{
				newSession.oRequest.headers.Remove("Authorization");
			}
			sAuthHeader = newSession.oRequest.headers["Proxy-Authorization"];
			if (sAuthHeader.OICContains("NTLM") || sAuthHeader.OICContains("Negotiate") || sAuthHeader.OICContains("Digest"))
			{
				newSession.oRequest.headers.Remove("Proxy-Authorization");
			}
		}
		newSession.ExecuteOnThreadPool();
		return newSession;
	}

	/// <summary>
	/// Directly inject a session into the Fiddler pipeline, returning a reference to it.
	/// NOTE: This method will THROW any exceptions to its caller.
	/// </summary>
	/// <param name="sRequest">String representing the HTTP request. If headers only, be sure to end with CRLFCRLF</param>
	/// <param name="oNewFlags">StringDictionary of Session Flags (or null)</param>
	/// <returns>The new session</returns>
	public Session SendRequest(string sRequest, StringDictionary oNewFlags)
	{
		byte[] arrBytes = CONFIG.oHeaderEncoding.GetBytes(sRequest);
		if (!Parser.FindEntityBodyOffsetFromArray(arrBytes, out var iHeaderLen, out var iOffset, out var _))
		{
			throw new ArgumentException("sRequest did not represent a valid HTTP request", "sRequest");
		}
		string sHeaders = CONFIG.oHeaderEncoding.GetString(arrBytes, 0, iHeaderLen) + "\r\n\r\n";
		HTTPRequestHeaders oRH = new HTTPRequestHeaders();
		if (!oRH.AssignFromString(sHeaders))
		{
			throw new ArgumentException("sRequest did not contain valid HTTP headers", "sRequest");
		}
		byte[] arrBody;
		if (1 > arrBytes.Length - iOffset)
		{
			arrBody = Utilities.emptyByteArray;
		}
		else
		{
			arrBody = new byte[arrBytes.Length - iOffset];
			Buffer.BlockCopy(arrBytes, iOffset, arrBody, 0, arrBody.Length);
		}
		return SendRequest(oRH, arrBody, oNewFlags, null);
	}

	[Obsolete("This overload of InjectCustomRequest is obsolete. Use a different version.", true)]
	public void InjectCustomRequest(HTTPRequestHeaders oHeaders, byte[] arrRequestBodyBytes, bool bRunRequestRules, bool bViewResult)
	{
		StringDictionary oSD = new StringDictionary();
		oSD["x-From-Builder"] = "true";
		if (bViewResult)
		{
			oSD["x-Builder-Inspect"] = "1";
		}
		InjectCustomRequest(oHeaders, arrRequestBodyBytes, oSD);
	}

	/// <summary>
	/// [DEPRECATED] Directly inject a session into the Fiddler pipeline.
	/// NOTE: This method will THROW any exceptions to its caller.
	/// </summary>
	/// <see cref="M:Fiddler.Proxy.SendRequest(Fiddler.HTTPRequestHeaders,System.Byte[],System.Collections.Specialized.StringDictionary)" />
	/// <param name="oHeaders">HTTP Request Headers</param>
	/// <param name="arrRequestBodyBytes">HTTP Request body (or null)</param>
	/// <param name="oNewFlags">StringDictionary of Session Flags (or null)</param>
	public void InjectCustomRequest(HTTPRequestHeaders oHeaders, byte[] arrRequestBodyBytes, StringDictionary oNewFlags)
	{
		SendRequest(oHeaders, arrRequestBodyBytes, oNewFlags);
	}

	/// <summary>
	/// [DEPRECATED] Directly inject a session into the Fiddler pipeline.
	/// NOTE: This method will THROW any exceptions to its caller.
	/// </summary>
	/// <see cref="M:Fiddler.Proxy.SendRequest(System.String,System.Collections.Specialized.StringDictionary)" />
	/// <param name="sRequest">String representing the HTTP request. If headers only, be sure to end with CRLFCRLF</param>
	/// <param name="oNewFlags">StringDictionary of Session Flags (or null)</param>
	public void InjectCustomRequest(string sRequest, StringDictionary oNewFlags)
	{
		SendRequest(sRequest, oNewFlags);
	}

	/// <summary>
	/// [DEPRECATED]: This version does no validation of the request data, and doesn't set SessionFlags.RequestGeneratedByFiddler
	/// Send a custom HTTP request to Fiddler's listening endpoint (127.0.0.1:8888 by default).
	/// NOTE: This method will THROW any exceptions to its caller and blocks the current thread.
	/// </summary>
	/// <see cref="M:Fiddler.Proxy.SendRequest(System.String,System.Collections.Specialized.StringDictionary)" />
	/// <param name="sRequest">String representing the HTTP request. If headers only, be sure to end with CRLFCRLF</param>
	public void InjectCustomRequest(string sRequest)
	{
		if (oAcceptor == null)
		{
			InjectCustomRequest(sRequest, null);
			return;
		}
		Socket oInjector = new Socket(IPAddress.Loopback.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
		oInjector.Connect(new IPEndPoint(IPAddress.Loopback, CONFIG.ListenPort));
		oInjector.Send(Encoding.UTF8.GetBytes(sRequest));
		oInjector.Shutdown(SocketShutdown.Both);
		oInjector.Close();
	}

	/// <summary>
	/// This function, when given a scheme host[:port], returns the gateway information of the proxy to forward requests to.
	/// </summary>
	/// <param name="sURIScheme">URIScheme: use http, https, or ftp</param>
	/// <param name="sHostAndPort">Host for which to return gateway information</param>
	/// <returns>IPEndPoint of gateway to use, or NULL</returns>
	public IPEndPoint FindGatewayForOrigin(string sURIScheme, string sHostAndPort)
	{
		if (string.IsNullOrEmpty(sURIScheme))
		{
			return null;
		}
		if (string.IsNullOrEmpty(sHostAndPort))
		{
			return null;
		}
		if (CONFIG.UpstreamGateway == GatewayType.None)
		{
			return null;
		}
		if (Utilities.isLocalhost(sHostAndPort))
		{
			return null;
		}
		if (sURIScheme.OICEquals("http") && sHostAndPort.EndsWith(":80", StringComparison.Ordinal))
		{
			sHostAndPort = sHostAndPort.Substring(0, sHostAndPort.Length - 3);
		}
		else if (sURIScheme.OICEquals("https") && sHostAndPort.EndsWith(":443", StringComparison.Ordinal))
		{
			sHostAndPort = sHostAndPort.Substring(0, sHostAndPort.Length - 4);
		}
		else if (sURIScheme.OICEquals("ftp") && sHostAndPort.EndsWith(":21", StringComparison.Ordinal))
		{
			sHostAndPort = sHostAndPort.Substring(0, sHostAndPort.Length - 3);
		}
		AutoProxy myAutoProxy = oAutoProxy;
		if (myAutoProxy != null && myAutoProxy.iAutoProxySuccessCount > -1)
		{
			if (myAutoProxy.GetAutoProxyForUrl(sURIScheme + "://" + sHostAndPort + "/", out var _ipepResult))
			{
				myAutoProxy.iAutoProxySuccessCount = 1;
				return _ipepResult;
			}
			if (myAutoProxy.iAutoProxySuccessCount == 0 && !FiddlerApplication.Prefs.GetBoolPref("fiddler.network.gateway.UseFailedAutoProxy", bDefault: false))
			{
				FiddlerApplication.Log.LogString("AutoProxy failed. Disabling for this network.");
				myAutoProxy.iAutoProxySuccessCount = -1;
			}
		}
		ProxyBypassList myBypassList = oBypassList;
		if (myBypassList != null && myBypassList.IsBypass(sURIScheme, sHostAndPort))
		{
			return null;
		}
		if (sURIScheme.OICEquals("http"))
		{
			return _ipepHttpGateway;
		}
		if (sURIScheme.OICEquals("https"))
		{
			return _ipepHttpsGateway;
		}
		if (sURIScheme.OICEquals("ftp"))
		{
			return _ipepFtpGateway;
		}
		return null;
	}

	/// <summary>
	/// Accept the connection and pass it off to a handler thread
	/// </summary>
	/// <param name="ar"></param>
	private void AcceptConnection(IAsyncResult ar)
	{
		try
		{
			ProxyExecuteParams oParams = new ProxyExecuteParams(oAcceptor.EndAccept(ar), _oHTTPSCertificate);
			ThreadPool.UnsafeQueueUserWorkItem(Session.CreateAndExecute, oParams);
		}
		catch (ObjectDisposedException exODE)
		{
			FiddlerApplication.Log.LogFormat("!ERROR - Fiddler Acceptor failed to AcceptConnection: {0}", FiddlerCore.Utilities.Utilities.DescribeException(exODE));
			return;
		}
		catch (Exception e2)
		{
			FiddlerApplication.Log.LogFormat("!WARNING - Fiddler Acceptor failed to AcceptConnection: {0}", FiddlerCore.Utilities.Utilities.DescribeException(e2));
		}
		try
		{
			oAcceptor.BeginAccept(AcceptConnection, null);
		}
		catch (Exception e)
		{
			FiddlerApplication.Log.LogFormat("!ERROR - Fiddler Acceptor failed to call BeginAccept: {0}", FiddlerCore.Utilities.Utilities.DescribeException(e));
		}
	}

	/// <summary>
	/// Register as the system proxy for WinINET and set the Dynamic registry key for other FiddlerHook
	/// </summary>
	/// <returns>True if the proxy registration was successful</returns>
	[Obsolete("Use Telerik.NetworkConnections.NetworkConnectionsManager.GetCurrentProxySettingsForConnection(*)/SetProxySettingsForConnections(*) to manipulate current proxy settings.")]
	public bool Attach()
	{
		return Attach(bCollectGWInfo: false);
	}

	/// <summary>
	/// If we get a notice that the proxy registry key has changed, wait 50ms and then check to see
	/// if the key is pointed at us. If not, raise the alarm.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	[Obsolete]
	private void ProxyRegistryKeysChanged(object sender, EventArgs e)
	{
		if (_bIsAttached && !_bDetaching && FiddlerApplication.Prefs.GetBoolPref("fiddler.proxy.WatchRegistry", bDefault: true))
		{
			ScheduledTasks.ScheduleWork("VerifyAttached", 50u, VerifyAttached);
		}
	}

	/// <summary>
	/// If we are supposed to be "attached", we re-verify the registry keys, and if they are corrupt, notify
	/// our host of the discrepency.
	/// </summary>
	[Obsolete]
	internal void VerifyAttached()
	{
		FiddlerApplication.Log.LogString("WinINET Registry change detected. Verifying proxy keys are intact...");
		bool bRegistryOk = true;
		try
		{
			if (oAllConnectoids != null)
			{
				bRegistryOk = !oAllConnectoids.MarkUnhookedConnections(fiddlerProxySettings);
				if (!bRegistryOk)
				{
					FiddlerApplication.Log.LogString("WinINET API indicates that Fiddler is no longer attached.");
				}
			}
		}
		catch (Exception)
		{
		}
		if (bRegistryOk)
		{
			using RegistryKey oReg = Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", writable: false);
			if (oReg != null)
			{
				if (1 != Utilities.GetRegistryInt(oReg, "ProxyEnable", 0))
				{
					bRegistryOk = false;
				}
				string sProxy = oReg.GetValue("ProxyServer") as string;
				if (string.IsNullOrEmpty(sProxy))
				{
					bRegistryOk = false;
				}
				else
				{
					if (!sProxy.OICEquals(CONFIG.sFiddlerListenHostPort) && !sProxy.OICContains("http=" + CONFIG.sFiddlerListenHostPort))
					{
						bRegistryOk = false;
						FiddlerApplication.Log.LogFormat("WinINET Registry had config: '{0}'", sProxy);
					}
					if (bRegistryOk)
					{
						string sProxyURL = oReg.GetValue("AutoConfigURL") as string;
						if (!string.IsNullOrEmpty(sProxyURL))
						{
							bRegistryOk = sProxyURL.OICContains(_GetPACScriptURL());
							if (!bRegistryOk)
							{
								FiddlerApplication.Log.LogFormat("WinINET Registry had config: 'URL={0}'", sProxyURL);
							}
						}
					}
				}
			}
		}
		if (!bRegistryOk)
		{
			OnDetachedUnexpectedly();
		}
	}

	[Obsolete]
	internal bool Attach(bool bCollectGWInfo)
	{
		//IL_0167: Unknown result type (might be due to invalid IL or missing references)
		//IL_0171: Expected O, but got Unknown
		if (_bIsAttached)
		{
			return true;
		}
		if (CONFIG.bIsViewOnly)
		{
			return false;
		}
		if (bCollectGWInfo)
		{
			CollectConnectoidAndGatewayInfo(shouldRefreshUpstreamGatewayInfo: true);
		}
		string fiddlerHostname = FiddlerApplication.Prefs.GetStringPref("fiddler.network.proxy.RegistrationHostName", "127.0.0.1");
		bool useUpstreamSettings = bCollectGWInfo && (CONFIG.UpstreamGateway == GatewayType.System || CONFIG.UpstreamGateway == GatewayType.Manual);
		fiddlerProxySettings = new ProxySettings(false, CONFIG.HookWithPAC, CONFIG.HookWithPAC ? _GetPACScriptURL() : null, CONFIG.sHostsThatBypassFiddler, true, fiddlerHostname, (ushort)CONFIG.ListenPort, CONFIG.bCaptureCONNECT || (useUpstreamSettings && upstreamProxySettings.HttpsProxyEnabled), CONFIG.bCaptureCONNECT ? fiddlerHostname : (useUpstreamSettings ? upstreamProxySettings.HttpsProxyHost : null), (ushort)(CONFIG.bCaptureCONNECT ? CONFIG.ListenPort : (useUpstreamSettings ? upstreamProxySettings.HttpsProxyPort : 0)), CONFIG.CaptureFTP || (useUpstreamSettings && upstreamProxySettings.FtpProxyEnabled), CONFIG.CaptureFTP ? fiddlerHostname : (useUpstreamSettings ? upstreamProxySettings.FtpProxyHost : null), (ushort)(CONFIG.CaptureFTP ? CONFIG.ListenPort : (useUpstreamSettings ? upstreamProxySettings.FtpProxyPort : 0)), useUpstreamSettings && upstreamProxySettings.SocksProxyEnabled, useUpstreamSettings ? upstreamProxySettings.SocksProxyHost : null, (ushort)(useUpstreamSettings ? upstreamProxySettings.SocksProxyPort : 0));
		if (!bCollectGWInfo)
		{
			CollectConnectoidAndGatewayInfo(shouldRefreshUpstreamGatewayInfo: true);
		}
		if (oAllConnectoids.HookConnections(fiddlerProxySettings))
		{
			_bIsAttached = true;
			FiddlerApplication.OnFiddlerAttach();
			if (FiddlerApplication.Prefs.GetBoolPref("fiddler.proxy.WatchRegistry", bDefault: true) && connectionsManager != null)
			{
				connectionsManager.ProxySettingsChanged += ProxyRegistryKeysChanged;
			}
			return true;
		}
		FiddlerApplication.Log.LogString("Error: Failed to register Fiddler as the system proxy.");
		return false;
	}

	private static string _GetPACScriptURL()
	{
		if (FiddlerApplication.Prefs.GetBoolPref("fiddler.proxy.pacfile.usefileprotocol", bDefault: true))
		{
			return "file://" + CONFIG.GetPath("Pac");
		}
		return "http://" + CONFIG.sFiddlerListenHostPort + "/proxy.pac";
	}

	/// <summary>
	/// This method sets up the connectoid list and updates gateway information. Called by the Attach() method, or 
	/// called on startup if Fiddler isn't configured to attach automatically.
	/// </summary>
	[Obsolete]
	internal void CollectConnectoidAndGatewayInfo(bool shouldRefreshUpstreamGatewayInfo)
	{
		try
		{
			oAllConnectoids = new Connectoids(connectionsManager);
			if (shouldRefreshUpstreamGatewayInfo)
			{
				RefreshUpstreamGatewayInformation();
			}
		}
		catch (Exception eX)
		{
			FiddlerApplication.Log.LogString(eX.ToString());
		}
	}

	/// <summary>
	/// Given an address list, walks the list until it's able to successfully make a connection.
	/// Used for finding an available Gateway when we have a list to choose from
	/// </summary>
	/// <param name="sHostPortList">A string, e.g. PROXY1:80</param>
	/// <returns>The IP:Port of the first alive endpoint for the specified host/port</returns>
	private static IPEndPoint GetFirstRespondingEndpoint(string sHostPortList)
	{
		if (Utilities.IsNullOrWhiteSpace(sHostPortList))
		{
			return null;
		}
		sHostPortList = Utilities.TrimAfter(sHostPortList, ';');
		IPEndPoint ipepResult = null;
		int iGatewayPort = 80;
		Utilities.CrackHostAndPort(sHostPortList, out var sGatewayHost, ref iGatewayPort);
		IPAddress[] arrGatewayIPs;
		try
		{
			arrGatewayIPs = DNSResolver.GetIPAddressList(sGatewayHost, bCheckCache: true, null);
		}
		catch
		{
			FiddlerApplication.Log.LogFormat("fiddler.network.gateway> Unable to resolve upstream proxy '{0}'... ignoring.", sGatewayHost);
			return null;
		}
		try
		{
			IPAddress[] array = arrGatewayIPs;
			foreach (IPAddress addrCandidate in array)
			{
				try
				{
					using Socket oSocket = new Socket(addrCandidate.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
					oSocket.NoDelay = true;
					if (FiddlerApplication.oProxy._DefaultEgressEndPoint != null)
					{
						oSocket.Bind(FiddlerApplication.oProxy._DefaultEgressEndPoint);
					}
					oSocket.Connect(addrCandidate, iGatewayPort);
					ipepResult = new IPEndPoint(addrCandidate, iGatewayPort);
				}
				catch (Exception eX2)
				{
					if (!FiddlerApplication.Prefs.GetBoolPref("fiddler.network.dns.fallback", bDefault: true))
					{
						break;
					}
					FiddlerApplication.Log.LogFormat("fiddler.network.gateway.connect>Connection to {0} failed. {1}. Will try DNS Failover if available.", addrCandidate.ToString(), eX2.Message);
					continue;
				}
				break;
			}
			return ipepResult;
		}
		catch (Exception)
		{
			return null;
		}
	}

	/// <summary>
	/// Set internal fields pointing at upstream proxies.
	/// </summary>
	private void _DetermineGatewayIPEndPoints()
	{
		if ((ProxySettings)null == upstreamProxySettings)
		{
			return;
		}
		if (upstreamProxySettings.HttpProxyEnabled)
		{
			_ipepHttpGateway = GetFirstRespondingEndpoint($"{upstreamProxySettings.HttpProxyHost}:{upstreamProxySettings.HttpProxyPort}");
		}
		if (upstreamProxySettings.HttpsProxyEnabled)
		{
			if ($"{upstreamProxySettings.HttpsProxyHost}:{upstreamProxySettings.HttpsProxyPort}" == $"{upstreamProxySettings.HttpProxyHost}:{upstreamProxySettings.HttpProxyPort}")
			{
				_ipepHttpsGateway = _ipepHttpGateway;
			}
			else
			{
				_ipepHttpsGateway = GetFirstRespondingEndpoint($"{upstreamProxySettings.HttpsProxyHost}:{upstreamProxySettings.HttpsProxyPort}");
			}
		}
		if (upstreamProxySettings.FtpProxyEnabled)
		{
			if ($"{upstreamProxySettings.FtpProxyHost}:{upstreamProxySettings.FtpProxyPort}" == $"{upstreamProxySettings.HttpProxyHost}:{upstreamProxySettings.HttpProxyPort}")
			{
				_ipepFtpGateway = _ipepHttpGateway;
			}
			else
			{
				_ipepFtpGateway = GetFirstRespondingEndpoint($"{upstreamProxySettings.FtpProxyHost}:{upstreamProxySettings.FtpProxyPort}");
			}
		}
		if (!string.IsNullOrEmpty(upstreamProxySettings.BypassHosts))
		{
			oBypassList = new ProxyBypassList(upstreamProxySettings.BypassHosts);
			if (!oBypassList.HasEntries)
			{
				oBypassList = null;
			}
		}
	}

	/// <summary>
	/// Detach the proxy by setting the registry keys and sending a Windows Message
	/// </summary>
	/// <returns>True if the proxy settings were successfully detached</returns>
	[Obsolete("Use Telerik.NetworkConnections.NetworkConnectionsManager.GetCurrentProxySettingsForConnection(*)/SetProxySettingsForConnections(*) to manipulate current proxy settings.")]
	public bool Detach()
	{
		return Detach(bSkipVerifyAttached: false);
	}

	/// <summary>
	/// Detach the proxy by setting the registry keys and sending a Windows Message
	/// </summary>
	/// <returns>True if the proxy settings were successfully detached</returns>
	[Obsolete]
	internal bool Detach(bool bSkipVerifyAttached)
	{
		if (!bSkipVerifyAttached && !_bIsAttached)
		{
			return true;
		}
		if (CONFIG.bIsViewOnly)
		{
			return true;
		}
		try
		{
			_bDetaching = true;
			if (!oAllConnectoids.UnhookAllConnections())
			{
				return false;
			}
			_bIsAttached = false;
			FiddlerApplication.OnFiddlerDetach();
		}
		finally
		{
			_bDetaching = false;
		}
		return true;
	}

	internal string _GetUpstreamPACScriptText()
	{
		return sUpstreamPACScript;
	}

	internal string _GetPACScriptText()
	{
		string sJSFindProxyForURLBody = FiddlerApplication.Prefs.GetStringPref("fiddler.proxy.pacfile.text", "return 'PROXY " + CONFIG.sFiddlerListenHostPort + "';");
		return "// Autogenerated file; do not edit. Rewritten on attach and detach of Fiddler.\r\n\r\nfunction FindProxyForURL(url, host){\r\n  " + sJSFindProxyForURLBody + "\r\n}";
	}

	/// <summary>
	/// Stop the proxy by closing the socket.
	/// </summary>
	internal void Stop()
	{
		if (oAcceptor == null)
		{
			return;
		}
		try
		{
			oAcceptor.LingerState = new LingerOption(enable: true, 0);
			oAcceptor.Close();
		}
		catch (Exception eX)
		{
			FiddlerApplication.DebugSpew("oProxy.Dispose threw an exception: " + eX.Message);
		}
	}

	/// <summary>
	/// Start the proxy by binding to the local port and accepting connections
	/// </summary>
	/// <param name="iPort">Port to listen on</param>
	/// <param name="bAllowRemote">TRUE to allow remote connections</param>
	/// <returns></returns>
	internal bool Start(int iPort, bool bAllowRemote)
	{
		bool bBindIPv6 = false;
		try
		{
			bBindIPv6 = bAllowRemote && CONFIG.EnableIPv6 && Socket.OSSupportsIPv6;
		}
		catch (Exception eX3)
		{
			if (eX3 is ConfigurationErrorsException)
			{
				string title = ".NET Configuration Error";
				string message2 = "A Microsoft .NET configuration file (listed below) is corrupt and contains invalid data. You can often correct this error by installing updates from WindowsUpdate and/or reinstalling the .NET Framework.\n\n" + eX3.Message + "\nSource: " + eX3.Source + "\n" + eX3.StackTrace + "\n\n" + eX3.InnerException?.ToString() + "\nFiddler v" + Utilities.ThisAssemblyVersion?.ToString() + ((8 == IntPtr.Size) ? " (x64) " : " (x86) ") + " [.NET " + Environment.Version?.ToString() + " on " + Environment.OSVersion.VersionString + "] ";
				FiddlerApplication.Log.LogFormat("{0}: {1}", title, message2);
				oAcceptor = null;
				return false;
			}
		}
		string sProcessListeningOnPort = FiddlerSock.GetListeningProcess(iPort);
		try
		{
			if (bBindIPv6)
			{
				oAcceptor = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
				if (Environment.OSVersion.Version.Major > 5)
				{
					oAcceptor.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, 0);
				}
			}
			else
			{
				oAcceptor = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
			}
			if (CONFIG.ForceExclusivePort)
			{
				oAcceptor.ExclusiveAddressUse = true;
			}
			try
			{
				if (!string.IsNullOrEmpty(sProcessListeningOnPort))
				{
					FiddlerApplication.Log.LogFormat("! WARNING: Port {0} is already in use (for at least some IP addresses) by '{1}'", iPort, sProcessListeningOnPort);
				}
				oAcceptor.Bind(new IPEndPoint((!bAllowRemote) ? IPAddress.Loopback : (bBindIPv6 ? IPAddress.IPv6Any : IPAddress.Any), iPort));
			}
			catch (SocketException)
			{
			}
			oAcceptor.Listen(50);
		}
		catch (SocketException eXS2)
		{
			string sSpecificErrorString = string.Empty;
			string sSpecificErrorTitle = "Fiddler Cannot Listen";
			switch (eXS2.ErrorCode)
			{
			case 10013:
			case 10048:
			{
				string sProcess = sProcessListeningOnPort;
				sSpecificErrorString = string.Format(arg1: (!string.IsNullOrEmpty(sProcess)) ? ("the process is '" + sProcess + "'.") : "use NETSTAT -AB at a command prompt to identify it.", format: "Another service is using port {0}; {1}\n\n{2}", arg0: iPort, arg2: string.Empty);
				sSpecificErrorTitle = "Port in Use";
				break;
			}
			case 10047:
			case 10049:
				if (bBindIPv6)
				{
					sSpecificErrorString = "An unsupported option was used. This often means that you've enabled IPv6 support inside Tools > Options, but your computer has IPv6 disabled.";
				}
				break;
			}
			oAcceptor = null;
			if (!string.IsNullOrEmpty(sSpecificErrorString))
			{
				sSpecificErrorString += "\n\n";
			}
			string message = string.Format("{2}Unable to bind to port [{0}]. ErrorCode: {1}.\n{3}\n\n{4}", iPort, eXS2.ErrorCode, sSpecificErrorString, eXS2.ToString(), "Fiddler v" + Utilities.ThisAssemblyVersion?.ToString() + " [.NET " + Environment.Version?.ToString() + " on " + Environment.OSVersion.VersionString + "]");
			FiddlerApplication.Log.LogFormat("{0}: {1}", sSpecificErrorTitle, message);
			return false;
		}
		catch (Exception eX2)
		{
			oAcceptor = null;
			FiddlerApplication.Log.LogString(eX2.ToString());
			return false;
		}
		try
		{
			oAcceptor.BeginAccept(AcceptConnection, null);
		}
		catch (Exception eX)
		{
			oAcceptor = null;
			FiddlerApplication.Log.LogFormat("Fiddler BeginAccept() Exception: {0}", eX.Message);
			return false;
		}
		return true;
	}

	/// <summary>
	/// Dispose Fiddler's listening socket
	/// </summary>
	public void Dispose()
	{
		NetworkChange.NetworkAvailabilityChanged -= NetworkChange_NetworkAvailabilityChanged;
		NetworkChange.NetworkAddressChanged -= NetworkChange_NetworkAddressChanged;
		if (watcherPrefNotify.HasValue)
		{
			FiddlerApplication.Prefs.RemoveWatcher(watcherPrefNotify.Value);
		}
		if (connectionsManager != null)
		{
			connectionsManager.ProxySettingsChanged -= ProxyRegistryKeysChanged;
		}
		Stop();
		if (oAutoProxy != null)
		{
			oAutoProxy.Dispose();
			oAutoProxy = null;
		}
	}

	/// <summary>
	/// Clear the pool of Server Pipes. May be called by extensions.
	/// </summary>
	public void PurgeServerPipePool()
	{
		htServerPipePool.Clear();
	}

	/// <summary>
	/// Assign HTTPS Certificate for this endpoint
	/// </summary>
	/// <param name="certHTTPS">Certificate to return to clients who connect</param>
	public void AssignEndpointCertificate(X509Certificate2 certHTTPS)
	{
		_oHTTPSCertificate = certHTTPS;
		if (certHTTPS != null)
		{
			_sHTTPSHostname = certHTTPS.Subject;
		}
		else
		{
			_sHTTPSHostname = null;
		}
	}

	internal void RefreshUpstreamGatewayInformation()
	{
		//IL_0191: Unknown result type (might be due to invalid IL or missing references)
		//IL_0198: Expected O, but got Unknown
		_ipepFtpGateway = (_ipepHttpGateway = (_ipepHttpsGateway = null));
		upstreamProxySettings = null;
		oBypassList = null;
		if (oAutoProxy != null)
		{
			oAutoProxy.Dispose();
			oAutoProxy = null;
		}
		switch (CONFIG.UpstreamGateway)
		{
		case GatewayType.None:
			FiddlerApplication.Log.LogString("Setting upstream gateway to none");
			break;
		case GatewayType.WPAD:
			FiddlerApplication.Log.LogString("Setting upstream gateway to WPAD");
			oAutoProxy = new AutoProxy(bAutoDiscover: true, null);
			break;
		case GatewayType.System:
		{
			ProxySettings proxySettings2 = FiddlerApplication.oProxy.oAllConnectoids.GetDefaultConnectionGatewayInfo(CONFIG.sHookConnectionNamespace, CONFIG.sHookConnectionNamed);
			AssignGateway(proxySettings2);
			break;
		}
		case GatewayType.Manual:
		{
			string proxyServerString = FiddlerApplication.Prefs.GetStringPref("fiddler.network.gateway.proxies", string.Empty);
			ProxySettings proxySettings = new ProxySettings(false, false, string.Empty, FiddlerApplication.Prefs.GetStringPref("fiddler.network.gateway.exceptions", string.Empty), GetProtocolProxyEnabled("http", proxyServerString), GetProtocolProxyHost("http", proxyServerString), GetProtocolProxyPort("http", proxyServerString), GetProtocolProxyEnabled("https", proxyServerString), GetProtocolProxyHost("https", proxyServerString), GetProtocolProxyPort("https", proxyServerString), GetProtocolProxyEnabled("ftp", proxyServerString), GetProtocolProxyHost("ftp", proxyServerString), GetProtocolProxyPort("ftp", proxyServerString), GetProtocolProxyEnabled("socks", proxyServerString), GetProtocolProxyHost("socks", proxyServerString), GetProtocolProxyPort("socks", proxyServerString));
			AssignGateway(proxySettings);
			break;
		}
		}
	}

	private static bool GetProtocolProxyEnabled(string protocol, string proxyServerString)
	{
		string protocolProxyListing = GetProtocolProxyListing(protocol, proxyServerString);
		if (string.IsNullOrEmpty(protocolProxyListing))
		{
			return false;
		}
		return true;
	}

	private static string GetProtocolProxyHost(string protocol, string proxyServerString)
	{
		string protocolProxyListing = GetProtocolProxyListing(protocol, proxyServerString);
		if (string.IsNullOrEmpty(protocolProxyListing))
		{
			return null;
		}
		string protocolProxyHostWithPort = protocolProxyListing.Replace(protocol + "=", string.Empty);
		return PortRegex.Replace(protocolProxyHostWithPort, string.Empty);
	}

	private static ushort GetProtocolProxyPort(string protocol, string proxyServerString)
	{
		string protocolProxyListing = GetProtocolProxyListing(protocol, proxyServerString);
		if (string.IsNullOrEmpty(protocolProxyListing))
		{
			return 0;
		}
		Match portMatch = PortRegex.Match(protocolProxyListing);
		if (portMatch.Success)
		{
			ushort.TryParse(portMatch.Result("$1"), out var port);
			return port;
		}
		return protocol switch
		{
			"http" => 80, 
			"https" => 443, 
			"ftp" => 21, 
			"socks" => 1080, 
			_ => 0, 
		};
	}

	private static string GetProtocolProxyListing(string protocol, string proxyServerString)
	{
		if (string.IsNullOrWhiteSpace(proxyServerString))
		{
			return null;
		}
		return (from psl in proxyServerString.Split(new char[2] { ';', ' ' }, StringSplitOptions.RemoveEmptyEntries)
			select psl.Trim() into psl
			orderby Enumerable.Contains(psl, '=') descending
			select psl).FirstOrDefault((string psl) => !Enumerable.Contains(psl, '=') || psl.StartsWith(protocol + "="));
	}

	/// <summary>
	/// Sets the upstream gateway to match the specified ProxySettings
	/// </summary>
	/// <param name="upstreamProxySettings"></param>
	private void AssignGateway(ProxySettings upstreamProxySettings)
	{
		//IL_000e: Unknown result type (might be due to invalid IL or missing references)
		//IL_0018: Expected O, but got Unknown
		if (upstreamProxySettings == (ProxySettings)null)
		{
			this.upstreamProxySettings = new ProxySettings();
		}
		else
		{
			this.upstreamProxySettings = upstreamProxySettings;
			if (this.upstreamProxySettings.UseWebProxyAutoDiscovery || (this.upstreamProxySettings.ProxyAutoConfigEnabled && !string.IsNullOrWhiteSpace(this.upstreamProxySettings.ProxyAutoConfigUrl)))
			{
				oAutoProxy = new AutoProxy(this.upstreamProxySettings.UseWebProxyAutoDiscovery, this.upstreamProxySettings.ProxyAutoConfigUrl);
			}
		}
		_DetermineGatewayIPEndPoints();
	}

	/// <summary>
	/// Generate or find a certificate for this endpoint
	/// </summary>
	/// <param name="sHTTPSHostname">Subject FQDN</param>
	/// <returns>TRUE if the certificate could be found/generated, false otherwise</returns>
	internal bool ActAsHTTPSEndpointForHostname(string sHTTPSHostname)
	{
		try
		{
			if (string.IsNullOrEmpty(sHTTPSHostname))
			{
				throw new ArgumentException();
			}
			_oHTTPSCertificate = CertMaker.FindCert(sHTTPSHostname);
			_sHTTPSHostname = _oHTTPSCertificate.Subject;
			return true;
		}
		catch (Exception)
		{
			_oHTTPSCertificate = null;
			_sHTTPSHostname = null;
		}
		return false;
	}

	/// <summary>
	/// Return a simple string indicating what upstream proxy/gateway is in use.
	/// </summary>
	/// <returns></returns>
	internal string GetGatewayInformation()
	{
		if (FiddlerApplication.oProxy.oAutoProxy != null)
		{
			return $"Gateway: Auto-Config\n{FiddlerApplication.oProxy.oAutoProxy.ToString()}";
		}
		IPEndPoint ipepGateway = FindGatewayForOrigin("http", "fiddler2.com");
		if (ipepGateway != null)
		{
			return $"Gateway: {ipepGateway.Address.ToString()}:{ipepGateway.Port.ToString()}\n";
		}
		return $"Gateway: No Gateway\n";
	}
}
