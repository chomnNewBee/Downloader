using System;
using System.ComponentModel;
using System.IO;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Text;
using FiddlerCore.Utilities;

namespace Fiddler;

/// <summary>
/// The CONFIG object is Fiddler's legacy settings object, introduced before the advent of the Preferences system.
/// </summary>
public static class CONFIG
{
	/// <summary>
	/// Underlying Preferences container whose IFiddlerPreferences interface is 
	/// exposed by the FiddlerApplication.Prefs property.
	/// </summary>
	private static PreferenceBag _Prefs;

	/// <summary>
	/// Response files larger than this (2^28 = ~262mb) will NOT be loaded into memory when using LoadResponseFromFile
	/// </summary>
	internal static int _cb_STREAM_LARGE_FILES;

	internal static int cbAutoStreamAndForget;

	internal static string sDefaultBrowserExe;

	internal static string sDefaultBrowserParams;

	internal static bool bRunningOnCLRv4;

	private static ProcessFilterCategories _pfcDecyptFilter;

	/// <summary>
	/// Cached layout info for columns.
	/// </summary>
	private static string sLVColInfo;

	internal static bool bReloadSessionIDAsFlag;

	/// <summary>
	/// True if this is a "Viewer" instance of Fiddler that will not persist its settings. Exposed as FiddlerApplication.IsViewerMode
	/// </summary>
	/// <remarks>
	/// TODO: ARCH: This setting shouldn't exist in FiddlerCore, but it's used in a dozen places</remarks>
	internal static bool bIsViewOnly;

	/// <summary>
	/// TODO: Why is this defaulted to FALSE? Has been since 2009, probably due to some bug. Should keep better records. (Sigh).
	/// </summary>
	internal static bool bUseXceedDecompressForGZIP;

	internal static bool bUseXceedDecompressForDeflate;

	/// <summary>
	/// Boolean controls whether Fiddler should map inbound connections to their original process using IPHLPAPI
	/// </summary>
	public static bool bMapSocketToProcess;

	[Obsolete("Please, use the 'DecryptHTTPS' property instead.")]
	public static bool bMITM_HTTPS;

	/// <summary>
	/// Boolean controls whether Fiddler will attempt to use the Server Name Indicator TLS extension to generate the SubjectCN for certificates
	/// </summary>
	public static bool bUseSNIForCN;

	private static bool bIgnoreServerCertErrors;

	[Obsolete("Please, use 'StreamAudioVideo' property instead.")]
	public static bool bStreamAudioVideo;

	internal static bool bCheckCompressionIntegrity;

	internal static bool bShowDefaultClientCertificateNeededPrompt;

	/// <summary>
	/// Returns 127.0.0.1:{ListenPort} or fiddler.network.proxy.RegistrationHostName:{ListenPort}
	/// </summary>
	internal static string sFiddlerListenHostPort;

	internal static string sMakeCertParamsRoot;

	internal static string sMakeCertParamsEE;

	internal static string sMakeCertRootCN;

	internal static string sMakeCertSubjectO;

	private static string sRootUrl;

	private static string sSecureRootUrl;

	internal static string sRootKey;

	private static string sUserPath;

	/// <summary>
	/// Use 128bit AES Encryption when password-protecting .SAZ files. Note that, while this 
	/// encryption is much stronger than the default encryption algorithm, it is significantly
	/// slower to save and load these files, and the Windows Explorer ZIP utility cannot open them.
	/// </summary>
	public static bool bUseAESForSAZ;

	/// <summary>
	/// SSL/TLS Protocols we allow the client to choose from (when we call AuthenticateAsServer)
	/// We allow all protocols by default (Ssl2,Ssl3,Tls1) and also 'Bitwise OR' in the constants for TLS1.1 and TLS1.2 in case we happen to be running on .NET4.5.
	/// </summary>
	public static SslProtocols oAcceptedClientHTTPSProtocols;

	/// <summary>
	/// SSL/TLS Protocols we request the server use (when we call AuthenticateAsClient). By default, SSL3 and TLS1 are accepted; we exclude SSL2 so that TLS Extensions may be sent.
	/// We do NOT enable TLS1.1 or TLS1.2 by default because many servers will fail if you offer them and unlike browsers, .NET has no fallback code.
	/// </summary>
	public static SslProtocols oAcceptedServerHTTPSProtocols;

	/// <summary>
	/// When True, Fiddler will offer the latest TLS protocol version offered by the client in its request
	/// </summary>
	internal static bool bMimicClientHTTPSProtocols;

	/// <summary>
	/// Version information for the Fiddler/FiddlerCore assembly
	/// </summary>
	public static Version FiddlerVersionInfo;

	internal const int I_MAX_CONNECTION_QUEUE = 50;

	internal static bool bIsBeta;

	/// <summary>
	/// Will send traffic to an upstream proxy?
	/// OBSOLETE -- DO NOT USE. see <see cref="P:Fiddler.CONFIG.UpstreamGateway" /> instead.
	/// </summary>
	[Obsolete]
	[EditorBrowsable(EditorBrowsableState.Never)]
	public static bool bForwardToGateway;

	[Obsolete]
	internal static GatewayType _UpstreamGateway;

	public static bool bDebugSpew;

	/// <summary>
	/// The encoding with which HTTP Headers should be parsed. Defaults to UTF8, but may be overridden by specifying a REG_SZ containing the encoding name in the registry key \Fiddler2\HeaderEncoding
	/// </summary>
	public static Encoding oHeaderEncoding;

	public static Encoding oBodyEncoding;

	[Obsolete("Please, use the 'ReuseServerSockets' property instead.")]
	public static bool bReuseServerSockets;

	[Obsolete("Please, use the 'ReuseClientSockets' property instead.")]
	public static bool bReuseClientSockets;

	/// <summary>
	/// Controls whether Fiddler should register as the HTTPS proxy
	/// </summary>
	public static bool bCaptureCONNECT;

	[Obsolete("Please, use 'CaptureFTP' property instead.")]
	public static bool bCaptureFTP;

	/// <summary>
	/// Controls whether Fiddler will try to write exceptions to the System Event log. Note: Usually fails due to ACLs on the Event Log.
	/// </summary>
	public static bool bUseEventLogForExceptions;

	/// <summary>
	/// Controls whether Fiddler will attempt to log on to the upstream proxy server to download the proxy configuration script
	/// </summary>
	public static bool bAutoProxyLogon;

	[Obsolete("Please, use the 'EnableIPv6' property instead.")]
	public static bool bEnableIPv6;

	private static string hookConnectionNamed;

	private static bool bHookAllConnections;

	private static bool bHookWithPAC;

	[Obsolete]
	private static string m_sHostsThatBypassFiddler;

	private static string m_JSEditor;

	/// <summary>
	/// The username to send to the upstream gateway if the Version Checking webservice request requires authentication
	/// </summary>
	public static string sGatewayUsername;

	/// <summary>
	/// The password to send to the upstream gateway if the Version Checking webservice request requires authentication
	/// </summary>
	public static string sGatewayPassword;

	private static bool m_bCheckForISA;

	private static int m_ListenPort;

	/// <summary>
	/// Set this flag if m_ListenPort is a "temporary" port (E.g. specified on command-line) and it shouldn't be overridden in the registry
	/// </summary>
	internal static bool bUsingPortOverride;

	private static bool m_bForceExclusivePort;

	/// <summary>
	/// Controls whether Certificate-Generation output will be spewed to the Fiddler Log
	/// </summary>
	public static bool bDebugCertificateGeneration;

	private static int _iReverseProxyForPort;

	/// <summary>
	/// Alternative hostname which Fiddler should recognize as an alias for the local machine. The
	/// default value of ? will never be usable, as it's the QueryString delimiter
	/// </summary>
	public static string sAlternateHostname;

	internal static string sReverseProxyHostname;

	/// <summary>
	/// (Lowercase) Machine Name
	/// </summary>
	internal static string sMachineName;

	/// <summary>
	/// (Lowercase) Machine Domain Name
	/// </summary>
	internal static string sMachineDomain;

	/// <summary>
	/// List of hostnames for which HTTPS decryption (if enabled) should be skipped
	/// </summary>
	internal static HostList oHLSkipDecryption;

	internal static bool bHLSkipDecryptionInvert;

	/// <summary>
	/// True if Fiddler should be maximized on restart
	/// </summary>
	private static bool fNeedToMaximizeOnload;

	public static RetryMode RetryOnReceiveFailure;

	internal const string RootPath = "Root";

	private static bool allowRemoteConnections;

	/// <summary>
	/// Generally, callers should use FiddlerApplication.Prefs, but RawPrefs allows use of the PreferenceBag members that
	/// are not a part of IFiddlerPreferences
	/// </summary>
	internal static PreferenceBag RawPrefs => _Prefs;

	/// <summary>
	/// Control which processes have HTTPS traffic decryption enabled
	/// </summary>
	public static ProcessFilterCategories DecryptWhichProcesses
	{
		get
		{
			return _pfcDecyptFilter;
		}
		set
		{
			_pfcDecyptFilter = value;
		}
	}

	/// <summary>
	/// Controls whether Fiddler should attempt to decrypt HTTPS Traffic
	/// </summary>
	public static bool DecryptHTTPS
	{
		get
		{
			return bMITM_HTTPS;
		}
		set
		{
			bMITM_HTTPS = value;
		}
	}

	/// <summary>
	/// Should Audio/Video types automatically stream by default?
	/// </summary>
	public static bool StreamAudioVideo
	{
		get
		{
			return bStreamAudioVideo;
		}
		set
		{
			bStreamAudioVideo = value;
		}
	}

	/// <summary>
	/// Gets a value indicating what mechanism, if any, will be used to find the upstream proxy/gateway.
	/// </summary>
	[Obsolete("Use Telerik.NetworkConnections.NetworkConnectionsManager.GetCurrentProxySettingsForConnection(*) to get information for the current proxy settings.")]
	public static GatewayType UpstreamGateway
	{
		get
		{
			return _UpstreamGateway;
		}
		internal set
		{
			if ((int)value < 0 || (int)value > 3)
			{
				value = GatewayType.System;
			}
			_UpstreamGateway = value;
			bForwardToGateway = value != GatewayType.None;
		}
	}

	/// <summary>
	/// Controls whether Fiddler will reuse server connections for multiple sessions
	/// </summary>
	public static bool ReuseServerSockets
	{
		get
		{
			return bReuseServerSockets;
		}
		set
		{
			bReuseServerSockets = value;
		}
	}

	/// <summary>
	/// Controls whether Fiddler will reuse client connections for multiple sessions
	/// </summary>
	public static bool ReuseClientSockets
	{
		get
		{
			return bReuseClientSockets;
		}
		set
		{
			bReuseClientSockets = value;
		}
	}

	/// <summary>
	/// Controls whether Fiddler should register as the FTP proxy
	/// </summary>
	public static bool CaptureFTP
	{
		get
		{
			return bCaptureFTP;
		}
		set
		{
			bCaptureFTP = value;
		}
	}

	/// <summary>
	/// Controls whether Fiddler will attempt to connect to IPv6 addresses
	/// </summary>
	public static bool EnableIPv6
	{
		get
		{
			return bEnableIPv6;
		}
		set
		{
			bEnableIPv6 = value;
		}
	}

	/// <summary>
	/// Name of connection to which Fiddler should autoattach if MonitorAllConnections is not set
	/// </summary>
	[Obsolete("Use Telerik.NetworkConnections.NetworkConnectionsManager.GetCurrentProxySettingsForConnection(*)/SetProxySettingsForConnections(*) to get/set proxy settings for a network connection.")]
	public static string sHookConnectionNamed
	{
		get
		{
			return hookConnectionNamed;
		}
		set
		{
			hookConnectionNamed = value;
		}
	}

	[Obsolete("Use Telerik.NetworkConnections.NetworkConnectionsManager.GetAllConnectionFullNames() to get information for the current connections.")]
	public static string sHookConnectionNamespace
	{
		get
		{
			if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
			{
				return "Linux";
			}
			if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
			{
				return "OSX";
			}
			return "WinINet";
		}
	}

	internal static bool HookAllConnections
	{
		get
		{
			return bHookAllConnections;
		}
		set
		{
			bHookAllConnections = value;
		}
	}

	internal static bool HookWithPAC
	{
		get
		{
			return bHookWithPAC;
		}
		set
		{
			bHookWithPAC = value;
		}
	}

	/// <summary>
	/// Port to which Fiddler should forward inbound requests when configured to run as a Reverse Proxy
	/// </summary>
	public static int iReverseProxyForPort
	{
		get
		{
			return _iReverseProxyForPort;
		}
		set
		{
			if (value > -1 && value <= 65535 && value != m_ListenPort)
			{
				_iReverseProxyForPort = value;
				return;
			}
			FiddlerApplication.Log.LogFormat("!Invalid configuration. ReverseProxyForPort may not be set to {0}", value);
		}
	}

	/// <summary>
	/// On attach, will configure WinINET to bypass Fiddler for these hosts.
	/// </summary>
	[Obsolete("Use Telerik.NetworkConnections.NetworkConnectionsManager.GetCurrentProxySettingsForConnection(*)/SetProxySettingsForConnections(*) to get/set ProxySettings.BypassHosts value for a network connection.")]
	public static string sHostsThatBypassFiddler
	{
		get
		{
			return m_sHostsThatBypassFiddler;
		}
		set
		{
			string sNewValue = value;
			if (sNewValue == null)
			{
				sNewValue = string.Empty;
			}
			if (!sNewValue.OICContains("<-loopback>") && !sNewValue.OICContains("<loopback>"))
			{
				sNewValue = string.Format("{0}{1}{2}", "<-loopback>", string.IsNullOrEmpty(sNewValue) ? string.Empty : ";", sNewValue);
			}
			m_sHostsThatBypassFiddler = sNewValue;
		}
	}

	/// <summary>
	/// Boolean indicating whether Fiddler will open the listening port exclusively
	/// </summary>
	public static bool ForceExclusivePort
	{
		get
		{
			return m_bForceExclusivePort;
		}
		internal set
		{
			m_bForceExclusivePort = value;
		}
	}

	/// <summary>
	/// Controls whether server certificate errors are ignored when decrypting HTTPS traffic.
	/// </summary>
	public static bool IgnoreServerCertErrors
	{
		get
		{
			return bIgnoreServerCertErrors;
		}
		set
		{
			bIgnoreServerCertErrors = value;
		}
	}

	/// <summary>
	/// The port upon which Fiddler is configured to listen.
	/// </summary>
	public static int ListenPort
	{
		get
		{
			return m_ListenPort;
		}
		internal set
		{
			if (value >= 0 && value < 65536)
			{
				m_ListenPort = value;
				sFiddlerListenHostPort = Utilities.TrimAfter(sFiddlerListenHostPort, ':') + ":" + m_ListenPort;
			}
		}
	}

	/// <summary>
	/// Returns the path and filename of the editor used to edit the Rules script file.
	/// </summary>
	[CodeDescription("Return path to user's FiddlerScript editor.")]
	public static string JSEditor
	{
		get
		{
			if (string.IsNullOrEmpty(m_JSEditor))
			{
				m_JSEditor = GetPath("DefaultScriptEditor");
			}
			return m_JSEditor;
		}
		set
		{
			m_JSEditor = value;
		}
	}

	/// <summary>
	/// Returns true if Fiddler should permit remote connections. Requires restart.
	/// </summary>
	[CodeDescription("Returns true if Fiddler is configured to accept remote clients.")]
	public static bool bAllowRemoteConnections
	{
		get
		{
			return allowRemoteConnections;
		}
		internal set
		{
			allowRemoteConnections = value;
		}
	}

	private static string GetConnectionName()
	{
		if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
		{
			return "GSettings";
		}
		if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
		{
			return "Default";
		}
		return "DefaultLAN";
	}

	public static void SetNoDecryptList(string sNewList)
	{
		if (string.IsNullOrEmpty(sNewList))
		{
			oHLSkipDecryption = null;
			return;
		}
		oHLSkipDecryption = new HostList();
		oHLSkipDecryption.AssignFromString(sNewList);
	}

	public static void SetNoDecryptListInvert(bool bInvert)
	{
		bHLSkipDecryptionInvert = bInvert;
	}

	/// <summary>
	/// Return a Special URL.
	/// </summary>
	/// <param name="sWhatUrl">String constant describing the URL to return. CASE-SENSITIVE!</param>
	/// <returns>Returns target URL</returns>
	[CodeDescription("Return a special Url.")]
	public static string GetUrl(string sWhatUrl)
	{
		return sWhatUrl switch
		{
			"AutoResponderHelp" => sRootUrl + "help/AutoResponder.asp", 
			"ChangeList" => "http://www.telerik.com/support/whats-new/fiddler/release-history/fiddler-v2.x?", 
			"FiltersHelp" => sRootUrl + "help/Filters.asp", 
			"HelpContents" => sRootUrl + "help/?ver=", 
			"REDIR" => "http://fiddler2.com/r/?", 
			"VerCheck" => (FiddlerApplication.Prefs.GetBoolPref("fiddler.updater.UseHTTPS", Environment.OSVersion.Version.Major > 5) ? "https" : "http") + "://www.telerik.com/UpdateCheck.aspx?isBeta=", 
			"InstallLatest" => bIsBeta ? (sSecureRootUrl + "r/?GetFiddler4Beta") : (sSecureRootUrl + "r/?GetFiddler4"), 
			"ShopAmazon" => "http://www.fiddlerbook.com/r/?shop", 
			"PrioritySupport" => "http://www.telerik.com/purchase/fiddler", 
			_ => sRootUrl, 
		};
	}

	public static string GetRedirUrl(string sKeyword)
	{
		return string.Format("{0}{1}", GetUrl("REDIR"), sKeyword);
	}

	/// <summary>
	/// Get a registry path for a named constant
	/// </summary>
	/// <param name="sWhatPath">The path to retrieve [Root, UI, Dynamic, Prefs]</param>
	/// <returns>The registry path</returns>
	public static string GetRegPath(string sWhatPath)
	{
		return sWhatPath switch
		{
			"Root" => sRootKey, 
			"MenuExt" => sRootKey + "MenuExt\\", 
			"UI" => sRootKey + "UI\\", 
			"Dynamic" => sRootKey + "Dynamic\\", 
			"Prefs" => sRootKey + "Prefs\\", 
			_ => sRootKey, 
		};
	}

	/// <summary>
	/// Return an app path (ending in Path.DirectorySeparatorChar) or a filename
	/// </summary>
	/// <param name="sWhatPath">CASE-SENSITIVE</param>
	/// <returns>The specified filesystem path</returns>
	[CodeDescription("Return a filesystem path.")]
	public static string GetPath(string sWhatPath)
	{
		switch (sWhatPath)
		{
		case "App":
		{
			string rootDirectory6 = PathsHelper.RootDirectory;
			char directorySeparatorChar = Path.DirectorySeparatorChar;
			return rootDirectory6 + directorySeparatorChar;
		}
		case "AutoFiddlers_Machine":
		{
			string rootDirectory5 = PathsHelper.RootDirectory;
			char directorySeparatorChar = Path.DirectorySeparatorChar;
			string text9 = directorySeparatorChar.ToString();
			directorySeparatorChar = Path.DirectorySeparatorChar;
			return rootDirectory5 + text9 + "Scripts" + directorySeparatorChar;
		}
		case "AutoFiddlers_User":
		{
			string text8 = sUserPath;
			char directorySeparatorChar = Path.DirectorySeparatorChar;
			return text8 + "Scripts" + directorySeparatorChar;
		}
		case "AutoResponderDefaultRules":
			return sUserPath + "AutoResponder.xml";
		case "Captures":
		{
			IFiddlerPreferences prefs3 = FiddlerApplication.Prefs;
			string text7 = sUserPath;
			char directorySeparatorChar = Path.DirectorySeparatorChar;
			return prefs3.GetStringPref("fiddler.config.path.captures", text7 + "Captures" + directorySeparatorChar);
		}
		case "CustomMimeMappingsXmlFile":
			return sUserPath + "CustomMimeMappings.xml";
		case "DefaultClientCertificate":
			return FiddlerApplication.Prefs.GetStringPref("fiddler.config.path.defaultclientcert", sUserPath + "ClientCertificate.cer");
		case "DefaultScriptEditor":
		{
			string path = GetPath("App");
			char directorySeparatorChar = Path.DirectorySeparatorChar;
			return path + "ScriptEditor" + directorySeparatorChar + "FSE2.exe";
		}
		case "FiddlerRootCert":
			return sUserPath + "DO_NOT_TRUST_FiddlerRoot.cer";
		case "Filters":
		{
			string text12 = sUserPath;
			char directorySeparatorChar = Path.DirectorySeparatorChar;
			return text12 + "Filters" + directorySeparatorChar;
		}
		case "FilterNowRulesXmlFile":
			return sUserPath + "FilterNowRules.xml";
		case "Inspectors":
		{
			string rootDirectory7 = PathsHelper.RootDirectory;
			char directorySeparatorChar = Path.DirectorySeparatorChar;
			string text11 = directorySeparatorChar.ToString();
			directorySeparatorChar = Path.DirectorySeparatorChar;
			return rootDirectory7 + text11 + "Inspectors" + directorySeparatorChar;
		}
		case "Inspectors_User":
		{
			string text10 = sUserPath;
			char directorySeparatorChar = Path.DirectorySeparatorChar;
			return text10 + "Inspectors" + directorySeparatorChar;
		}
		case "PerUser-ISA-Config":
		{
			string sFolder = "C:\\";
			try
			{
				sFolder = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
			}
			catch (Exception)
			{
			}
			return sFolder + "\\microsoft\\firewall client 2004\\management.ini";
		}
		case "PerMachine-ISA-Config":
		{
			string sFolder = "C:\\";
			try
			{
				sFolder = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
			}
			catch (Exception)
			{
			}
			return sFolder + "\\microsoft\\firewall client 2004\\management.ini";
		}
		case "MakeCert":
		{
			IFiddlerPreferences prefs4 = FiddlerApplication.Prefs;
			string rootDirectory4 = PathsHelper.RootDirectory;
			char directorySeparatorChar = Path.DirectorySeparatorChar;
			string sFolder = prefs4.GetStringPref("fiddler.config.path.makecert", rootDirectory4 + directorySeparatorChar + "MakeCert.exe");
			if (!File.Exists(sFolder))
			{
				sFolder = "MakeCert.exe";
			}
			return sFolder;
		}
		case "MyDocs":
		{
			string sFolder = "C:\\";
			try
			{
				sFolder = Environment.GetFolderPath(Environment.SpecialFolder.Personal, Environment.SpecialFolderOption.DoNotVerify);
			}
			catch (Exception e2)
			{
				FiddlerApplication.Log.LogFormat("!!Initialization Error: Failed to retrieve path to your Documents folder.\nThis generally means you have a relative environment variable.\nDefaulting to {0}\n\n{1}", sFolder, e2.Message);
			}
			return sFolder;
		}
		case "Pac":
			return FiddlerApplication.Prefs.GetStringPref("fiddler.config.path.pac", sUserPath + "Scripts" + Path.DirectorySeparatorChar + "BrowserPAC.js");
		case "Requests":
			return FiddlerApplication.Prefs.GetStringPref("fiddler.config.path.requests", sUserPath + "Captures" + Path.DirectorySeparatorChar + "Requests" + Path.DirectorySeparatorChar);
		case "Responses":
			return FiddlerApplication.Prefs.GetStringPref("fiddler.config.path.responses", sUserPath + "Captures" + Path.DirectorySeparatorChar + "Responses" + Path.DirectorySeparatorChar);
		case "Root":
			return sUserPath;
		case "SafeTemp":
		{
			string sFolder = "C:\\";
			try
			{
				sFolder = Environment.GetFolderPath(Environment.SpecialFolder.InternetCache);
				if (sFolder[sFolder.Length - 1] != Path.DirectorySeparatorChar)
				{
					string text6 = sFolder;
					char directorySeparatorChar = Path.DirectorySeparatorChar;
					sFolder = text6 + directorySeparatorChar;
				}
			}
			catch (Exception e)
			{
				string title = "GetPath(SafeTemp) Failed";
				string message = "Failed to retrieve path to your Internet Cache folder.\nThis generally means you have a relative environment variable.\nDefaulting to C:\\\n\n" + e.Message;
				FiddlerApplication.Log.LogFormat("{0}: {1}", title, message);
			}
			return sFolder;
		}
		case "Scripts":
		{
			string text5 = sUserPath;
			char directorySeparatorChar = Path.DirectorySeparatorChar;
			return text5 + "Scripts" + directorySeparatorChar;
		}
		case "TemplateResponses":
		{
			IFiddlerPreferences prefs2 = FiddlerApplication.Prefs;
			string rootDirectory3 = PathsHelper.RootDirectory;
			char directorySeparatorChar = Path.DirectorySeparatorChar;
			string text4 = directorySeparatorChar.ToString();
			directorySeparatorChar = Path.DirectorySeparatorChar;
			return prefs2.GetStringPref("fiddler.config.path.templateresponses", rootDirectory3 + text4 + "ResponseTemplates" + directorySeparatorChar);
		}
		case "Tools":
		{
			IFiddlerPreferences prefs = FiddlerApplication.Prefs;
			string rootDirectory2 = PathsHelper.RootDirectory;
			char directorySeparatorChar = Path.DirectorySeparatorChar;
			string text3 = directorySeparatorChar.ToString();
			directorySeparatorChar = Path.DirectorySeparatorChar;
			return prefs.GetStringPref("fiddler.config.path.Tools", rootDirectory2 + text3 + "Tools" + directorySeparatorChar);
		}
		case "Transcoders_Machine":
		{
			string rootDirectory = PathsHelper.RootDirectory;
			char directorySeparatorChar = Path.DirectorySeparatorChar;
			string text2 = directorySeparatorChar.ToString();
			directorySeparatorChar = Path.DirectorySeparatorChar;
			return rootDirectory + text2 + "ImportExport" + directorySeparatorChar;
		}
		case "Transcoders_User":
		{
			string text = sUserPath;
			char directorySeparatorChar = Path.DirectorySeparatorChar;
			return text + "ImportExport" + directorySeparatorChar;
		}
		default:
			return "C:\\";
		}
	}

	/// <summary>
	/// Ensure that the per-user folders used by Fiddler are present.
	/// </summary>
	internal static void EnsureFoldersExist()
	{
		try
		{
			if (!Directory.Exists(GetPath("Captures")))
			{
				Directory.CreateDirectory(GetPath("Captures"));
			}
			if (!Directory.Exists(GetPath("Requests")))
			{
				Directory.CreateDirectory(GetPath("Requests"));
			}
			if (!Directory.Exists(GetPath("Responses")))
			{
				Directory.CreateDirectory(GetPath("Responses"));
			}
			if (!Directory.Exists(GetPath("Scripts")))
			{
				Directory.CreateDirectory(GetPath("Scripts"));
			}
		}
		catch (Exception eX)
		{
			string title = "Folder Creation Failed";
			FiddlerApplication.Log.LogFormat("{0}: {1}", title, eX.ToString());
		}
	}

	static CONFIG()
	{
		_Prefs = null;
		_cb_STREAM_LARGE_FILES = 536870912;
		cbAutoStreamAndForget = 2147483591;
		sDefaultBrowserExe = "iexplore.exe";
		sDefaultBrowserParams = string.Empty;
		bRunningOnCLRv4 = true;
		_pfcDecyptFilter = ProcessFilterCategories.All;
		sLVColInfo = null;
		bReloadSessionIDAsFlag = false;
		bIsViewOnly = false;
		bUseXceedDecompressForGZIP = false;
		bUseXceedDecompressForDeflate = false;
		bMapSocketToProcess = true;
		bMITM_HTTPS = false;
		bUseSNIForCN = false;
		bIgnoreServerCertErrors = false;
		bStreamAudioVideo = false;
		bCheckCompressionIntegrity = false;
		bShowDefaultClientCertificateNeededPrompt = true;
		sFiddlerListenHostPort = "127.0.0.1:8888";
		sMakeCertParamsRoot = "-r -ss my -n \"CN={0}{1}\" -sky signature -eku 1.3.6.1.5.5.7.3.1 -h 1 -cy authority -a {3} -m 132 -b {4} {5}";
		sMakeCertParamsEE = "-pe -ss my -n \"CN={0}{1}\" -sky exchange -in {2} -is my -eku 1.3.6.1.5.5.7.3.1 -cy end -a {3} -m 132 -b {4} {5}";
		sMakeCertRootCN = "DO_NOT_TRUST_FiddlerRoot";
		sMakeCertSubjectO = ", O=DO_NOT_TRUST, OU=Created by http://www.fiddler2.com";
		sRootUrl = "http://fiddler2.com/fiddlercore/";
		sSecureRootUrl = "https://fiddler2.com/";
		sRootKey = "SOFTWARE\\Microsoft\\FiddlerCore\\";
		string path = GetPath("MyDocs");
		char directorySeparatorChar = Path.DirectorySeparatorChar;
		string text = directorySeparatorChar.ToString();
		directorySeparatorChar = Path.DirectorySeparatorChar;
		sUserPath = path + text + "FiddlerCore" + directorySeparatorChar;
		bUseAESForSAZ = true;
		oAcceptedClientHTTPSProtocols = SslProtocols.Default | SslProtocols.Ssl2 | SslProtocols.Tls11 | SslProtocols.Tls12;
		oAcceptedServerHTTPSProtocols = SslProtocols.Default;
		bMimicClientHTTPSProtocols = true;
		FiddlerVersionInfo = Assembly.GetExecutingAssembly().GetName().Version;
		bIsBeta = false;
		bForwardToGateway = true;
		_UpstreamGateway = GatewayType.System;
		bDebugSpew = false;
		oHeaderEncoding = Encoding.UTF8;
		oBodyEncoding = Encoding.UTF8;
		bReuseServerSockets = true;
		bReuseClientSockets = true;
		bCaptureCONNECT = true;
		bCaptureFTP = false;
		bUseEventLogForExceptions = false;
		bAutoProxyLogon = false;
		bEnableIPv6 = Environment.OSVersion.Version.Major > 5;
		hookConnectionNamed = GetConnectionName();
		bHookAllConnections = true;
		bHookWithPAC = false;
		m_bCheckForISA = true;
		m_ListenPort = 8888;
		bUsingPortOverride = false;
		bDebugCertificateGeneration = true;
		sAlternateHostname = "?";
		sReverseProxyHostname = "localhost";
		sMachineName = string.Empty;
		sMachineDomain = string.Empty;
		oHLSkipDecryption = null;
		bHLSkipDecryptionInvert = false;
		RetryOnReceiveFailure = RetryMode.Always;
		try
		{
			try
			{
				IPGlobalProperties oIPGP = IPGlobalProperties.GetIPGlobalProperties();
				sMachineDomain = oIPGP.DomainName.ToLowerInvariant();
				sMachineName = oIPGP.HostName.ToLowerInvariant();
				oIPGP = null;
			}
			catch (Exception)
			{
			}
			m_ListenPort = 8866;
			_LoadPreferences();
			if (Environment.OSVersion.Version.Major < 6 && Environment.OSVersion.Version.Minor < 1)
			{
				bMapSocketToProcess = false;
			}
		}
		catch (Exception eX)
		{
			string title = "Initialization of CONFIG Prefs Failed";
			FiddlerApplication.Log.LogFormat("{0}: {1}", title, eX.ToString());
		}
	}

	/// <summary>
	/// Loads Preferences from the Registry and fills appropriate fields
	/// </summary>
	private static void _LoadPreferences()
	{
		_Prefs = new PreferenceBag(null);
		bReloadSessionIDAsFlag = FiddlerApplication.Prefs.GetBoolPref("fiddler.saz.ReloadIDAsFlag", bReloadSessionIDAsFlag);
		bDebugCertificateGeneration = FiddlerApplication.Prefs.GetBoolPref("fiddler.certmaker.Debug", bDebugCertificateGeneration);
		bUseSNIForCN = FiddlerApplication.Prefs.GetBoolPref("fiddler.network.https.SetCNFromSNI", bDefault: false);
		string sList = FiddlerApplication.Prefs.GetStringPref("fiddler.network.https.SupportedClientProtocolVersions", null);
		if (!string.IsNullOrEmpty(sList))
		{
			SslProtocols sslChoices2 = Utilities.ParseSSLProtocolString(sList);
			if (sslChoices2 != 0)
			{
				oAcceptedClientHTTPSProtocols = sslChoices2;
			}
		}
		sList = FiddlerApplication.Prefs.GetStringPref("fiddler.network.https.SupportedServerProtocolVersions", null);
		if (!string.IsNullOrEmpty(sList))
		{
			SslProtocols sslChoices = Utilities.ParseSSLProtocolString(sList);
			if (sslChoices != 0)
			{
				oAcceptedServerHTTPSProtocols = sslChoices;
			}
			bMimicClientHTTPSProtocols = sList.OICContains("<client>");
		}
		_cb_STREAM_LARGE_FILES = FiddlerApplication.Prefs.GetInt32Pref("fiddler.memory.DropIfOver", _cb_STREAM_LARGE_FILES);
		int cb = FiddlerApplication.Prefs.GetInt32Pref("fiddler.memory.StreamAndForgetIfOver", -1);
		if (cb < 0)
		{
			cb = 2147483591;
		}
		cbAutoStreamAndForget = cb;
	}

	internal static bool ShouldSkipDecryption(string sHost)
	{
		if (oHLSkipDecryption == null)
		{
			return false;
		}
		bool bOnList = oHLSkipDecryption.ContainsHost(sHost);
		if (bHLSkipDecryptionInvert)
		{
			bOnList = !bOnList;
		}
		return bOnList;
	}
}
