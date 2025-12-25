using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using FiddlerCore.Utilities;
using FiddlerCore.Utilities.SmartAssembly.Attributes;

namespace Fiddler;

/// <summary>
/// The Session object manages the complete HTTP session including the UI listitem, the ServerChatter, and the ClientChatter.
/// </summary>
[DebuggerDisplay("Session #{m_requestID}, {m_state}, {fullUrl}, [{BitFlags}]")]
public class Session
{
	[DoNotObfuscate]
	internal bool isReceivedByFiddlerOrchestra;

	/// <summary>
	/// Should we try to use the SPNToken type?
	/// Cached for performance reasons.
	/// ISSUE: It's technically possible to use FiddlerCorev2/v3 on .NET/4.5 but we won't set this field if you do that.
	/// </summary>
	private static bool bTrySPNTokenObject = true;

	/// <summary>
	/// Sorta hacky, we may use a .NET WebRequest object to generate a valid NTLM/Kerberos response if the server
	/// demands authentication and the Session is configured to automatically respond.
	/// </summary>
	private WebRequest __WebRequestForAuth = null;

	/// <summary>
	/// Used if the Session is bound to a WebSocket or CONNECTTunnel
	/// </summary>
	public ITunnel __oTunnel = null;

	/// <summary>
	/// File to stream if responseBodyBytes is null
	/// </summary>
	private string __sResponseFileToStream;

	private SessionFlags _bitFlags;

	private static int cRequests;

	/// <summary>
	/// When a client socket is reused, this field holds the next Session until its execution begins
	/// </summary>
	private Session nextSession = null;

	/// <summary>
	/// Should response be buffered for tampering.
	/// </summary>
	/// <remarks>ARCH: This should have been a property instead of a field, so we could throw an InvalidStateException if code tries to manipulate this value after the response has begun</remarks>
	public bool bBufferResponse = FiddlerApplication.Prefs.GetBoolPref("fiddler.ui.rules.bufferresponses", bDefault: false);

	/// <summary>
	/// Timers stored as this Session progresses
	/// </summary>
	public SessionTimers Timers = new SessionTimers();

	private SessionStates m_state;

	private bool _bypassGateway;

	private int m_requestID;

	private int _LocalProcessID;

	public object ViewItem;

	/// <summary>
	/// Field is set to False if socket is poisoned due to HTTP errors.
	/// </summary>
	private bool _bAllowClientPipeReuse = true;

	/// <summary>
	/// Object representing the HTTP Response.
	/// </summary>
	[CodeDescription("Object representing the HTTP Response.")]
	public ServerChatter oResponse;

	/// <summary>
	/// Object representing the HTTP Request.
	/// </summary>
	[CodeDescription("Object representing the HTTP Request.")]
	public ClientChatter oRequest;

	/// <summary>
	/// Fiddler-internal flags set on the Session.
	/// </summary>
	/// <remarks>TODO: ARCH: This shouldn't be exposed directly; it should be wrapped by a ReaderWriterLockSlim to prevent
	/// exceptions while enumerating the flags for storage, etc</remarks>
	[CodeDescription("Fiddler-internal flags set on the session.")]
	public readonly StringDictionary oFlags = new StringDictionary();

	/// <summary>
	/// Contains the bytes of the request body.
	/// </summary>
	[CodeDescription("Contains the bytes of the request body.")]
	public byte[] requestBodyBytes;

	/// <summary>
	/// Contains the bytes of the response body.
	/// </summary>
	[CodeDescription("Contains the bytes of the response body.")]
	public byte[] responseBodyBytes;

	/// <summary>
	/// IP Address of the client for this session.
	/// </summary>
	[CodeDescription("IP Address of the client for this session.")]
	public string m_clientIP;

	/// <summary>
	/// Client port attached to Fiddler.
	/// </summary>
	[CodeDescription("Client port attached to Fiddler.")]
	public int m_clientPort;

	/// <summary>
	/// IP Address of the server for this session.
	/// </summary>
	[CodeDescription("IP Address of the server for this session.")]
	public string m_hostIP;

	/// <summary>
	/// Event object used for pausing and resuming the thread servicing this session
	/// </summary>
	private AutoResetEvent oSyncEvent;

	private static EventHandler beforeSessionCounterReset;

	/// <summary>
	/// Current step in the SessionProcessing State Machine
	/// </summary>
	private ProcessingStates _pState;

	private bool bLeakedResponseAlready = false;

	/// <summary>
	/// Bitflags of commonly-queried session attributes
	/// </summary>
	public SessionFlags BitFlags
	{
		get
		{
			return _bitFlags;
		}
		internal set
		{
			if (CONFIG.bDebugSpew && value != _bitFlags)
			{
				FiddlerApplication.DebugSpew("Session #{0} bitflags adjusted from {1} to {2} @ {3}", id, _bitFlags, value, Environment.StackTrace);
			}
			_bitFlags = value;
		}
	}

	/// <summary>
	/// Returns True if this is a HTTP CONNECT tunnel.
	/// </summary>
	public bool isTunnel
	{
		get; [DoNotObfuscate]
		internal set;
	}

	/// <summary>
	/// A common use for the Tag property is to store data that is closely associated with the Session.
	/// It is NOT marshalled during drag/drop and is NOT serialized to a SAZ file.
	/// </summary>
	public object Tag { get; set; }

	/// <summary>
	/// If this session is a Tunnel, and the tunnel's IsOpen property is TRUE, returns TRUE. Otherwise returns FALSE.
	/// </summary>
	public bool TunnelIsOpen
	{
		get
		{
			if (__oTunnel != null)
			{
				return __oTunnel.IsOpen;
			}
			return false;
		}
	}

	/// <summary>
	/// If this session is a Tunnel, returns number of bytes sent from the Server to the Client
	/// </summary>
	public long TunnelIngressByteCount
	{
		get
		{
			if (__oTunnel != null)
			{
				return __oTunnel.IngressByteCount;
			}
			return 0L;
		}
	}

	/// <summary>
	/// If this session is a Tunnel, returns number of bytes sent from the Client to the Server
	/// </summary>
	public long TunnelEgressByteCount
	{
		get
		{
			if (__oTunnel != null)
			{
				return __oTunnel.EgressByteCount;
			}
			return 0L;
		}
	}

	[CodeDescription("Gets Request Headers, or empty headers if headers do not exist")]
	public HTTPRequestHeaders RequestHeaders
	{
		get
		{
			HTTPRequestHeaders oRH = null;
			if (Utilities.HasHeaders(oRequest))
			{
				oRH = oRequest.headers;
			}
			if (oRH == null)
			{
				oRH = new HTTPRequestHeaders("/", null);
			}
			return oRH;
		}
	}

	[CodeDescription("Gets Response Headers, or empty headers if headers do not exist")]
	public HTTPResponseHeaders ResponseHeaders
	{
		get
		{
			HTTPResponseHeaders oRH = null;
			if (Utilities.HasHeaders(oResponse))
			{
				oRH = oResponse.headers;
			}
			if (oRH == null)
			{
				oRH = new HTTPResponseHeaders(0, "HEADERS NOT SET", null);
			}
			return oRH;
		}
	}

	/// <summary>
	/// Gets or Sets the HTTP Request body bytes. 
	/// Setter adjusts Content-Length header, and removes Transfer-Encoding and Content-Encoding headers.
	/// Setter DOES NOT CLONE the passed array.
	/// Setter will throw if the Request object does not exist for some reason.
	/// Use utilSetRequestBody(sStr) to ensure proper character encoding if you need to use a string.
	/// </summary>
	[CodeDescription("Gets or Sets the Request body bytes; Setter fixes up headers.")]
	public byte[] RequestBody
	{
		get
		{
			return requestBodyBytes ?? Utilities.emptyByteArray;
		}
		set
		{
			if (value == null)
			{
				value = Utilities.emptyByteArray;
			}
			oRequest.headers.Remove("Transfer-Encoding");
			oRequest.headers.Remove("Content-Encoding");
			requestBodyBytes = value;
			oRequest.headers["Content-Length"] = value.LongLength.ToString();
		}
	}

	[CodeDescription("Gets or Sets the request's Method (e.g. GET, POST, etc).")]
	public string RequestMethod
	{
		get
		{
			if (!Utilities.HasHeaders(oRequest))
			{
				return string.Empty;
			}
			return oRequest.headers.HTTPMethod;
		}
		set
		{
			if (Utilities.HasHeaders(oRequest))
			{
				oRequest.headers.HTTPMethod = value;
			}
		}
	}

	/// <summary>
	/// Gets or Sets the HTTP Response body bytes.
	/// Setter adjusts Content-Length header, and removes Transfer-Encoding and Content-Encoding headers.
	/// Setter DOES NOT CLONE the passed array.
	/// Setter will throw if the Response object has not yet been created. (See utilCreateResponseAndBypassServer)
	/// Use utilSetResponseBody(sStr) to ensure proper character encoding if you need to use a string.
	/// </summary>
	[CodeDescription("Gets or Sets the Response body bytes; Setter fixes up headers.")]
	public byte[] ResponseBody
	{
		get
		{
			return responseBodyBytes ?? Utilities.emptyByteArray;
		}
		set
		{
			if (value == null)
			{
				value = Utilities.emptyByteArray;
			}
			oResponse.headers.Remove("Transfer-Encoding");
			oResponse.headers.Remove("Content-Encoding");
			responseBodyBytes = value;
			oResponse.headers["Content-Length"] = value.LongLength.ToString();
		}
	}

	/// <summary>
	/// When true, this session was conducted using the HTTPS protocol.
	/// </summary>
	[CodeDescription("When true, this session was conducted using the HTTPS protocol.")]
	public bool isHTTPS
	{
		get
		{
			if (!Utilities.HasHeaders(oRequest))
			{
				return false;
			}
			return "HTTPS".OICEquals(oRequest.headers.UriScheme);
		}
	}

	/// <summary>
	/// When true, this session was conducted using the FTP protocol.
	/// </summary>
	[CodeDescription("When true, this session was conducted using the FTP protocol.")]
	public bool isFTP
	{
		get
		{
			if (!Utilities.HasHeaders(oRequest))
			{
				return false;
			}
			return "FTP".OICEquals(oRequest.headers.UriScheme);
		}
	}

	/// <summary>
	/// Get the process ID of the application which made this request, or 0 if it cannot be determined.
	/// </summary>
	[CodeDescription("Get the process ID of the application which made this request, or 0 if it cannot be determined.")]
	public int LocalProcessID => _LocalProcessID;

	/// <summary>
	/// Get the Process Info of the application which made this request, or String.Empty if it is not known
	/// </summary>
	[CodeDescription("Get the Process Info the application which made this request, or String.Empty if it cannot be determined.")]
	public string LocalProcess
	{
		get
		{
			if (!oFlags.ContainsKey("X-ProcessInfo"))
			{
				return string.Empty;
			}
			return oFlags["X-ProcessInfo"];
		}
	}

	/// <summary>
	/// Gets a path-less filename suitable for saving the Response entity. Uses Content-Disposition if available.
	/// </summary>
	[CodeDescription("Gets a path-less filename suitable for saving the Response entity. Uses Content-Disposition if available.")]
	public string SuggestedFilename
	{
		get
		{
			if (!Utilities.HasHeaders(oResponse))
			{
				return id + ".txt";
			}
			if (Utilities.IsNullOrEmpty(responseBodyBytes))
			{
				string sFormat = "{0}_Status{1}.txt";
				return string.Format(sFormat, id.ToString(), responseCode.ToString());
			}
			string sResult = oResponse.headers.GetTokenValue("Content-Disposition", "filename*");
			if (sResult != null && sResult.Length > 7 && sResult.OICStartsWith("utf-8''"))
			{
				return Utilities.UrlDecode(sResult.Substring(7));
			}
			sResult = oResponse.headers.GetTokenValue("Content-Disposition", "filename");
			if (sResult != null)
			{
				return _MakeSafeFilename(sResult);
			}
			string sCandidateFilename = Utilities.TrimBeforeLast(Utilities.TrimAfter(url, '?'), '/');
			if (sCandidateFilename.Length > 0 && sCandidateFilename.Length < 64 && sCandidateFilename.Contains(".") && sCandidateFilename.LastIndexOf('.') == sCandidateFilename.IndexOf('.'))
			{
				string sFilename = _MakeSafeFilename(sCandidateFilename);
				string sNewExtension = string.Empty;
				if (url.Contains("?") || sFilename.Length < 1 || sFilename.OICEndsWithAny(".aspx", ".php", ".jsp", ".asp", ".asmx", ".cgi", ".cfm", ".ashx"))
				{
					sNewExtension = _GetSuggestedFilenameExt();
					if (sFilename.OICEndsWith(sNewExtension))
					{
						sNewExtension = string.Empty;
					}
				}
				string sFormat2 = (FiddlerApplication.Prefs.GetBoolPref("fiddler.session.prependIDtosuggestedfilename", bDefault: false) ? "{0}_{1}{2}" : "{1}{2}");
				return string.Format(sFormat2, id.ToString(), sFilename, sNewExtension);
			}
			StringBuilder sbResult = new StringBuilder(32);
			sbResult.Append(id);
			sbResult.Append("_");
			sbResult.Append(_GetSuggestedFilenameExt());
			return sbResult.ToString();
		}
	}

	/// <summary>
	/// Set to true in OnBeforeRequest if this request should bypass the gateway
	/// </summary>
	[CodeDescription("Set to true in OnBeforeRequest if this request should bypass the gateway")]
	public bool bypassGateway
	{
		get
		{
			return _bypassGateway;
		}
		set
		{
			_bypassGateway = value;
		}
	}

	/// <summary>
	/// Returns the port used by the client to communicate to Fiddler.
	/// </summary>
	[CodeDescription("Returns the port used by the client to communicate to Fiddler.")]
	public int clientPort => m_clientPort;

	/// <summary>
	/// State of session. Note Side-Effects: If setting to .Aborted, calls FinishUISession. If setting to/from a Tamper state, calls RefreshMyInspectors
	/// </summary>
	[CodeDescription("Enumerated state of the current session.")]
	public SessionStates state
	{
		get
		{
			return m_state;
		}
		set
		{
			SessionStates oldState = m_state;
			m_state = value;
			if (m_state == SessionStates.Aborted)
			{
				oFlags["X-Aborted-When"] = oldState.ToString();
			}
			RaiseOnStateChangedIfNotIgnored(oldState, value);
			if (m_state >= SessionStates.Done)
			{
				this.OnStateChanged = null;
				FireCompleteTransaction();
			}
		}
	}

	/// <summary>
	/// Returns the path and query part of the URL. (For a CONNECT request, returns the host:port to be connected.)
	/// </summary>
	[CodeDescription("Returns the path and query part of the URL. (For a CONNECT request, returns the host:port to be connected.)")]
	public string PathAndQuery
	{
		get
		{
			HTTPRequestHeaders oRH = oRequest.headers;
			if (oRH == null)
			{
				return string.Empty;
			}
			return oRH.RequestPath;
		}
		set
		{
			oRequest.headers.RequestPath = value;
		}
	}

	/// <summary>
	/// Retrieves the complete URI, including protocol/scheme, in the form http://www.host.com/filepath?query.
	/// Or sets the complete URI, adjusting the UriScheme and/or Host.
	/// </summary>
	[CodeDescription("Retrieves the complete URI, including protocol/scheme, in the form http://www.host.com/filepath?query.")]
	public string fullUrl
	{
		get
		{
			if (!Utilities.HasHeaders(oRequest))
			{
				return string.Empty;
			}
			return $"{oRequest.headers.UriScheme}://{url}";
		}
		set
		{
			if (string.IsNullOrEmpty(value))
			{
				throw new ArgumentException("Must specify a complete URI");
			}
			string sScheme = Utilities.TrimAfter(value, "://").ToLowerInvariant();
			string sRemainder = Utilities.TrimBefore(value, "://");
			if (sScheme != "http" && sScheme != "https" && sScheme != "ftp")
			{
				throw new ArgumentException("URI scheme must be http, https, or ftp");
			}
			oRequest.headers.UriScheme = sScheme;
			url = sRemainder;
		}
	}

	/// <summary>
	/// Gets or sets the URL (without protocol) being requested from the server, in the form www.host.com/filepath?query.
	/// </summary>
	[CodeDescription("Gets or sets the URL (without protocol) being requested from the server, in the form www.host.com/filepath?query.")]
	public string url
	{
		get
		{
			if (HTTPMethodIs("CONNECT"))
			{
				return PathAndQuery;
			}
			return host + PathAndQuery;
		}
		set
		{
			if (value.OICStartsWithAny("http://", "https://", "ftp://"))
			{
				throw new ArgumentException("If you wish to specify a protocol, use the fullUrl property instead. Input was: " + value);
			}
			if (HTTPMethodIs("CONNECT"))
			{
				string text2 = (PathAndQuery = value);
				host = text2;
				return;
			}
			int ixToken = value.IndexOfAny(new char[2] { '/', '?' });
			if (ixToken > -1)
			{
				host = value.Substring(0, ixToken);
				PathAndQuery = value.Substring(ixToken);
			}
			else
			{
				host = value;
				PathAndQuery = "/";
			}
		}
	}

	/// <summary>
	/// DNS Name of the host server targeted by this request. May include IPv6 literal brackets. NB: a port# may be included.
	/// </summary>
	[CodeDescription("Gets/Sets the host to which this request is targeted. MAY include IPv6 literal brackets. MAY include a trailing port#.")]
	public string host
	{
		get
		{
			return (oRequest != null) ? oRequest.host : string.Empty;
		}
		set
		{
			if (oRequest != null)
			{
				oRequest.host = value;
			}
		}
	}

	/// <summary>
	/// DNS Name of the host server (no port) targeted by this request. Will include IPv6-literal brackets for IPv6-literal addresses
	/// </summary>
	[CodeDescription("Gets/Sets the hostname to which this request is targeted; does NOT include any port# but will include IPv6-literal brackets for IPv6 literals.")]
	public string hostname
	{
		get
		{
			string sHost = oRequest.host;
			if (sHost.Length < 1)
			{
				return string.Empty;
			}
			int ixToken = sHost.LastIndexOf(':');
			if (ixToken > -1 && ixToken > sHost.LastIndexOf(']'))
			{
				return sHost.Substring(0, ixToken);
			}
			return oRequest.host;
		}
		set
		{
			int ixToken = value.LastIndexOf(':');
			if (ixToken > -1 && ixToken > value.LastIndexOf(']'))
			{
				throw new ArgumentException("Do not specify a port when setting hostname; use host property instead.");
			}
			string sOldHost = (HTTPMethodIs("CONNECT") ? PathAndQuery : host);
			ixToken = sOldHost.LastIndexOf(':');
			if (ixToken > -1 && ixToken > sOldHost.LastIndexOf(']'))
			{
				host = value + sOldHost.Substring(ixToken);
			}
			else
			{
				host = value;
			}
		}
	}

	/// <summary>
	/// Returns the server port to which this request is targeted.
	/// </summary>
	[CodeDescription("Returns the server port to which this request is targeted.")]
	public int port
	{
		get
		{
			string sHost = (HTTPMethodIs("CONNECT") ? oRequest.headers.RequestPath : oRequest.host);
			int iPort = (isHTTPS ? 443 : (isFTP ? 21 : 80));
			Utilities.CrackHostAndPort(sHost, out var _, ref iPort);
			return iPort;
		}
		set
		{
			if (value < 0 || value > 65535)
			{
				throw new ArgumentException("A valid target port value (0-65535) must be specified.");
			}
			host = $"{hostname}:{value}";
		}
	}

	/// <summary>
	/// Returns the sequential number of this session. Note, by default numbering is restarted at zero when the session list is cleared.
	/// </summary>
	[CodeDescription("Returns the sequential number of this request.")]
	public int id => m_requestID;

	/// <summary>
	/// Returns the Address used by the client to communicate to Fiddler.
	/// </summary>
	[CodeDescription("Returns the Address used by the client to communicate to Fiddler.")]
	public string clientIP => (m_clientIP == null) ? "0.0.0.0" : m_clientIP;

	/// <summary>
	/// Gets or Sets the HTTP Status code of the server's response
	/// </summary>
	[CodeDescription("Gets or Sets the HTTP Status code of the server's response")]
	public int responseCode
	{
		get
		{
			if (Utilities.HasHeaders(oResponse))
			{
				return oResponse.headers.HTTPResponseCode;
			}
			return 0;
		}
		set
		{
			if (Utilities.HasHeaders(oResponse))
			{
				oResponse.headers.SetStatus(value, "Fiddled");
			}
		}
	}

	/// <summary>
	/// Checks whether this is a WebSocket, and if so, whether it has logged any parsed messages.
	/// </summary>
	public bool bHasWebSocketMessages
	{
		get
		{
			if (!isAnyFlagSet(SessionFlags.IsWebSocketTunnel) || HTTPMethodIs("CONNECT"))
			{
				return false;
			}
			if (!(__oTunnel is WebSocket oWS))
			{
				return false;
			}
			return oWS.MessageCount > 0;
		}
	}

	/// <summary>
	/// Returns TRUE if this session's State &gt; ReadingResponse, and oResponse, oResponse.headers, and responseBodyBytes are all non-null. Note that
	/// bHasResponse returns FALSE if the session is currently reading, even if a body was copied using the COMETPeek feature
	/// </summary>
	[CodeDescription("Returns TRUE if this session state>ReadingResponse and oResponse not null.")]
	public bool bHasResponse => state > SessionStates.ReadingResponse && oResponse != null && oResponse.headers != null && responseBodyBytes != null;

	/// <summary>
	/// Indexer property into SESSION flags, REQUEST headers, and RESPONSE headers. e.g. oSession["Request", "Host"] returns string value for the Request host header. If null, returns String.Empty
	/// </summary>
	/// <param name="sCollection">SESSION, REQUEST or RESPONSE</param>
	/// <param name="sName">The name of the flag or header</param>
	/// <returns>String value or String.Empty</returns>
	[CodeDescription("Indexer property into SESSION flags, REQUEST headers, and RESPONSE headers. e.g. oSession[\"Request\", \"Host\"] returns string value for the Request host header. If null, returns String.Empty")]
	public string this[string sCollection, string sName]
	{
		get
		{
			if ("SESSION".OICEquals(sCollection))
			{
				string sValue = oFlags[sName];
				return sValue ?? string.Empty;
			}
			if ("REQUEST".OICEquals(sCollection))
			{
				if (!Utilities.HasHeaders(oRequest))
				{
					return string.Empty;
				}
				return oRequest[sName];
			}
			if ("RESPONSE".OICEquals(sCollection))
			{
				if (!Utilities.HasHeaders(oResponse))
				{
					return string.Empty;
				}
				return oResponse[sName];
			}
			return "undefined";
		}
	}

	/// <summary>
	/// Simple indexer into the Session's oFlags object; returns null if flag is not present.
	/// </summary>
	/// <returns>
	/// Returns the string value if the specified flag is present, or null if it is not.
	/// </returns>
	[CodeDescription("Indexer property into session flags collection. oSession[\"Flagname\"] returns string value (or null if missing!).")]
	public string this[string sFlag]
	{
		get
		{
			return oFlags[sFlag];
		}
		set
		{
			if (value == null)
			{
				oFlags.Remove(sFlag);
			}
			else
			{
				oFlags[sFlag] = value;
			}
		}
	}

	/// <summary>
	/// This event fires when new session is created.
	/// </summary>
	public static event EventHandler<Session> SessionCreated;

	/// <summary>
	/// This event fires when one of its fields is changed
	/// </summary>
	internal static event EventHandler<Session> SessionFieldChanged;

	/// <summary>
	/// This event fires at any time the session's State changes. Use with caution due to the potential for performance impact.
	/// </summary>
	public event EventHandler<StateChangeEventArgs> OnStateChanged;

	/// <summary>
	/// This event fires if this Session automatically yields a new one, for instance, if Fiddler is configured to automatically
	/// follow redirects or perform multi-leg authentication (X-AutoAuth).
	/// </summary>
	public event EventHandler<ContinueTransactionEventArgs> OnContinueTransaction;

	public event EventHandler<EventArgs> OnCompleteTransaction;

	internal static event EventHandler BeforeSessionCounterReset
	{
		[DoNotObfuscate]
		add
		{
			beforeSessionCounterReset = (EventHandler)Delegate.Combine(beforeSessionCounterReset, value);
		}
		[DoNotObfuscate]
		remove
		{
			beforeSessionCounterReset = (EventHandler)Delegate.Remove(beforeSessionCounterReset, value);
		}
	}

	/// <summary>
	/// DO NOT USE. TEMPORARY WHILE REFACTORING VISIBILITY OF MEMBERS
	/// </summary>
	/// <param name="FlagsToSet"></param>
	/// <param name="b"></param>
	public void UNSTABLE_SetBitFlag(SessionFlags FlagsToSet, bool b)
	{
		SetBitFlag(FlagsToSet, b);
	}

	/// <summary>
	/// Sets or unsets the specified SessionFlag(s)
	/// </summary>
	/// <param name="FlagsToSet">SessionFlags</param>
	/// <param name="b">Desired set value</param>
	internal void SetBitFlag(SessionFlags FlagsToSet, bool b)
	{
		if (b)
		{
			BitFlags = _bitFlags | FlagsToSet;
		}
		else
		{
			BitFlags = _bitFlags & ~FlagsToSet;
		}
	}

	/// <summary>
	/// Test the session's BitFlags
	/// </summary>
	/// <param name="FlagsToTest">One or more (OR'd) SessionFlags</param>
	/// <returns>TRUE if ALL specified flag(s) are set</returns>
	public bool isFlagSet(SessionFlags FlagsToTest)
	{
		return FlagsToTest == (_bitFlags & FlagsToTest);
	}

	/// <summary>
	/// Test the session's BitFlags
	/// </summary>
	/// <param name="FlagsToTest">One or more (OR'd) SessionFlags</param>
	/// <returns>TRUE if ANY of specified flag(s) are set</returns>
	public bool isAnyFlagSet(SessionFlags FlagsToTest)
	{
		return (_bitFlags & FlagsToTest) != 0;
	}

	/// <summary>
	/// Returns TRUE if the Session's HTTP Method is available and matches the target method.
	/// </summary>
	/// <param name="sTestFor">The target HTTP Method being compared.</param>
	/// <returns>true, if the method is specified and matches sTestFor (case-insensitive); otherwise false.</returns>
	[CodeDescription("Returns TRUE if the Session's HTTP Method is available and matches the target method.")]
	public bool HTTPMethodIs(string sTestFor)
	{
		return RequestMethod.OICEquals(sTestFor);
	}

	/// <summary>
	/// Returns TRUE if the Session's target hostname (no port) matches sTestHost (case-insensitively).
	/// </summary>
	/// <param name="sTestHost">The host to which this session's host should be compared.</param>
	/// <returns>True if this session is targeted to the specified host.</returns>
	[CodeDescription("Returns TRUE if the Session's target hostname (no port) matches sTestHost (case-insensitively).")]
	public bool HostnameIs(string sTestHost)
	{
		if (oRequest == null)
		{
			return false;
		}
		int ixToken = oRequest.host.LastIndexOf(':');
		if (ixToken > -1 && ixToken > oRequest.host.LastIndexOf(']'))
		{
			return string.Compare(oRequest.host, 0, sTestHost, 0, ixToken, StringComparison.OrdinalIgnoreCase) == 0;
		}
		return oRequest.host.OICEquals(sTestHost);
	}

	/// <summary>
	/// Replaces any characters in a filename that are unsafe with safe equivalents, and trim to 160 characters.
	/// </summary>
	/// <param name="sFilename"></param>
	/// <returns></returns>
	private static string _MakeSafeFilename(string sFilename)
	{
		char[] arrCharUnsafe = Path.GetInvalidFileNameChars();
		if (sFilename.IndexOfAny(arrCharUnsafe) < 0)
		{
			return Utilities.TrimTo(sFilename, 160);
		}
		StringBuilder sbFilename = new StringBuilder(sFilename);
		for (int x = 0; x < sbFilename.Length; x++)
		{
			if (Array.IndexOf(arrCharUnsafe, sFilename[x]) > -1)
			{
				sbFilename[x] = '-';
			}
		}
		return Utilities.TrimTo(sbFilename.ToString(), 160);
	}

	/// <summary>
	/// Examines the MIME type, and if ambiguous, returns sniffs the body.
	/// </summary>
	/// <returns></returns>
	private string _GetSuggestedFilenameExt()
	{
		string extension = Utilities.FileExtensionForMIMEType(oResponse.MIMEType);
		if (extension != ".txt")
		{
			return extension;
		}
		if (MimeSniffer.Instance.TrySniff(responseBodyBytes, out var sniffedExtension))
		{
			return sniffedExtension;
		}
		return extension;
	}

	private void RaiseOnStateChangedIfNotIgnored(SessionStates oldState, SessionStates newState)
	{
		if (!isFlagSet(SessionFlags.Ignored))
		{
			EventHandler<StateChangeEventArgs> oToNotify = this.OnStateChanged;
			if (oToNotify != null)
			{
				StateChangeEventArgs eaSC = new StateChangeEventArgs(oldState, newState);
				oToNotify(this, eaSC);
			}
		}
	}

	/// <summary>
	/// Notify extensions if this Session naturally led to another (e.g. due to redirect chasing or Automatic Authentication)
	/// </summary>
	/// <param name="oOrig">The original session</param>
	/// <param name="oNew">The new session created</param>
	private void FireContinueTransaction(Session oOrig, Session oNew, ContinueTransactionReason oReason)
	{
		EventHandler<ContinueTransactionEventArgs> oToNotify = this.OnContinueTransaction;
		if (this.OnCompleteTransaction != null)
		{
			oNew.OnCompleteTransaction = this.OnCompleteTransaction;
			this.OnCompleteTransaction = null;
		}
		this.OnContinueTransaction = null;
		if (oToNotify != null)
		{
			ContinueTransactionEventArgs eaCT = new ContinueTransactionEventArgs(oOrig, oNew, oReason);
			oToNotify(this, eaCT);
		}
	}

	private void FireCompleteTransaction()
	{
		EventHandler<EventArgs> oToNotify = this.OnCompleteTransaction;
		this.OnContinueTransaction = null;
		this.OnCompleteTransaction = null;
		oToNotify?.Invoke(this, new EventArgs());
	}

	/// <summary>
	/// Returns HTML representing the Session. Call Utilities.StringToCF_HTML on the result of this function before placing it on the clipboard.
	/// </summary>
	/// <param name="HeadersOnly">TRUE if only the headers should be copied.</param>
	/// <returns>A HTML-formatted fragment representing the current session.</returns>
	public string ToHTMLFragment(bool HeadersOnly)
	{
		if (!Utilities.HasHeaders(oRequest))
		{
			return string.Empty;
		}
		StringBuilder sbOutput = new StringBuilder();
		sbOutput.Append("<span class='REQUEST'>");
		sbOutput.Append(Utilities.HtmlEncode(oRequest.headers.ToString(prependVerbLine: true, appendEmptyLine: true, includeProtocolAndHostInPath: true)).Replace("\r\n", "<br />"));
		if (!HeadersOnly && !Utilities.IsNullOrEmpty(requestBodyBytes))
		{
			Encoding oEnc2 = GetRequestBodyEncoding();
			sbOutput.Append(Utilities.HtmlEncode(oEnc2.GetString(requestBodyBytes)).Replace("\r\n", "<br />"));
		}
		sbOutput.Append("</span><br />");
		if (Utilities.HasHeaders(oResponse))
		{
			sbOutput.Append("<span class='RESPONSE'>");
			sbOutput.Append(Utilities.HtmlEncode(oResponse.headers.ToString(prependStatusLine: true, appendEmptyLine: true)).Replace("\r\n", "<br />"));
			if (!HeadersOnly && !Utilities.IsNullOrEmpty(responseBodyBytes))
			{
				Encoding oEnc = Utilities.getResponseBodyEncoding(this);
				sbOutput.Append(Utilities.HtmlEncode(oEnc.GetString(responseBodyBytes)).Replace("\r\n", "<br />"));
			}
			sbOutput.Append("</span>");
		}
		return sbOutput.ToString();
	}

	/// <summary>
	/// Store this session's request and response to a string.
	/// </summary>
	/// <param name="HeadersOnly">If true, return only the request and response headers</param>
	/// <returns>String representing this session</returns>
	public string ToString(bool HeadersOnly)
	{
		if (!Utilities.HasHeaders(oRequest))
		{
			return string.Empty;
		}
		StringBuilder sbOutput = new StringBuilder();
		sbOutput.Append(oRequest.headers.ToString(prependVerbLine: true, appendEmptyLine: true, includeProtocolAndHostInPath: true));
		if (!HeadersOnly && !Utilities.IsNullOrEmpty(requestBodyBytes))
		{
			Encoding oEnc2 = GetRequestBodyEncoding();
			sbOutput.Append(oEnc2.GetString(requestBodyBytes));
		}
		sbOutput.Append("\r\n");
		if (Utilities.HasHeaders(oResponse))
		{
			sbOutput.Append(oResponse.headers.ToString(prependStatusLine: true, appendEmptyLine: true));
			if (!HeadersOnly && !Utilities.IsNullOrEmpty(responseBodyBytes))
			{
				Encoding oEnc = Utilities.getResponseBodyEncoding(this);
				sbOutput.Append(oEnc.GetString(responseBodyBytes));
			}
			sbOutput.Append("\r\n");
		}
		return sbOutput.ToString();
	}

	/// <summary>
	/// Store this session's request and response to a string.
	/// </summary>
	/// <returns>A string containing the content of the request and response.</returns>
	public override string ToString()
	{
		return ToString(HeadersOnly: false);
	}

	/// <summary>
	/// This method resumes the Session's thread in response to "Continue" commands from the UI
	/// </summary>
	public void ThreadResume()
	{
		if (oSyncEvent == null)
		{
			return;
		}
		try
		{
			oSyncEvent.Set();
		}
		catch (Exception)
		{
		}
	}

	/// <summary>
	/// Set the SessionFlags.Ignore bit for this Session, also configuring it to stream, drop read data, and bypass event handlers.
	/// For a CONNECT Tunnel, traffic will be blindly shuffled back and forth. Session will be hidden.
	/// </summary>
	[CodeDescription("Sets the SessionFlags.Ignore bit for this Session, hiding it and ignoring its traffic.")]
	public void Ignore()
	{
		SetBitFlag(SessionFlags.Ignored, b: true);
		if (HTTPMethodIs("CONNECT"))
		{
			oFlags["x-no-decrypt"] = "IgnoreFlag";
			oFlags["x-no-parse"] = "IgnoreFlag";
		}
		else
		{
			oFlags["log-drop-response-body"] = "IgnoreFlag";
			oFlags["log-drop-request-body"] = "IgnoreFlag";
		}
		bBufferResponse = false;
	}

	/// <summary>
	/// Called by an AcceptConnection-spawned background thread, create a new session object from a client socket 
	/// and execute the session
	/// </summary>
	/// <param name="oParams">Parameter object defining client socket and endpoint's HTTPS certificate, if present</param>
	internal static void CreateAndExecute(object oParams)
	{
		try
		{
			DateTime dtNow = DateTime.Now;
			ProxyExecuteParams oPEP = (ProxyExecuteParams)oParams;
			Interlocked.Add(ref COUNTERS.TOTAL_DELAY_ACCEPT_CONNECTION, (long)(dtNow - oPEP.dtConnectionAccepted).TotalMilliseconds);
			Interlocked.Increment(ref COUNTERS.CONNECTIONS_ACCEPTED);
			Socket sockRequest = oPEP.oSocket;
			ClientPipe pipeRequest = new ClientPipe(sockRequest, oPEP.dtConnectionAccepted);
			Session newSession = new Session(pipeRequest, null);
			FiddlerApplication.DoAfterSocketAccept(newSession, sockRequest);
			if (oPEP.oServerCert == null || newSession.AcceptHTTPSRequest(oPEP.oServerCert))
			{
				newSession.Execute(null);
			}
		}
		catch (Exception eX)
		{
			FiddlerApplication.Log.LogString(eX.ToString());
		}
	}

	/// <summary>
	/// Call this method to AuthenticateAsServer on the client pipe (e.g. Fiddler itself is acting as a HTTPS server). 
	/// If configured, the pipe will first sniff the request's TLS ClientHello ServerNameIndicator extension.
	/// </summary>
	/// <param name="oCert">The default certificate to use</param>
	/// <returns>TRUE if a HTTPS handshake was achieved; FALSE for any exceptions or other errors.</returns>
	private bool AcceptHTTPSRequest(X509Certificate2 oCert)
	{
		try
		{
			if (CONFIG.bUseSNIForCN)
			{
				byte[] arrSniff = new byte[1024];
				int iPeekCount = oRequest.pipeClient.GetRawSocket().Receive(arrSniff, SocketFlags.Peek);
				HTTPSClientHello oHello = new HTTPSClientHello();
				if (oHello.LoadFromStream(new MemoryStream(arrSniff, 0, iPeekCount, writable: false)))
				{
					oFlags["https-Client-SessionID"] = oHello.SessionID;
					if (!string.IsNullOrEmpty(oHello.ServerNameIndicator))
					{
						FiddlerApplication.DebugSpew("Secure Endpoint request with SNI of '{0}'", oHello.ServerNameIndicator);
						oFlags["https-Client-SNIHostname"] = oHello.ServerNameIndicator;
						oCert = CertMaker.FindCert(oHello.ServerNameIndicator);
					}
				}
			}
			if (!oRequest.pipeClient.SecureClientPipeDirect(oCert))
			{
				FiddlerApplication.Log.LogString("Failed to secure client connection when acting as Secure Endpoint.");
				return false;
			}
		}
		catch (Exception eX)
		{
			FiddlerApplication.Log.LogFormat("Failed to secure client connection when acting as Secure Endpoint: {0}", eX.ToString());
		}
		return true;
	}

	/// <summary>
	/// Call this function while in the "reading response" state to update the responseBodyBytes array with
	/// the partially read response.
	/// </summary>
	/// <returns>TRUE if the peek succeeded; FALSE if not in the ReadingResponse state</returns>
	public bool COMETPeek()
	{
		if (state != SessionStates.ReadingResponse)
		{
			return false;
		}
		try
		{
			responseBodyBytes = oResponse._PeekAtBody();
			return true;
		}
		catch (Exception eX)
		{
			FiddlerApplication.Log.LogString(eX.ToString());
			return false;
		}
	}

	/// <summary>
	/// Prevents the server pipe from this session from being pooled for reuse
	/// </summary>
	public void PoisonServerPipe()
	{
		if (oResponse != null)
		{
			oResponse._PoisonPipe();
		}
	}

	/// <summary>
	/// Ensures that, after the response is complete, the client socket is closed and not reused.
	/// Does NOT (and must not) close the pipe.
	/// </summary>
	public void PoisonClientPipe()
	{
		_bAllowClientPipeReuse = false;
	}

	/// <summary>
	/// Immediately close client and server sockets. Call in the event of errors-- doesn't queue server pipes for future reuse.
	/// </summary>
	/// <param name="bNullThemToo"></param>
	private void CloseSessionPipes(bool bNullThemToo)
	{
		if (CONFIG.bDebugSpew)
		{
			FiddlerApplication.DebugSpew("CloseSessionPipes() for Session #{0}", id);
		}
		if (oRequest != null && oRequest.pipeClient != null)
		{
			if (CONFIG.bDebugSpew)
			{
				FiddlerApplication.DebugSpew("Closing client pipe...", id);
			}
			oRequest.pipeClient.End();
			if (bNullThemToo)
			{
				oRequest.pipeClient = null;
			}
		}
		if (oResponse != null && oResponse.pipeServer != null)
		{
			FiddlerApplication.DebugSpew("Closing server pipe...", id);
			oResponse.pipeServer.End();
			if (bNullThemToo)
			{
				oResponse.pipeServer = null;
			}
		}
	}

	/// <summary>
	/// Closes both client and server pipes and moves state to Aborted; unpauses thread if paused.
	/// </summary>
	public void Abort()
	{
		try
		{
			if (isAnyFlagSet(SessionFlags.IsBlindTunnel | SessionFlags.IsDecryptingTunnel | SessionFlags.IsWebSocketTunnel))
			{
				if (__oTunnel != null)
				{
					__oTunnel.CloseTunnel();
					oFlags["x-Fiddler-Aborted"] = "true";
					state = SessionStates.Aborted;
				}
			}
			else if (m_state < SessionStates.Done)
			{
				CloseSessionPipes(bNullThemToo: true);
				oFlags["x-Fiddler-Aborted"] = "true";
				state = SessionStates.Aborted;
				ThreadResume();
			}
		}
		catch (Exception)
		{
		}
	}

	/// <summary>
	/// Save HTTP response body to Fiddler Captures folder. You likely want to call utilDecodeResponse first.
	/// </summary>
	/// <returns>True if the response body was successfully saved</returns>
	[CodeDescription("Save HTTP response body to Fiddler Captures folder.")]
	public bool SaveResponseBody()
	{
		string sPath = CONFIG.GetPath("Captures");
		StringBuilder sbFilename = new StringBuilder();
		sbFilename.Append(SuggestedFilename);
		while (File.Exists(sPath + sbFilename.ToString()))
		{
			sbFilename.Insert(0, id + "_");
		}
		sbFilename.Insert(0, sPath);
		return SaveResponseBody(sbFilename.ToString());
	}

	/// <summary>
	/// Save HTTP response body to specified location. You likely want to call utilDecodeResponse first.
	/// </summary>
	/// <param name="sFilename">The name of the file to which the response body should be saved.</param>
	/// <returns>True if the file was successfully written.</returns>
	[CodeDescription("Save HTTP response body to specified location.")]
	public bool SaveResponseBody(string sFilename)
	{
		try
		{
			Utilities.WriteArrayToFile(sFilename, responseBodyBytes);
			return true;
		}
		catch (Exception eX)
		{
			string title = "Save Failed";
			string message = eX.Message + "\n\n" + sFilename;
			FiddlerApplication.Log.LogFormat("{0}: {1}", title, message);
			return false;
		}
	}

	/// <summary>
	/// Save the request body to a file. You likely want to call utilDecodeRequest first.
	/// </summary>
	/// <param name="sFilename">The name of the file to which the request body should be saved.</param>
	/// <returns>True if the file was successfully written.</returns>
	[CodeDescription("Save HTTP request body to specified location.")]
	public bool SaveRequestBody(string sFilename)
	{
		try
		{
			Utilities.WriteArrayToFile(sFilename, requestBodyBytes);
			return true;
		}
		catch (Exception eX)
		{
			string title = "Save Failed";
			string message = eX.Message + "\n\n" + sFilename;
			FiddlerApplication.Log.LogFormat("{0}: {1}", title, message);
			return false;
		}
	}

	/// <summary>
	/// Save the request and response to a single file.
	/// </summary>
	/// <param name="sFilename">The filename to which the session should be saved.</param>
	/// <param name="bHeadersOnly">TRUE if only the headers should be written.</param>
	public void SaveSession(string sFilename, bool bHeadersOnly)
	{
		Utilities.EnsureOverwritable(sFilename);
		using FileStream fs = new FileStream(sFilename, FileMode.Create, FileAccess.Write);
		WriteToStream(fs, bHeadersOnly);
	}

	/// <summary>
	/// Save the request to a file.
	/// The headers' Request Line will not contain the scheme or host, which is probably not what you want.
	/// </summary>
	/// <param name="sFilename">The name of the file to which the request should be saved.</param>
	/// <param name="bHeadersOnly">TRUE to save only the headers</param>
	public void SaveRequest(string sFilename, bool bHeadersOnly)
	{
		SaveRequest(sFilename, bHeadersOnly, bIncludeSchemeAndHostInPath: false);
	}

	/// <summary>
	/// Save the request to a file. Throws if file cannot be written.
	/// </summary>
	/// <param name="sFilename">The name of the file to which the request should be saved.</param>
	/// <param name="bHeadersOnly">TRUE to save only the headers.</param>
	/// <param name="bIncludeSchemeAndHostInPath">TRUE to include the Scheme and Host in the Request Line.</param>
	public void SaveRequest(string sFilename, bool bHeadersOnly, bool bIncludeSchemeAndHostInPath)
	{
		Utilities.EnsureOverwritable(sFilename);
		using FileStream oFS = new FileStream(sFilename, FileMode.Create, FileAccess.Write);
		if (oRequest.headers != null)
		{
			byte[] arrRequest = oRequest.headers.ToByteArray(prependVerbLine: true, appendEmptyLine: true, bIncludeSchemeAndHostInPath, oFlags["X-OverrideHost"]);
			oFS.Write(arrRequest, 0, arrRequest.Length);
			if (!bHeadersOnly && requestBodyBytes != null)
			{
				oFS.Write(requestBodyBytes, 0, requestBodyBytes.Length);
			}
		}
	}

	/// <summary>
	/// Read metadata about this session from a stream. NB: Closes the Stream when done.
	/// </summary>
	/// <param name="strmMetadata">The stream of XML text from which session metadata will be loaded.</param>
	/// <returns>True if the Metadata was successfully loaded; False if any exceptions were trapped.</returns>
	public bool LoadMetadata(Stream strmMetadata)
	{
		string sXMLTrue = XmlConvert.ToString(value: true);
		SessionFlags sfInferredFlags = SessionFlags.None;
		string sOriginalID = null;
		try
		{
			XmlTextReader oXML = new XmlTextReader(strmMetadata);
			oXML.WhitespaceHandling = WhitespaceHandling.None;
			while (oXML.Read())
			{
				XmlNodeType nodeType = oXML.NodeType;
				XmlNodeType xmlNodeType = nodeType;
				if (xmlNodeType != XmlNodeType.Element)
				{
					continue;
				}
				switch (oXML.Name)
				{
				case "Session":
					if (oXML.GetAttribute("Aborted") != null)
					{
						SessionStates oldState = m_state;
						m_state = SessionStates.Aborted;
						RaiseOnStateChangedIfNotIgnored(oldState, m_state);
					}
					if (oXML.GetAttribute("BitFlags") != null)
					{
						BitFlags = (SessionFlags)uint.Parse(oXML.GetAttribute("BitFlags"), NumberStyles.HexNumber);
					}
					if (oXML.GetAttribute("SID") != null)
					{
						sOriginalID = oXML.GetAttribute("SID");
					}
					break;
				case "SessionFlag":
					oFlags.Add(oXML.GetAttribute("N"), oXML.GetAttribute("V"));
					break;
				case "SessionTimers":
				{
					Timers.ClientConnected = XmlConvert.ToDateTime(oXML.GetAttribute("ClientConnected"), XmlDateTimeSerializationMode.RoundtripKind);
					string sTemp = oXML.GetAttribute("ClientBeginRequest");
					if (sTemp != null)
					{
						Timers.ClientBeginRequest = XmlConvert.ToDateTime(sTemp, XmlDateTimeSerializationMode.RoundtripKind);
					}
					sTemp = oXML.GetAttribute("GotRequestHeaders");
					if (sTemp != null)
					{
						Timers.FiddlerGotRequestHeaders = XmlConvert.ToDateTime(sTemp, XmlDateTimeSerializationMode.RoundtripKind);
					}
					Timers.ClientDoneRequest = XmlConvert.ToDateTime(oXML.GetAttribute("ClientDoneRequest"), XmlDateTimeSerializationMode.RoundtripKind);
					sTemp = oXML.GetAttribute("GatewayTime");
					if (sTemp != null)
					{
						Timers.GatewayDeterminationTime = XmlConvert.ToInt32(sTemp);
					}
					sTemp = oXML.GetAttribute("DNSTime");
					if (sTemp != null)
					{
						Timers.DNSTime = XmlConvert.ToInt32(sTemp);
					}
					sTemp = oXML.GetAttribute("TCPConnectTime");
					if (sTemp != null)
					{
						Timers.TCPConnectTime = XmlConvert.ToInt32(sTemp);
					}
					sTemp = oXML.GetAttribute("HTTPSHandshakeTime");
					if (sTemp != null)
					{
						Timers.HTTPSHandshakeTime = XmlConvert.ToInt32(sTemp);
					}
					sTemp = oXML.GetAttribute("ServerConnected");
					if (sTemp != null)
					{
						Timers.ServerConnected = XmlConvert.ToDateTime(sTemp, XmlDateTimeSerializationMode.RoundtripKind);
					}
					sTemp = oXML.GetAttribute("FiddlerBeginRequest");
					if (sTemp != null)
					{
						Timers.FiddlerBeginRequest = XmlConvert.ToDateTime(sTemp, XmlDateTimeSerializationMode.RoundtripKind);
					}
					Timers.ServerGotRequest = XmlConvert.ToDateTime(oXML.GetAttribute("ServerGotRequest"), XmlDateTimeSerializationMode.RoundtripKind);
					sTemp = oXML.GetAttribute("ServerBeginResponse");
					if (sTemp != null)
					{
						Timers.ServerBeginResponse = XmlConvert.ToDateTime(sTemp, XmlDateTimeSerializationMode.RoundtripKind);
					}
					sTemp = oXML.GetAttribute("GotResponseHeaders");
					if (sTemp != null)
					{
						Timers.FiddlerGotResponseHeaders = XmlConvert.ToDateTime(sTemp, XmlDateTimeSerializationMode.RoundtripKind);
					}
					Timers.ServerDoneResponse = XmlConvert.ToDateTime(oXML.GetAttribute("ServerDoneResponse"), XmlDateTimeSerializationMode.RoundtripKind);
					Timers.ClientBeginResponse = XmlConvert.ToDateTime(oXML.GetAttribute("ClientBeginResponse"), XmlDateTimeSerializationMode.RoundtripKind);
					Timers.ClientDoneResponse = XmlConvert.ToDateTime(oXML.GetAttribute("ClientDoneResponse"), XmlDateTimeSerializationMode.RoundtripKind);
					break;
				}
				case "TunnelInfo":
				{
					long lngBytesEgress = 0L;
					long lngBytesIngress = 0L;
					if (long.TryParse(oXML.GetAttribute("BytesEgress"), out lngBytesEgress) && long.TryParse(oXML.GetAttribute("BytesIngress"), out lngBytesIngress))
					{
						__oTunnel = new MockTunnel(lngBytesEgress, lngBytesIngress);
					}
					break;
				}
				case "PipeInfo":
					bBufferResponse = sXMLTrue != oXML.GetAttribute("Streamed");
					if (!bBufferResponse)
					{
						sfInferredFlags |= SessionFlags.ResponseStreamed;
					}
					if (sXMLTrue == oXML.GetAttribute("CltReuse"))
					{
						sfInferredFlags |= SessionFlags.ClientPipeReused;
					}
					if (sXMLTrue == oXML.GetAttribute("Reused"))
					{
						sfInferredFlags |= SessionFlags.ServerPipeReused;
					}
					if (oResponse != null)
					{
						oResponse.m_bWasForwarded = sXMLTrue == oXML.GetAttribute("Forwarded");
						if (oResponse.m_bWasForwarded)
						{
							sfInferredFlags |= SessionFlags.SentToGateway;
						}
					}
					break;
				}
			}
			if (BitFlags == SessionFlags.None)
			{
				BitFlags = sfInferredFlags;
			}
			if (Timers.ClientBeginRequest.Ticks < 1)
			{
				Timers.ClientBeginRequest = Timers.ClientConnected;
			}
			if (Timers.FiddlerBeginRequest.Ticks < 1)
			{
				Timers.FiddlerBeginRequest = Timers.ServerGotRequest;
			}
			if (Timers.FiddlerGotRequestHeaders.Ticks < 1)
			{
				Timers.FiddlerGotRequestHeaders = Timers.ClientBeginRequest;
			}
			if (Timers.FiddlerGotResponseHeaders.Ticks < 1)
			{
				Timers.FiddlerGotResponseHeaders = Timers.ServerBeginResponse;
			}
			if (m_clientPort == 0 && oFlags.ContainsKey("X-ClientPort"))
			{
				int.TryParse(oFlags["X-ClientPort"], out m_clientPort);
			}
			if (oFlags.ContainsKey("X-ProcessInfo") && int.TryParse(Utilities.TrimBefore(oFlags["X-ProcessInfo"], ':'), out var i))
			{
				_LocalProcessID = i;
			}
			if (sOriginalID != null)
			{
				if (CONFIG.bReloadSessionIDAsFlag || oFlags.ContainsKey("ui-comments"))
				{
					oFlags["x-OriginalSessionID"] = sOriginalID;
				}
				else
				{
					oFlags["ui-comments"] = $"[#{sOriginalID}]";
				}
			}
			oXML.Close();
			return true;
		}
		catch (Exception eX)
		{
			FiddlerApplication.Log.LogString(eX.ToString());
			return false;
		}
	}

	/// <summary>
	/// Writes this session's metadata to a file.
	/// </summary>
	/// <param name="sFilename">The name of the file to which the metadata should be saved in XML format.</param>
	/// <returns>True if the file was successfully written.</returns>
	public bool SaveMetadata(string sFilename)
	{
		try
		{
			FileStream oFS = new FileStream(sFilename, FileMode.Create, FileAccess.Write);
			WriteMetadataToStream(oFS);
			oFS.Close();
			return true;
		}
		catch (Exception eX)
		{
			FiddlerApplication.Log.LogString(eX.ToString());
			return false;
		}
	}

	/// <summary>
	/// Saves the response (headers and body) to a file
	/// </summary>
	/// <param name="sFilename">The File to write</param>
	/// <param name="bHeadersOnly">TRUE if only heaers should be written</param>
	public void SaveResponse(string sFilename, bool bHeadersOnly)
	{
		Directory.CreateDirectory(Path.GetDirectoryName(sFilename));
		FileStream oFS = new FileStream(sFilename, FileMode.Create, FileAccess.Write);
		if (oResponse.headers != null)
		{
			byte[] arrResponse = oResponse.headers.ToByteArray(prependStatusLine: true, appendEmptyLine: true);
			oFS.Write(arrResponse, 0, arrResponse.Length);
			if (!bHeadersOnly && responseBodyBytes != null)
			{
				oFS.Write(responseBodyBytes, 0, responseBodyBytes.Length);
			}
		}
		oFS.Close();
	}

	/// <summary>
	/// Write the metadata about this Session to a stream. The Stream is left open!
	/// </summary>
	/// <param name="strmMetadata">The Stream to write to</param>
	public void WriteMetadataToStream(Stream strmMetadata)
	{
		XmlTextWriter oXML = new XmlTextWriter(strmMetadata, Encoding.UTF8);
		oXML.Formatting = Formatting.Indented;
		oXML.WriteStartDocument();
		oXML.WriteStartElement("Session");
		oXML.WriteAttributeString("SID", id.ToString());
		oXML.WriteAttributeString("BitFlags", ((uint)BitFlags).ToString("x"));
		if (m_state == SessionStates.Aborted)
		{
			oXML.WriteAttributeString("Aborted", XmlConvert.ToString(value: true));
		}
		oXML.WriteStartElement("SessionTimers");
		oXML.WriteAttributeString("ClientConnected", XmlConvert.ToString(Timers.ClientConnected, XmlDateTimeSerializationMode.RoundtripKind));
		oXML.WriteAttributeString("ClientBeginRequest", XmlConvert.ToString(Timers.ClientBeginRequest, XmlDateTimeSerializationMode.RoundtripKind));
		oXML.WriteAttributeString("GotRequestHeaders", XmlConvert.ToString(Timers.FiddlerGotRequestHeaders, XmlDateTimeSerializationMode.RoundtripKind));
		oXML.WriteAttributeString("ClientDoneRequest", XmlConvert.ToString(Timers.ClientDoneRequest, XmlDateTimeSerializationMode.RoundtripKind));
		oXML.WriteAttributeString("GatewayTime", XmlConvert.ToString(Timers.GatewayDeterminationTime));
		oXML.WriteAttributeString("DNSTime", XmlConvert.ToString(Timers.DNSTime));
		oXML.WriteAttributeString("TCPConnectTime", XmlConvert.ToString(Timers.TCPConnectTime));
		oXML.WriteAttributeString("HTTPSHandshakeTime", XmlConvert.ToString(Timers.HTTPSHandshakeTime));
		oXML.WriteAttributeString("ServerConnected", XmlConvert.ToString(Timers.ServerConnected, XmlDateTimeSerializationMode.RoundtripKind));
		oXML.WriteAttributeString("FiddlerBeginRequest", XmlConvert.ToString(Timers.FiddlerBeginRequest, XmlDateTimeSerializationMode.RoundtripKind));
		oXML.WriteAttributeString("ServerGotRequest", XmlConvert.ToString(Timers.ServerGotRequest, XmlDateTimeSerializationMode.RoundtripKind));
		oXML.WriteAttributeString("ServerBeginResponse", XmlConvert.ToString(Timers.ServerBeginResponse, XmlDateTimeSerializationMode.RoundtripKind));
		oXML.WriteAttributeString("GotResponseHeaders", XmlConvert.ToString(Timers.FiddlerGotResponseHeaders, XmlDateTimeSerializationMode.RoundtripKind));
		oXML.WriteAttributeString("ServerDoneResponse", XmlConvert.ToString(Timers.ServerDoneResponse, XmlDateTimeSerializationMode.RoundtripKind));
		oXML.WriteAttributeString("ClientBeginResponse", XmlConvert.ToString(Timers.ClientBeginResponse, XmlDateTimeSerializationMode.RoundtripKind));
		oXML.WriteAttributeString("ClientDoneResponse", XmlConvert.ToString(Timers.ClientDoneResponse, XmlDateTimeSerializationMode.RoundtripKind));
		oXML.WriteEndElement();
		oXML.WriteStartElement("PipeInfo");
		if (!bBufferResponse)
		{
			oXML.WriteAttributeString("Streamed", XmlConvert.ToString(value: true));
		}
		if (oRequest != null && oRequest.bClientSocketReused)
		{
			oXML.WriteAttributeString("CltReuse", XmlConvert.ToString(value: true));
		}
		if (oResponse != null)
		{
			if (oResponse.bServerSocketReused)
			{
				oXML.WriteAttributeString("Reused", XmlConvert.ToString(value: true));
			}
			if (oResponse.bWasForwarded)
			{
				oXML.WriteAttributeString("Forwarded", XmlConvert.ToString(value: true));
			}
		}
		oXML.WriteEndElement();
		if (isTunnel && __oTunnel != null)
		{
			oXML.WriteStartElement("TunnelInfo");
			oXML.WriteAttributeString("BytesEgress", XmlConvert.ToString(__oTunnel.EgressByteCount));
			oXML.WriteAttributeString("BytesIngress", XmlConvert.ToString(__oTunnel.IngressByteCount));
			oXML.WriteEndElement();
		}
		oXML.WriteStartElement("SessionFlags");
		foreach (string sKey in oFlags.Keys)
		{
			oXML.WriteStartElement("SessionFlag");
			oXML.WriteAttributeString("N", sKey);
			oXML.WriteAttributeString("V", oFlags[sKey]);
			oXML.WriteEndElement();
		}
		oXML.WriteEndElement();
		oXML.WriteEndElement();
		oXML.WriteEndDocument();
		oXML.Flush();
	}

	/// <summary>
	/// Write the session's Request to the specified stream 
	/// </summary>
	/// <param name="bHeadersOnly">TRUE if only the headers should be be written</param>
	/// <param name="bIncludeProtocolAndHostWithPath">TRUE if the Scheme and Host should be written in the Request Line</param>
	/// <param name="oFS">The Stream to which the request should be written</param>
	/// <returns>True if the request was written to the stream. False if the request headers do not exist. Throws on other stream errors.</returns>
	public bool WriteRequestToStream(bool bHeadersOnly, bool bIncludeProtocolAndHostWithPath, Stream oFS)
	{
		return WriteRequestToStream(bHeadersOnly, bIncludeProtocolAndHostWithPath, bEncodeIfBinary: false, oFS);
	}

	/// <summary>
	/// Write the session's Request to the specified stream 
	/// </summary>
	/// <param name="bHeadersOnly">TRUE if only the headers should be be written</param>
	/// <param name="bIncludeProtocolAndHostWithPath">TRUE if the Scheme and Host should be written in the Request Line</param>
	/// <param name="bEncodeIfBinary">TRUE if binary bodies should be encoded in base64 for text-safe transport (e.g. used by Composer drag/drop)</param>
	/// <param name="oFS">The Stream to which the request should be written</param>
	/// <returns>True if the request was written to the stream. False if the request headers do not exist. Throws on other stream errors.</returns>
	public bool WriteRequestToStream(bool bHeadersOnly, bool bIncludeProtocolAndHostWithPath, bool bEncodeIfBinary, Stream oFS)
	{
		if (!Utilities.HasHeaders(oRequest))
		{
			return false;
		}
		bool bEncode = bEncodeIfBinary && !bHeadersOnly && requestBodyBytes != null && Utilities.arrayContainsNonText(requestBodyBytes);
		HTTPRequestHeaders oRH = oRequest.headers;
		if (bEncode)
		{
			oRH = (HTTPRequestHeaders)oRH.Clone();
			oRH["Fiddler-Encoding"] = "base64";
		}
		byte[] arrData = oRH.ToByteArray(prependVerbLine: true, appendEmptyLine: true, bIncludeProtocolAndHostWithPath, oFlags["X-OverrideHost"]);
		oFS.Write(arrData, 0, arrData.Length);
		if (bEncode)
		{
			byte[] oEncArr = Encoding.ASCII.GetBytes(Convert.ToBase64String(requestBodyBytes));
			oFS.Write(oEncArr, 0, oEncArr.Length);
			return true;
		}
		if (!bHeadersOnly && !Utilities.IsNullOrEmpty(requestBodyBytes))
		{
			oFS.Write(requestBodyBytes, 0, requestBodyBytes.Length);
		}
		return true;
	}

	/// <summary>
	/// Write the session's Response to the specified stream
	/// </summary>
	/// <param name="oFS">The stream to which the response should be written</param>
	/// <param name="bHeadersOnly">TRUE if only the headers should be written</param>
	/// <returns>TRUE if the response was written to the stream. False if the response headers do not exist. Throws on other stream errors.</returns>
	public bool WriteResponseToStream(Stream oFS, bool bHeadersOnly)
	{
		if (!Utilities.HasHeaders(oResponse))
		{
			return false;
		}
		byte[] arrData = oResponse.headers.ToByteArray(prependStatusLine: true, appendEmptyLine: true);
		oFS.Write(arrData, 0, arrData.Length);
		if (!bHeadersOnly && !Utilities.IsNullOrEmpty(responseBodyBytes))
		{
			oFS.Write(responseBodyBytes, 0, responseBodyBytes.Length);
		}
		return true;
	}

	internal bool WriteWebSocketMessagesToStream(Stream oFS)
	{
		if (!(__oTunnel is WebSocket oWS))
		{
			return false;
		}
		return oWS.WriteWebSocketMessageListToStream(oFS);
	}

	/// <summary>
	/// Write the session to the specified stream
	/// </summary>
	/// <param name="oFS">The stream to which the session should be written</param>
	/// <param name="bHeadersOnly">TRUE if only the request and response headers should be written</param>
	/// <returns>False on any exceptions; True otherwise</returns>
	[CodeDescription("Write the session (or session headers) to the specified stream")]
	public bool WriteToStream(Stream oFS, bool bHeadersOnly)
	{
		try
		{
			WriteRequestToStream(bHeadersOnly, bIncludeProtocolAndHostWithPath: true, oFS);
			oFS.WriteByte(13);
			oFS.WriteByte(10);
			WriteResponseToStream(oFS, bHeadersOnly);
			return true;
		}
		catch (Exception)
		{
			return false;
		}
	}

	/// <summary>
	/// Replace HTTP request body using the specified file.
	/// </summary>
	/// <param name="sFilename">The file containing the request</param>
	/// <returns>True if the file was successfully loaded as the request body</returns>
	[CodeDescription("Replace HTTP request headers and body using the specified file.")]
	public bool LoadRequestBodyFromFile(string sFilename)
	{
		if (!Utilities.HasHeaders(oRequest))
		{
			return false;
		}
		sFilename = Utilities.EnsurePathIsAbsolute(CONFIG.GetPath("Requests"), sFilename);
		return oRequest.ReadRequestBodyFromFile(sFilename);
	}

	private bool LoadResponse(Stream strmResponse, string sResponseFile, string sOptionalContentTypeHint)
	{
		bool bUseStream = string.IsNullOrEmpty(sResponseFile);
		oResponse = new ServerChatter(this, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
		responseBodyBytes = Utilities.emptyByteArray;
		bBufferResponse = true;
		BitFlags |= SessionFlags.ResponseGeneratedByFiddler;
		oFlags["x-Fiddler-Generated"] = (bUseStream ? "LoadResponseFromStream" : "LoadResponseFromFile");
		bool bReturn = ((!bUseStream) ? oResponse.ReadResponseFromFile(sResponseFile, sOptionalContentTypeHint) : oResponse.ReadResponseFromStream(strmResponse, sOptionalContentTypeHint));
		if (HTTPMethodIs("HEAD"))
		{
			responseBodyBytes = Utilities.emptyByteArray;
		}
		_EnsureStateAtLeast(SessionStates.AutoTamperResponseBefore);
		return bReturn;
	}

	/// <summary>
	/// Replace HTTP response headers and body using the specified stream.
	/// </summary>
	/// <param name="strmResponse">The stream containing the response.</param>
	/// <returns>True if the Stream was successfully loaded.</returns>
	public bool LoadResponseFromStream(Stream strmResponse, string sOptionalContentTypeHint)
	{
		return LoadResponse(strmResponse, null, sOptionalContentTypeHint);
	}

	/// <summary>
	/// Replace HTTP response headers and body using the specified file.
	/// </summary>
	/// <param name="sFilename">The file containing the response.</param>
	/// <returns>True if the file was successfully loaded.</returns>
	[CodeDescription("Replace HTTP response headers and body using the specified file.")]
	public bool LoadResponseFromFile(string sFilename)
	{
		sFilename = Utilities.GetFirstLocalResponse(sFilename);
		try
		{
			FileInfo oFI = new FileInfo(sFilename);
			if (oFI.Length > CONFIG._cb_STREAM_LARGE_FILES)
			{
				SetBitFlag(SessionFlags.ResponseGeneratedByFiddler | SessionFlags.ResponseBodyDropped, b: true);
				oFlags["x-Fiddler-Generated"] = "StreamResponseFromFile";
				oResponse.GenerateHeadersForLocalFile(sFilename);
				__sResponseFileToStream = sFilename;
				responseBodyBytes = Utilities.emptyByteArray;
				return true;
			}
		}
		catch (Exception)
		{
		}
		string sContentTypeHint = Utilities.ContentTypeForFilename(sFilename);
		return LoadResponse(null, sFilename, sContentTypeHint);
	}

	/// <summary>
	/// Return a string generated from the request body, decoding it and converting from a codepage if needed. Throws on errors.
	/// </summary>
	/// <returns>A string containing the request body.</returns>
	[CodeDescription("Return a string generated from the request body, decoding it and converting from a codepage if needed. Possibly expensive due to decompression and will throw on malformed content. Throws on errors.")]
	public string GetRequestBodyAsString()
	{
		if (!_HasRequestBody() || !Utilities.HasHeaders(oRequest))
		{
			return string.Empty;
		}
		byte[] arrCopy;
		if (oRequest.headers.ExistsAny(new string[2] { "Content-Encoding", "Transfer-Encoding" }))
		{
			arrCopy = Utilities.Dupe(requestBodyBytes);
			Utilities.utilDecodeHTTPBody(oRequest.headers, ref arrCopy);
		}
		else
		{
			arrCopy = requestBodyBytes;
		}
		Encoding oEncoding = Utilities.getEntityBodyEncoding(oRequest.headers, arrCopy);
		return Utilities.GetStringFromArrayRemovingBOM(arrCopy, oEncoding);
	}

	/// <summary>
	/// Return a string generated from the response body, decoding it and converting from a codepage if needed. Throws on errors.
	/// </summary>
	/// <returns>A string containing the response body.</returns>
	[CodeDescription("Return a string generated from the response body, decoding it and converting from a codepage if needed. Possibly expensive due to decompression and will throw on malformed content. Throws on errors.")]
	public string GetResponseBodyAsString()
	{
		if (!_HasResponseBody() || !Utilities.HasHeaders(oResponse))
		{
			return string.Empty;
		}
		byte[] arrCopy;
		if (oResponse.headers.ExistsAny(new string[2] { "Content-Encoding", "Transfer-Encoding" }))
		{
			arrCopy = Utilities.Dupe(responseBodyBytes);
			Utilities.utilDecodeHTTPBody(oResponse.headers, ref arrCopy);
		}
		else
		{
			arrCopy = responseBodyBytes;
		}
		Encoding oEncoding = Utilities.getEntityBodyEncoding(oResponse.headers, arrCopy);
		return Utilities.GetStringFromArrayRemovingBOM(arrCopy, oEncoding);
	}

	[CodeDescription("Return a string md5, sha1, sha256, sha384, or sha512 hash of an unchunked and decompressed copy of the response body. Throws on errors.")]
	public string GetResponseBodyHash(string sHashAlg)
	{
		if (!"md5".OICEquals(sHashAlg) && !"sha1".OICEquals(sHashAlg) && !"sha256".OICEquals(sHashAlg) && !"sha384".OICEquals(sHashAlg) && !"sha512".OICEquals(sHashAlg))
		{
			throw new NotImplementedException("Hash algorithm " + sHashAlg + " is not implemented");
		}
		if (!_HasResponseBody() || !Utilities.HasHeaders(oResponse))
		{
			return string.Empty;
		}
		byte[] arrCopy = Utilities.Dupe(responseBodyBytes);
		Utilities.utilDecodeHTTPBody(oResponse.headers, ref arrCopy);
		if (sHashAlg.OICEquals("sha256"))
		{
			return Utilities.GetSHA256Hash(arrCopy);
		}
		if (sHashAlg.OICEquals("sha1"))
		{
			return Utilities.GetSHA1Hash(arrCopy);
		}
		if (sHashAlg.OICEquals("sha512"))
		{
			return Utilities.GetSHA512Hash(arrCopy);
		}
		if (sHashAlg.OICEquals("sha384"))
		{
			return Utilities.GetSHA384Hash(arrCopy);
		}
		if (sHashAlg.OICEquals("md5"))
		{
			return Utilities.GetMD5Hash(arrCopy);
		}
		throw new Exception("Unknown failure");
	}

	[CodeDescription("Return a base64 string md5, sha1, sha256, sha384, or sha512 hash of an unchunked and decompressed copy of the response body. Throws on errors.")]
	public string GetResponseBodyHashAsBase64(string sHashAlgorithm)
	{
		if (!_HasResponseBody() || !Utilities.HasHeaders(oResponse))
		{
			return string.Empty;
		}
		byte[] arrCopy = Utilities.Dupe(responseBodyBytes);
		Utilities.utilDecodeHTTPBody(oResponse.headers, ref arrCopy);
		return Utilities.GetHashAsBase64(sHashAlgorithm, arrCopy);
	}

	/// <summary>
	/// Find the text encoding of the request
	/// WARNING: Will not decompress body to scan for indications of the character set
	/// </summary>
	/// <returns>Returns the Encoding of the requestBodyBytes</returns>
	[CodeDescription("Returns the Encoding of the requestBodyBytes")]
	public Encoding GetRequestBodyEncoding()
	{
		return Utilities.getEntityBodyEncoding(oRequest.headers, requestBodyBytes);
	}

	/// <summary>
	/// Find the text encoding of the response
	/// WARNING: Will not decompress body to scan for indications of the character set
	/// </summary>
	/// <returns>The Encoding of the responseBodyBytes</returns>
	[CodeDescription("Returns the Encoding of the responseBodyBytes")]
	public Encoding GetResponseBodyEncoding()
	{
		return Utilities.getResponseBodyEncoding(this);
	}

	/// <summary>
	/// Returns true if the absolute request URI contains the specified string. Case-insensitive.
	/// </summary>
	/// <param name="sLookfor">Case-insensitive string to find</param>
	/// <returns>TRUE if the URI contains the string</returns>
	[CodeDescription("Returns true if request URI contains the specified string. Case-insensitive.")]
	public bool uriContains(string sLookfor)
	{
		return fullUrl.OICContains(sLookfor);
	}

	/// <summary>
	/// Removes chunking and HTTP Compression from the Response. Adds or updates Content-Length header.
	/// </summary>
	/// <returns>Returns TRUE if the response was decoded; returns FALSE on failure, or if response didn't have headers that showed encoding.</returns>
	[CodeDescription("Removes chunking and HTTP Compression from the response. Adds or updates Content-Length header.")]
	public bool utilDecodeResponse()
	{
		return utilDecodeResponse(bSilent: false);
	}

	/// <summary>
	/// Removes chunking and HTTP Compression from the Response. Adds or updates Content-Length header.
	/// </summary>
	/// <param name="bSilent">TRUE if error messages should be suppressed. False otherwise.</param>
	/// <returns>TRUE if the decoding was successsful.</returns>
	public bool utilDecodeResponse(bool bSilent)
	{
		if (!Utilities.HasHeaders(oResponse) || (!oResponse.headers.Exists("Transfer-Encoding") && !oResponse.headers.Exists("Content-Encoding")))
		{
			return false;
		}
		try
		{
			Utilities.utilTryDecode(oResponse.headers, ref responseBodyBytes, bSilent);
		}
		catch (Exception eX)
		{
			if (CONFIG.bDebugSpew)
			{
				FiddlerApplication.DebugSpew("utilDecodeResponse failed. The HTTP response body was malformed. " + FiddlerCore.Utilities.Utilities.DescribeException(eX));
			}
			if (!bSilent)
			{
				string title = "utilDecodeResponse failed for Session #" + id;
				string message = "The HTTP response body was malformed.";
				FiddlerApplication.Log.LogFormat("{0}: {1}" + Environment.NewLine + "{2}", title, message, eX.ToString());
			}
			oFlags["x-UtilDecodeResponse"] = FiddlerCore.Utilities.Utilities.DescribeException(eX);
			oFlags["ui-backcolor"] = "LightYellow";
			return false;
		}
		return true;
	}

	/// <summary>
	/// Removes chunking and HTTP Compression from the Request. Adds or updates Content-Length header.
	/// </summary>
	/// <returns>Returns TRUE if the request was decoded; returns FALSE on failure, or if request didn't have headers that showed encoding.</returns>
	[CodeDescription("Removes chunking and HTTP Compression from the Request. Adds or updates Content-Length header.")]
	public bool utilDecodeRequest()
	{
		return utilDecodeRequest(bSilent: false);
	}

	public bool utilDecodeRequest(bool bSilent)
	{
		if (!Utilities.HasHeaders(oRequest) || (!oRequest.headers.Exists("Transfer-Encoding") && !oRequest.headers.Exists("Content-Encoding")))
		{
			return false;
		}
		try
		{
			Utilities.utilTryDecode(oRequest.headers, ref requestBodyBytes, bSilent);
		}
		catch (Exception eX)
		{
			if (!bSilent)
			{
				string title = "utilDecodeResponse failed for Session #" + id;
				string message = "The HTTP request body was malformed.";
				FiddlerApplication.Log.LogFormat("{0}: {1}" + Environment.NewLine + "{2}", title, message, eX.ToString());
			}
			oFlags["x-UtilDecodeRequest"] = FiddlerCore.Utilities.Utilities.DescribeException(eX);
			oFlags["ui-backcolor"] = "LightYellow";
			return false;
		}
		return true;
	}

	/// <summary>
	/// Use GZIP to compress the request body. Throws exceptions to caller.
	/// </summary>
	/// <returns>TRUE if compression succeeded</returns>
	[CodeDescription("Use GZIP to compress the request body. Throws exceptions to caller.")]
	public bool utilGZIPRequest()
	{
		if (!_mayCompressRequest())
		{
			return false;
		}
		requestBodyBytes = Utilities.GzipCompress(requestBodyBytes);
		oRequest.headers["Content-Encoding"] = "gzip";
		oRequest.headers["Content-Length"] = ((requestBodyBytes == null) ? "0" : requestBodyBytes.LongLength.ToString());
		return true;
	}

	/// <summary>
	/// Use GZIP to compress the response body. Throws exceptions to caller.
	/// </summary>
	/// <returns>TRUE if compression succeeded</returns>
	[CodeDescription("Use GZIP to compress the response body. Throws exceptions to caller.")]
	public bool utilGZIPResponse()
	{
		if (!_mayCompressResponse())
		{
			return false;
		}
		responseBodyBytes = Utilities.GzipCompress(responseBodyBytes);
		oResponse.headers["Content-Encoding"] = "gzip";
		oResponse.headers["Content-Length"] = ((responseBodyBytes == null) ? "0" : responseBodyBytes.LongLength.ToString());
		return true;
	}

	/// <summary>
	/// Use DEFLATE to compress the response body. Throws exceptions to caller.
	/// </summary>
	/// <returns>TRUE if compression succeeded</returns>
	[CodeDescription("Use DEFLATE to compress the response body. Throws exceptions to caller.")]
	public bool utilDeflateResponse()
	{
		if (!_mayCompressResponse())
		{
			return false;
		}
		responseBodyBytes = Utilities.DeflaterCompress(responseBodyBytes);
		oResponse.headers["Content-Encoding"] = "deflate";
		oResponse.headers["Content-Length"] = ((responseBodyBytes == null) ? "0" : responseBodyBytes.LongLength.ToString());
		return true;
	}

	/// <summary>
	/// Use BZIP2 to compress the response body. Throws exceptions to caller.
	/// </summary>
	/// <returns>TRUE if compression succeeded</returns>
	[CodeDescription("Use BZIP2 to compress the response body. Throws exceptions to caller.")]
	public bool utilBZIP2Response()
	{
		if (!_mayCompressResponse())
		{
			return false;
		}
		responseBodyBytes = Utilities.bzip2Compress(responseBodyBytes);
		oResponse.headers["Content-Encoding"] = "bzip2";
		oResponse.headers["Content-Length"] = ((responseBodyBytes == null) ? "0" : responseBodyBytes.LongLength.ToString());
		return true;
	}

	private bool _mayCompressRequest()
	{
		if (!_HasRequestBody() || oRequest.headers.Exists("Content-Encoding") || oRequest.headers.Exists("Transfer-Encoding"))
		{
			return false;
		}
		return true;
	}

	private bool _mayCompressResponse()
	{
		if (!_HasResponseBody() || oResponse.headers.Exists("Content-Encoding") || oResponse.headers.Exists("Transfer-Encoding"))
		{
			return false;
		}
		return true;
	}

	/// <summary>
	/// Introduces HTTP Chunked encoding on the response body
	/// </summary>
	/// <param name="iSuggestedChunkCount">The number of chunks to try to create</param>
	/// <returns>TRUE if the chunking could be performed.</returns>
	[CodeDescription("Apply Transfer-Encoding: chunked to the response, if possible.")]
	public bool utilChunkResponse(int iSuggestedChunkCount)
	{
		if (!Utilities.HasHeaders(oRequest) || !"HTTP/1.1".OICEquals(oRequest.headers.HTTPVersion) || HTTPMethodIs("HEAD") || HTTPMethodIs("CONNECT") || !Utilities.HasHeaders(oResponse) || !Utilities.HTTPStatusAllowsBody(oResponse.headers.HTTPResponseCode) || (responseBodyBytes != null && responseBodyBytes.LongLength > int.MaxValue) || oResponse.headers.Exists("Transfer-Encoding"))
		{
			return false;
		}
		responseBodyBytes = Utilities.doChunk(responseBodyBytes, iSuggestedChunkCount);
		oResponse.headers.Remove("Content-Length");
		oResponse.headers["Transfer-Encoding"] = "chunked";
		return true;
	}

	/// <summary>
	/// Perform a string replacement on the request body. Adjusts the Content-Length header if needed.
	/// </summary>
	/// <param name="sSearchFor">The case-sensitive string to search for.</param>
	/// <param name="sReplaceWith">The text to replace.</param>
	/// <returns>TRUE if one or more replacements occurred.</returns>
	[CodeDescription("Perform a case-sensitive string replacement on the request body (not URL!). Updates Content-Length header. Returns TRUE if replacements occur.")]
	public bool utilReplaceInRequest(string sSearchFor, string sReplaceWith)
	{
		if (!_HasRequestBody() || !Utilities.HasHeaders(oRequest))
		{
			return false;
		}
		string sBody = GetRequestBodyAsString();
		string sNewBody = sBody.Replace(sSearchFor, sReplaceWith);
		if (sBody != sNewBody)
		{
			utilSetRequestBody(sNewBody);
			return true;
		}
		return false;
	}

	/// <summary>
	/// Call inside OnBeforeRequest to create a response object and bypass the server.
	/// </summary>
	[CodeDescription("Call inside OnBeforeRequest to create a Response object and bypass the server.")]
	public void utilCreateResponseAndBypassServer()
	{
		if (state > SessionStates.SendingRequest)
		{
			throw new InvalidOperationException("Too late, we're already talking to the server.");
		}
		if (isFlagSet(SessionFlags.RequestStreamed))
		{
			oResponse.StreamRequestBody();
		}
		oResponse = new ServerChatter(this, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
		responseBodyBytes = Utilities.emptyByteArray;
		oFlags["x-Fiddler-Generated"] = "utilCreateResponseAndBypassServer";
		BitFlags |= SessionFlags.ResponseGeneratedByFiddler;
		bBufferResponse = true;
		state = SessionStates.AutoTamperResponseBefore;
	}

	[CodeDescription("Copy an existing Session's response to this Session, bypassing the server if not already contacted")]
	public void utilAssignResponse(Session oFromSession)
	{
		utilAssignResponse(oFromSession.oResponse.headers, oFromSession.responseBodyBytes);
	}

	[CodeDescription("Copy an existing response to this Session, bypassing the server if not already contacted")]
	public void utilAssignResponse(HTTPResponseHeaders oRH, byte[] arrBody)
	{
		if (oResponse == null)
		{
			oResponse = new ServerChatter(this, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
		}
		if (oRH == null)
		{
			oResponse.headers = new HTTPResponseHeaders();
			oResponse.headers.SetStatus(200, "Fiddler-Generated");
		}
		else
		{
			oResponse.headers = (HTTPResponseHeaders)oRH.Clone();
		}
		responseBodyBytes = arrBody ?? Utilities.emptyByteArray;
		oFlags["x-Fiddler-Generated"] = "utilAssignResponse";
		BitFlags |= SessionFlags.ResponseGeneratedByFiddler;
		bBufferResponse = true;
		state = SessionStates.AutoTamperResponseBefore;
	}

	/// <summary>
	/// Perform a regex-based string replacement on the response body. Adjusts the Content-Length header if needed. 
	/// </summary>
	/// <param name="sSearchForRegEx">The regular expression used to search the body. Specify RegEx Options via leading Inline Flags, e.g. (?im) for case-Insensitive Multi-line.</param>
	/// <param name="sReplaceWithExpression">The text or expression used to replace</param>
	/// <returns>TRUE if replacements occured</returns>
	[CodeDescription("Perform a regex-based replacement on the response body. Specify RegEx Options via leading Inline Flags, e.g. (?im) for case-Insensitive Multi-line. Updates Content-Length header. Note, you should call utilDecodeResponse first!  Returns TRUE if replacements occur.")]
	public bool utilReplaceRegexInResponse(string sSearchForRegEx, string sReplaceWithExpression)
	{
		if (!_HasResponseBody())
		{
			return false;
		}
		Encoding oEncoding = Utilities.getResponseBodyEncoding(this);
		string sArray = oEncoding.GetString(responseBodyBytes);
		string sArray2 = Regex.Replace(sArray, sSearchForRegEx, sReplaceWithExpression, RegexOptions.ExplicitCapture | RegexOptions.Singleline);
		if (sArray != sArray2)
		{
			responseBodyBytes = oEncoding.GetBytes(sArray2);
			oResponse["Content-Length"] = responseBodyBytes.LongLength.ToString();
			return true;
		}
		return false;
	}

	/// <summary>
	/// Perform a string replacement on the response body (potentially multiple times). Adjust the Content-Length header if needed. 
	/// </summary>
	/// <param name="sSearchFor">String to find (case-sensitive)</param>
	/// <param name="sReplaceWith">String to use to replace</param>
	/// <returns>TRUE if replacements occurred</returns>
	[CodeDescription("Perform a case-sensitive string replacement on the response body. Updates Content-Length header. Note, you should call utilDecodeResponse first!  Returns TRUE if replacements occur.")]
	public bool utilReplaceInResponse(string sSearchFor, string sReplaceWith)
	{
		return _innerReplaceInResponse(sSearchFor, sReplaceWith, bReplaceAll: true, bCaseSensitive: true);
	}

	/// <summary>
	/// Perform a one-time string replacement on the response body. Adjust the Content-Length header if needed. 
	/// </summary>
	/// <param name="sSearchFor">String to find (case-sensitive)</param>
	/// <param name="sReplaceWith">String to use to replace</param>
	/// <param name="bCaseSensitive">TRUE for Case-Sensitive</param>
	/// <returns>TRUE if a replacement occurred</returns>
	[CodeDescription("Perform a single case-sensitive string replacement on the response body. Updates Content-Length header. Note, you should call utilDecodeResponse first! Returns TRUE if replacements occur.")]
	public bool utilReplaceOnceInResponse(string sSearchFor, string sReplaceWith, bool bCaseSensitive)
	{
		return _innerReplaceInResponse(sSearchFor, sReplaceWith, bReplaceAll: false, bCaseSensitive);
	}

	private bool _innerReplaceInResponse(string sSearchFor, string sReplaceWith, bool bReplaceAll, bool bCaseSensitive)
	{
		if (!_HasResponseBody())
		{
			return false;
		}
		Encoding oEncoding = Utilities.getResponseBodyEncoding(this);
		string sArray = oEncoding.GetString(responseBodyBytes);
		string sArray2;
		if (bReplaceAll)
		{
			sArray2 = sArray.Replace(sSearchFor, sReplaceWith);
		}
		else
		{
			int iX = sArray.IndexOf(sSearchFor, bCaseSensitive ? StringComparison.InvariantCulture : StringComparison.InvariantCultureIgnoreCase);
			if (iX == 0)
			{
				sArray2 = sReplaceWith + sArray.Substring(sSearchFor.Length);
			}
			else
			{
				if (iX <= 0)
				{
					return false;
				}
				sArray2 = sArray.Substring(0, iX) + sReplaceWith + sArray.Substring(iX + sSearchFor.Length);
			}
		}
		if (sArray != sArray2)
		{
			responseBodyBytes = oEncoding.GetBytes(sArray2);
			oResponse["Content-Length"] = responseBodyBytes.LongLength.ToString();
			return true;
		}
		return false;
	}

	/// <summary>
	/// Replaces the request body with sString. Sets Content-Length header and removes Transfer-Encoding/Content-Encoding.
	/// </summary>
	/// <param name="sString">The desired request Body as a string</param>
	[CodeDescription("Replaces the request body with sString. Sets Content-Length header & removes Transfer-Encoding/Content-Encoding")]
	public void utilSetRequestBody(string sString)
	{
		if (sString == null)
		{
			sString = string.Empty;
		}
		oRequest.headers.Remove("Transfer-Encoding");
		oRequest.headers.Remove("Content-Encoding");
		Encoding oEnc = Utilities.getEntityBodyEncoding(oRequest.headers, null);
		requestBodyBytes = oEnc.GetBytes(sString);
		oRequest["Content-Length"] = requestBodyBytes.LongLength.ToString();
	}

	/// <summary>
	/// Replaces the response body with sString. Sets Content-Length header and removes Transfer-Encoding/Content-Encoding
	/// </summary>
	/// <param name="sString">The desired response Body as a string</param>
	[CodeDescription("Replaces the response body with sString. Sets Content-Length header & removes Transfer-Encoding/Content-Encoding")]
	public void utilSetResponseBody(string sString)
	{
		if (sString == null)
		{
			sString = string.Empty;
		}
		oResponse.headers.Remove("Transfer-Encoding");
		oResponse.headers.Remove("Content-Encoding");
		Encoding oEnc = Utilities.getResponseBodyEncoding(this);
		responseBodyBytes = oEnc.GetBytes(sString);
		oResponse["Content-Length"] = responseBodyBytes.LongLength.ToString();
	}

	/// <summary>
	/// Add a string to the top of the response body, updating Content-Length. (Call utilDecodeResponse first!)
	/// </summary>
	/// <param name="sString">The string to prepend</param>
	[CodeDescription("Prepend a string to the response body. Updates Content-Length header. Note, you should call utilDecodeResponse first!")]
	public void utilPrependToResponseBody(string sString)
	{
		if (responseBodyBytes == null)
		{
			responseBodyBytes = Utilities.emptyByteArray;
		}
		Encoding oEnc = Utilities.getResponseBodyEncoding(this);
		responseBodyBytes = Utilities.JoinByteArrays(oEnc.GetBytes(sString), responseBodyBytes);
		oResponse.headers["Content-Length"] = responseBodyBytes.LongLength.ToString();
	}

	/// <summary>
	/// Find a string in the request body. Return its index, or -1.
	/// </summary>
	/// <param name="sSearchFor">Term to search for</param>
	/// <param name="bCaseSensitive">Require case-sensitive match?</param>
	/// <returns>Location of sSearchFor,or -1</returns>
	[CodeDescription("Find a string in the request body. Return its index or -1.")]
	public int utilFindInRequest(string sSearchFor, bool bCaseSensitive)
	{
		if (!_HasRequestBody())
		{
			return -1;
		}
		string sBody = Utilities.getEntityBodyEncoding(oRequest.headers, requestBodyBytes).GetString(requestBodyBytes);
		return sBody.IndexOf(sSearchFor, bCaseSensitive ? StringComparison.InvariantCulture : StringComparison.InvariantCultureIgnoreCase);
	}

	private bool _HasRequestBody()
	{
		return !Utilities.IsNullOrEmpty(requestBodyBytes);
	}

	private bool _HasResponseBody()
	{
		return !Utilities.IsNullOrEmpty(responseBodyBytes);
	}

	/// <summary>
	/// Find a string in the response body. Return its index, or -1.
	/// </summary>
	/// <param name="sSearchFor">Term to search for</param>
	/// <param name="bCaseSensitive">Require case-sensitive match?</param>
	/// <returns>Location of sSearchFor,or -1</returns>
	[CodeDescription("Find a string in the response body. Return its index or -1. Note, you should call utilDecodeResponse first!")]
	public int utilFindInResponse(string sSearchFor, bool bCaseSensitive)
	{
		if (!_HasResponseBody())
		{
			return -1;
		}
		string sBody = Utilities.getResponseBodyEncoding(this).GetString(responseBodyBytes);
		return sBody.IndexOf(sSearchFor, bCaseSensitive ? StringComparison.InvariantCulture : StringComparison.InvariantCultureIgnoreCase);
	}

	/// <summary>
	/// Reset the SessionID counter to 0. This method can lead to confusing UI, so use sparingly.
	/// </summary>
	[CodeDescription("Reset the SessionID counter to 0. This method can lead to confusing UI, so use sparingly.")]
	internal static void ResetSessionCounter()
	{
		OnBeforeSessionCounterReset();
		Interlocked.Exchange(ref cRequests, 0);
	}

	private static void OnBeforeSessionCounterReset()
	{
		beforeSessionCounterReset?.Invoke(null, EventArgs.Empty);
	}

	/// <summary>
	/// Create a Session object from two byte[] representing request and response.
	/// </summary>
	/// <param name="arrRequest">The client data bytes</param>
	/// <param name="arrResponse">The server data bytes</param>
	public Session(byte[] arrRequest, byte[] arrResponse)
	{
		ConstructSession(arrRequest, arrResponse, SessionFlags.None);
		RaiseSessionCreated();
	}

	/// <summary>
	/// Create a Session object from a (serializable) SessionData object
	/// </summary>
	/// <param name="oSD"></param>
	public Session(SessionData oSD)
	{
		ConstructSession(oSD.arrRequest, oSD.arrResponse, SessionFlags.None);
		LoadMetadata(new MemoryStream(oSD.arrMetadata));
		if (oSD.arrWebSocketMessages != null && oSD.arrWebSocketMessages.Length != 0)
		{
			WebSocket.LoadWebSocketMessagesFromStream(this, new MemoryStream(oSD.arrWebSocketMessages));
		}
		RaiseSessionCreated();
	}

	/// <summary>
	/// Create a Session object from two byte[] representing request and response. This is used when loading a Session Archive Zip.
	/// </summary>
	/// <param name="arrRequest">The client data bytes</param>
	/// <param name="arrResponse">The server data bytes</param>
	/// <param name="oSF">SessionFlags for this session</param>
	public Session(byte[] arrRequest, byte[] arrResponse, SessionFlags oSF)
	{
		ConstructSession(arrRequest, arrResponse, oSF);
		RaiseSessionCreated();
	}

	private void ConstructSession(byte[] arrRequest, byte[] arrResponse, SessionFlags oSF)
	{
		if (Utilities.IsNullOrEmpty(arrRequest))
		{
			arrRequest = Encoding.ASCII.GetBytes("GET http://MISSING-REQUEST/? HTTP/0.0\r\nHost:MISSING-REQUEST\r\nX-Fiddler-Generated: Request Data was missing\r\n\r\n");
		}
		if (Utilities.IsNullOrEmpty(arrResponse))
		{
			arrResponse = Encoding.ASCII.GetBytes("HTTP/1.1 0 FIDDLER GENERATED - RESPONSE DATA WAS MISSING\r\n\r\n");
		}
		state = SessionStates.Done;
		m_requestID = Interlocked.Increment(ref cRequests);
		BitFlags = oSF;
		if (!Parser.FindEntityBodyOffsetFromArray(arrRequest, out var iRequestHeadersLen, out var iRequestEntityOffset, out var hpwDontCare))
		{
			throw new InvalidDataException("Request corrupt, unable to find end of headers.");
		}
		if (!Parser.FindEntityBodyOffsetFromArray(arrResponse, out var iResponseHeadersLen, out var iResponseEntityOffset, out hpwDontCare))
		{
			throw new InvalidDataException("Response corrupt, unable to find end of headers.");
		}
		requestBodyBytes = new byte[arrRequest.Length - iRequestEntityOffset];
		responseBodyBytes = new byte[arrResponse.Length - iResponseEntityOffset];
		Buffer.BlockCopy(arrRequest, iRequestEntityOffset, requestBodyBytes, 0, requestBodyBytes.Length);
		Buffer.BlockCopy(arrResponse, iResponseEntityOffset, responseBodyBytes, 0, responseBodyBytes.Length);
		string sRequestHeaders = CONFIG.oHeaderEncoding.GetString(arrRequest, 0, iRequestHeadersLen) + "\r\n\r\n";
		string sResponseHeaders = CONFIG.oHeaderEncoding.GetString(arrResponse, 0, iResponseHeadersLen) + "\r\n\r\n";
		oRequest = new ClientChatter(this, sRequestHeaders);
		oResponse = new ServerChatter(this, sResponseHeaders);
	}

	/// <summary>
	/// Creates a new session and attaches it to the pipes passed as arguments
	/// </summary>
	/// <param name="clientPipe">The client pipe from which the request is read and to which the response is written.</param>
	/// <param name="serverPipe">The server pipe to which the request is sent and from which the response is read. May be null.</param>
	internal Session(ClientPipe clientPipe, ServerPipe serverPipe)
	{
		if (CONFIG.bDebugSpew)
		{
			OnStateChanged += delegate(object s, StateChangeEventArgs ea)
			{
				FiddlerApplication.DebugSpew("onstatechange>#{0} moving from state '{1}' to '{2}' {3}", id.ToString(), ea.oldState, ea.newState, Environment.StackTrace);
			};
		}
		if (clientPipe != null)
		{
			Timers.ClientConnected = clientPipe.dtAccepted;
			m_clientIP = ((clientPipe.Address == null) ? null : clientPipe.Address.ToString());
			m_clientPort = clientPipe.Port;
			oFlags["x-clientIP"] = m_clientIP;
			oFlags["x-clientport"] = m_clientPort.ToString();
			if (clientPipe.LocalProcessID != 0)
			{
				_LocalProcessID = clientPipe.LocalProcessID;
				oFlags["x-ProcessInfo"] = $"{clientPipe.LocalProcessName}:{_LocalProcessID}";
			}
		}
		else
		{
			Timers.ClientConnected = DateTime.Now;
		}
		oResponse = new ServerChatter(this);
		oRequest = new ClientChatter(this);
		oRequest.pipeClient = clientPipe;
		oResponse.pipeServer = serverPipe;
		RaiseSessionCreated();
	}

	/// <summary>
	/// Initialize a new session from a given request headers and body request builder data. Note: No Session ID is assigned here.
	/// </summary>
	/// <param name="oRequestHeaders">NB: If you're copying an existing request, use oRequestHeaders.Clone()</param>
	/// <param name="arrRequestBody">The bytes of the request's body</param>
	public Session(HTTPRequestHeaders oRequestHeaders, byte[] arrRequestBody)
	{
		ConstructSession(oRequestHeaders, arrRequestBody);
		RaiseSessionCreated();
	}

	private void ConstructSession(HTTPRequestHeaders oRequestHeaders, byte[] arrRequestBody)
	{
		if (oRequestHeaders == null)
		{
			throw new ArgumentNullException("oRequestHeaders", "oRequestHeaders must not be null when creating a new Session.");
		}
		if (arrRequestBody == null)
		{
			arrRequestBody = Utilities.emptyByteArray;
		}
		if (CONFIG.bDebugSpew)
		{
			OnStateChanged += delegate(object s, StateChangeEventArgs ea)
			{
				FiddlerApplication.DebugSpew("onstatechange>#{0} moving from state '{1}' to '{2}' {3}", id.ToString(), ea.oldState, ea.newState, Environment.StackTrace);
			};
		}
		Timers.ClientConnected = (Timers.ClientBeginRequest = (Timers.FiddlerGotRequestHeaders = DateTime.Now));
		m_clientIP = null;
		m_clientPort = 0;
		oFlags["x-clientIP"] = m_clientIP;
		oFlags["x-clientport"] = m_clientPort.ToString();
		oResponse = new ServerChatter(this);
		oRequest = new ClientChatter(this);
		oRequest.pipeClient = null;
		oResponse.pipeServer = null;
		oRequest.headers = oRequestHeaders;
		requestBodyBytes = arrRequestBody;
		m_state = SessionStates.AutoTamperRequestBefore;
	}

	/// <summary>
	/// Copy Constructor. <seealso cref="M:Fiddler.Session.BuildFromData(System.Boolean,Fiddler.HTTPRequestHeaders,System.Byte[],Fiddler.HTTPResponseHeaders,System.Byte[],Fiddler.SessionFlags)" />.
	/// </summary>
	/// <param name="toDeepCopy">Session to clone into a new Session instance</param>
	public Session(Session toDeepCopy)
	{
		ConstructSession((HTTPRequestHeaders)toDeepCopy.RequestHeaders.Clone(), Utilities.Dupe(toDeepCopy.requestBodyBytes));
		_AssignID();
		SetBitFlag(toDeepCopy._bitFlags, b: true);
		foreach (string sKey in toDeepCopy.oFlags.Keys)
		{
			oFlags[sKey] = toDeepCopy.oFlags[sKey];
		}
		oResponse.headers = (HTTPResponseHeaders)toDeepCopy.ResponseHeaders.Clone();
		responseBodyBytes = Utilities.Dupe(toDeepCopy.responseBodyBytes);
		state = SessionStates.Done;
		Timers = toDeepCopy.Timers.Clone();
		RaiseSessionCreated();
	}

	/// <summary>
	/// Factory constructor
	/// </summary>
	/// <param name="bClone"></param>
	/// <param name="headersRequest"></param>
	/// <param name="arrRequestBody"></param>
	/// <param name="headersResponse"></param>
	/// <param name="arrResponseBody"></param>
	/// <param name="oSF"></param>
	/// <returns></returns>
	public static Session BuildFromData(bool bClone, HTTPRequestHeaders headersRequest, byte[] arrRequestBody, HTTPResponseHeaders headersResponse, byte[] arrResponseBody, SessionFlags oSF)
	{
		if (headersRequest == null)
		{
			headersRequest = new HTTPRequestHeaders();
			headersRequest.HTTPMethod = "GET";
			headersRequest.HTTPVersion = "HTTP/1.1";
			headersRequest.UriScheme = "http";
			headersRequest.Add("Host", "localhost");
			headersRequest.RequestPath = "/" + DateTime.Now.Ticks;
		}
		else if (bClone)
		{
			headersRequest = (HTTPRequestHeaders)headersRequest.Clone();
		}
		if (headersResponse == null)
		{
			headersResponse = new HTTPResponseHeaders();
			headersResponse.SetStatus(200, "OK");
			headersResponse.HTTPVersion = "HTTP/1.1";
			headersResponse.Add("Connection", "close");
		}
		else if (bClone)
		{
			headersResponse = (HTTPResponseHeaders)headersResponse.Clone();
		}
		if (arrRequestBody == null)
		{
			arrRequestBody = Utilities.emptyByteArray;
		}
		else if (bClone)
		{
			arrRequestBody = (byte[])arrRequestBody.Clone();
		}
		if (arrResponseBody == null)
		{
			arrResponseBody = Utilities.emptyByteArray;
		}
		else if (bClone)
		{
			arrResponseBody = (byte[])arrResponseBody.Clone();
		}
		Session oResult = new Session(headersRequest, arrRequestBody);
		oResult._AssignID();
		oResult.SetBitFlag(oSF, b: true);
		oResult.oResponse.headers = headersResponse;
		oResult.responseBodyBytes = arrResponseBody;
		oResult.state = SessionStates.Done;
		return oResult;
	}

	internal void ExecuteOnThreadPool()
	{
		ThreadPool.UnsafeQueueUserWorkItem(Execute, DateTime.Now);
	}

	internal void ExecuteWhenDataAvailable()
	{
		if (m_state > SessionStates.ReadingRequest)
		{
			ExecuteOnThreadPool();
		}
		else
		{
			if (oRequest == null || oRequest.pipeClient == null)
			{
				return;
			}
			if (oRequest.pipeClient.HasDataAvailable())
			{
				ExecuteOnThreadPool();
				return;
			}
			Socket oSock = oRequest.pipeClient.GetRawSocket();
			if (oSock == null)
			{
				return;
			}
			oSock.ReceiveTimeout = ClientPipe._timeoutIdle;
			Interlocked.Increment(ref COUNTERS.ASYNC_WAIT_CLIENT_REUSE);
			Interlocked.Increment(ref COUNTERS.TOTAL_ASYNC_WAIT_CLIENT_REUSE);
			oSock.BeginReceive(new byte[1], 0, 1, SocketFlags.Peek, out var err, delegate(IAsyncResult arOutcome)
			{
				Interlocked.Decrement(ref COUNTERS.ASYNC_WAIT_CLIENT_REUSE);
				int num = 0;
				try
				{
					num = oSock.EndReceive(arOutcome, out var _);
				}
				catch (Exception eX)
				{
					if (CONFIG.bDebugSpew)
					{
						FiddlerApplication.DebugSpew("! SocketReuse EndReceive threw {0} for {1}", FiddlerCore.Utilities.Utilities.DescribeException(eX), (oSock.RemoteEndPoint as IPEndPoint).Port);
					}
					num = -1;
				}
				if (num < 1)
				{
					if (oRequest.pipeClient != null)
					{
						oRequest.pipeClient.End();
					}
				}
				else
				{
					Execute(null);
				}
			}, null);
			if (err != 0 && err != SocketError.IOPending)
			{
				Interlocked.Decrement(ref COUNTERS.ASYNC_WAIT_CLIENT_REUSE);
				if (oRequest.pipeClient != null)
				{
					oRequest.pipeClient.End();
				}
			}
		}
	}

	internal Task ExecuteAsync(object objThreadState)
	{
		return Task.Factory.StartNew(delegate
		{
			ManualResetEvent resetEvent = new ManualResetEvent(initialState: false);
			OnStateChanged += delegate(object s, StateChangeEventArgs e)
			{
				if (e.newState >= SessionStates.Done)
				{
					resetEvent.Set();
				}
			};
			Execute(objThreadState);
			resetEvent.WaitOne();
		});
	}

	/// <summary>
	/// Called when the Session is ready to begin processing. Eats exceptions to prevent unhandled exceptions on background threads from killing the application.
	/// </summary>
	/// <param name="objThreadState">Unused parameter (required by ThreadPool)</param>
	internal void Execute(object objThreadState)
	{
		try
		{
			InnerExecute();
		}
		catch (Exception eX)
		{
			string title = "Uncaught Exception in Session #" + id;
			FiddlerApplication.Log.LogFormat("{0}: {1}", title, eX.ToString());
		}
	}

	internal void RunStateMachine()
	{
		bool bAsyncExit = false;
		do
		{
			switch (_pState)
			{
			case ProcessingStates.GetRequestStart:
				if (!_executeObtainRequest())
				{
					_pState = ProcessingStates.Finished;
				}
				else
				{
					_pState++;
				}
				break;
			case ProcessingStates.PauseForRequestTampering:
				_pState++;
				break;
			case ProcessingStates.ResumeFromRequestTampering:
				_EnsureStateAtLeast(SessionStates.AutoTamperRequestAfter);
				_pState++;
				break;
			case ProcessingStates.GetRequestEnd:
				if (m_state >= SessionStates.Done)
				{
					return;
				}
				_smCheckForAutoReply();
				if (HTTPMethodIs("CONNECT"))
				{
					isTunnel = true;
					if (oFlags.ContainsKey("x-replywithtunnel"))
					{
						_ReturnSelfGeneratedCONNECTTunnel(hostname);
						_pState = ProcessingStates.Finished;
						break;
					}
				}
				if (m_state >= SessionStates.ReadingResponse)
				{
					if (isAnyFlagSet(SessionFlags.ResponseGeneratedByFiddler))
					{
						FiddlerApplication.DoResponseHeadersAvailable(this);
					}
					_pState = ProcessingStates.ReadResponseEnd;
					break;
				}
				_smValidateRequestPort();
				if (_smReplyWithFile())
				{
					_pState = ProcessingStates.ReadResponseEnd;
					break;
				}
				if (_isDirectRequestToFiddler())
				{
					if (oRequest.headers.RequestPath.OICEndsWith(".pac"))
					{
						if (oRequest.headers.RequestPath.OICEndsWith("/proxy.pac"))
						{
							_returnPACFileResponse();
							_pState = ProcessingStates.Finished;
							break;
						}
						if (oRequest.headers.RequestPath.OICEndsWith("/UpstreamProxy.pac"))
						{
							_returnUpstreamPACFileResponse();
							_pState = ProcessingStates.Finished;
							break;
						}
					}
					if (oRequest.headers.RequestPath.OICEndsWith("/fiddlerroot.cer"))
					{
						_returnRootCert(this);
						_pState = ProcessingStates.Finished;
						break;
					}
					if (CONFIG.iReverseProxyForPort == 0)
					{
						_returnEchoServiceResponse();
						_pState = ProcessingStates.Finished;
						break;
					}
					oFlags.Add("X-ReverseProxy", "1");
					host = $"{CONFIG.sReverseProxyHostname}:{CONFIG.iReverseProxyForPort}";
				}
				if (_pState == ProcessingStates.GetRequestEnd)
				{
					_pState++;
				}
				break;
			case ProcessingStates.ConnectStart:
				state = SessionStates.SendingRequest;
				if (isFTP && !isFlagSet(SessionFlags.SentToGateway))
				{
					_pState = ProcessingStates.ReadResponseStart;
					break;
				}
				oResponse.BeginAsyncConnectToHost(delegate
				{
					if (state >= SessionStates.Done)
					{
						_pState = ProcessingStates.Finished;
					}
					else
					{
						_pState++;
					}
					RunStateMachine();
				});
				bAsyncExit = true;
				break;
			case ProcessingStates.SendRequestStart:
			{
				_EnsureStateAtLeast(SessionStates.SendingRequest);
				bool bSendSucceeded = false;
				try
				{
					oResponse.SendRequest();
					bSendSucceeded = true;
				}
				catch (Exception eX)
				{
					if (oResponse._MayRetryWhenSendFailed())
					{
						oResponse.pipeServer = null;
						oFlags["x-RetryOnFailedSend"] += "*";
						FiddlerApplication.DebugSpew("[{0}] ServerSocket Reuse failed during SendRequest(). Restarting fresh.", id);
						_pState = ProcessingStates.ConnectStart;
						break;
					}
					FiddlerApplication.DebugSpew("SendRequest() failed: {0}", FiddlerCore.Utilities.Utilities.DescribeException(eX));
					oRequest.FailSession(504, "Fiddler - Send Failure", "[Fiddler] SendRequest() failed: " + FiddlerCore.Utilities.Utilities.DescribeException(eX));
				}
				if (oFlags.ContainsKey("log-drop-request-body") && !Utilities.IsNullOrEmpty(requestBodyBytes) && !isAnyFlagSet(SessionFlags.RequestStreamed | SessionFlags.IsRPCTunnel))
				{
					_smDropRequestBody();
				}
				if (!bSendSucceeded)
				{
					CloseSessionPipes(bNullThemToo: true);
					state = SessionStates.Aborted;
					_pState = ProcessingStates.Finished;
					break;
				}
				if (isFlagSet(SessionFlags.RequestStreamed) && !oResponse.StreamRequestBody())
				{
					CloseSessionPipes(bNullThemToo: true);
					state = SessionStates.Aborted;
					_pState = ProcessingStates.Finished;
					break;
				}
				Timers.ServerGotRequest = DateTime.Now;
				if (isFlagSet(SessionFlags.IsRPCTunnel))
				{
					bool bTunnelResponseImmediately = false;
					GenericTunnel.CreateTunnel(this, bTunnelResponseImmediately);
					if (bTunnelResponseImmediately)
					{
						_pState = ProcessingStates.Finished;
						break;
					}
				}
				_pState++;
				break;
			}
			case ProcessingStates.ReadResponseStart:
				state = SessionStates.ReadingResponse;
				if (HTTPMethodIs("CONNECT") && !oResponse.m_bWasForwarded)
				{
					_BuildConnectionEstablishedReply();
				}
				else
				{
					if (!oResponse.ReadResponse())
					{
						if (_MayRetryWhenReceiveFailed())
						{
							FiddlerApplication.DebugSpew("[{0}] ServerSocket Reuse failed. Restarting fresh.", id);
							oFlags["x-RetryOnFailedReceive"] += "*";
							oResponse.Initialize(bAllocatePipeReadBuffer: true);
							_pState = ProcessingStates.ConnectStart;
							break;
						}
						FiddlerApplication.DebugSpew("Failed to read server response and retry is forbidden. Aborting Session #{0}", id);
						oResponse.FreeResponseDataBuffer();
						if (state != SessionStates.Aborted)
						{
							string sErrorBody = string.Empty;
							if (!Utilities.IsNullOrEmpty(responseBodyBytes))
							{
								sErrorBody = Encoding.UTF8.GetString(responseBodyBytes);
							}
							sErrorBody = $"[Fiddler] ReadResponse() failed: The server did not return a complete response for this request. Server returned {oResponse.m_responseTotalDataCount:N0} bytes. {sErrorBody}";
							if (!oResponse.bLeakedHeaders)
							{
								oRequest.FailSession(504, "Fiddler - Receive Failure", sErrorBody);
							}
							else
							{
								try
								{
									_BuildReceiveFailureReply(sErrorBody);
									oRequest.pipeClient.EndWithRST();
								}
								catch
								{
								}
							}
						}
						CloseSessionPipes(bNullThemToo: true);
						state = SessionStates.Aborted;
						_pState = ProcessingStates.Finished;
						break;
					}
					if (200 == responseCode && isFlagSet(SessionFlags.IsRPCTunnel))
					{
						_smInitiateRPCStreaming();
						_pState = ProcessingStates.Finished;
						break;
					}
					if (isAnyFlagSet(SessionFlags.ResponseBodyDropped))
					{
						responseBodyBytes = Utilities.emptyByteArray;
						oResponse.FreeResponseDataBuffer();
					}
					else
					{
						responseBodyBytes = oResponse.TakeEntity();
						if (oResponse.headers.Exists("Content-Length") && !HTTPMethodIs("HEAD") && long.TryParse(oResponse.headers["Content-Length"], NumberStyles.Integer, NumberFormatInfo.InvariantInfo, out var iEntityLength) && iEntityLength != responseBodyBytes.LongLength)
						{
							FiddlerApplication.HandleHTTPError(this, SessionFlags.ProtocolViolationInResponse, bPoisonClientConnection: true, bPoisonServerConnection: true, $"Content-Length mismatch: Response Header indicated {iEntityLength:N0} bytes, but server sent {responseBodyBytes.LongLength:N0} bytes.");
						}
					}
				}
				_pState++;
				break;
			case ProcessingStates.ReadResponseEnd:
				if (!isFlagSet(SessionFlags.ResponseBodyDropped))
				{
					oFlags["x-ResponseBodyTransferLength"] = ((responseBodyBytes == null) ? "0" : responseBodyBytes.LongLength.ToString("N0"));
				}
				state = SessionStates.AutoTamperResponseBefore;
				_pState++;
				break;
			case ProcessingStates.RunResponseRulesStart:
				FiddlerApplication.DoBeforeResponse(this);
				if (_smIsResponseAutoHandled())
				{
					_pState = ProcessingStates.Finished;
					break;
				}
				if (m_state >= SessionStates.Done || isFlagSet(SessionFlags.ResponseStreamed))
				{
					FinishUISession();
					if (isFlagSet(SessionFlags.ResponseStreamed) && oFlags.ContainsKey("log-drop-response-body"))
					{
						SetBitFlag(SessionFlags.ResponseBodyDropped, b: true);
						responseBodyBytes = Utilities.emptyByteArray;
					}
					bLeakedResponseAlready = true;
				}
				if (bLeakedResponseAlready)
				{
					_EnsureStateAtLeast(SessionStates.Done);
					FiddlerApplication.DoAfterSessionComplete(this);
					_pState = ProcessingStates.ReturnBufferedResponseStart;
					break;
				}
				if (oFlags.ContainsKey("x-replywithfile"))
				{
					LoadResponseFromFile(oFlags["x-replywithfile"]);
					oFlags["x-replacedwithfile"] = oFlags["x-replywithfile"];
					oFlags.Remove("x-replywithfile");
				}
				_pState++;
				break;
			case ProcessingStates.PauseForResponseTampering:
				_pState++;
				break;
			case ProcessingStates.ResumeFromResponseTampering:
				if (oSyncEvent != null)
				{
					oSyncEvent.Close();
					oSyncEvent = null;
				}
				if (m_state >= SessionStates.Done)
				{
					_pState = ProcessingStates.Finished;
					break;
				}
				state = SessionStates.AutoTamperResponseAfter;
				_pState++;
				break;
			case ProcessingStates.ReturnBufferedResponseStart:
			{
				bool bIsNTLMType2 = false;
				if (_isResponseMultiStageAuthChallenge())
				{
					bIsNTLMType2 = _isNTLMType2();
				}
				if (m_state >= SessionStates.Done)
				{
					FinishUISession();
					bLeakedResponseAlready = true;
				}
				if (!bLeakedResponseAlready)
				{
					ReturnResponse(bIsNTLMType2);
				}
				if (bLeakedResponseAlready && oRequest.pipeClient != null)
				{
					if (bIsNTLMType2 || _MayReuseMyClientPipe())
					{
						_createNextSession(bIsNTLMType2);
					}
					else
					{
						oRequest.pipeClient.End();
					}
					oRequest.pipeClient = null;
				}
				_pState++;
				break;
			}
			case ProcessingStates.ReturnBufferedResponseEnd:
				oResponse.releaseServerPipe();
				_pState++;
				break;
			case ProcessingStates.DoAfterSessionEventStart:
				_pState++;
				break;
			case ProcessingStates.Finished:
				_EnsureStateAtLeast(SessionStates.Done);
				if (nextSession != null)
				{
					nextSession.ExecuteWhenDataAvailable();
					nextSession = null;
				}
				bAsyncExit = true;
				break;
			default:
				if ((int)_pState > 29)
				{
					FiddlerApplication.Log.LogFormat("! CRITICAL ERROR: State machine will live forever... Session {0} with state {1} has pState {2}", id, state, _pState);
					bAsyncExit = true;
				}
				_pState++;
				break;
			}
		}
		while (!bAsyncExit);
	}

	/// <summary>
	/// InnerExecute() implements Fiddler's HTTP Pipeline
	/// </summary>
	private void InnerExecute()
	{
		if (oRequest != null && oResponse != null)
		{
			RunStateMachine();
		}
	}

	/// <summary>
	/// Initiate bi-directional streaming on the RPC connection
	/// </summary>
	private void _smInitiateRPCStreaming()
	{
		responseBodyBytes = oResponse.TakeEntity();
		try
		{
			oRequest.pipeClient.Send(oResponse.headers.ToByteArray(prependStatusLine: true, appendEmptyLine: true));
			oRequest.pipeClient.Send(responseBodyBytes);
			SetBitFlag(SessionFlags.ResponseBodyDropped, b: true);
			responseBodyBytes = Utilities.emptyByteArray;
			(__oTunnel as GenericTunnel).BeginResponseStreaming();
		}
		catch (Exception eX)
		{
			FiddlerApplication.Log.LogFormat("Failed to create RPC Tunnel {0}", FiddlerCore.Utilities.Utilities.DescribeException(eX));
		}
	}

	private void _smDropRequestBody()
	{
		oFlags["x-RequestBodyLength"] = requestBodyBytes.Length.ToString("N0");
		requestBodyBytes = Utilities.emptyByteArray;
		SetBitFlag(SessionFlags.RequestBodyDropped, b: true);
	}

	private bool _smIsResponseAutoHandled()
	{
		if (Utilities.HasHeaders(oResponse))
		{
			if (_handledAsAutomaticRedirect())
			{
				return true;
			}
			if (_handledAsAutomaticAuth())
			{
				return true;
			}
		}
		return false;
	}

	private bool _smReplyWithFile()
	{
		if (!oFlags.ContainsKey("x-replywithfile"))
		{
			return false;
		}
		oResponse = new ServerChatter(this, "HTTP/1.1 200 OK\r\nServer: Fiddler\r\n\r\n");
		if (LoadResponseFromFile(oFlags["x-replywithfile"]) && isAnyFlagSet(SessionFlags.ResponseGeneratedByFiddler))
		{
			FiddlerApplication.DoResponseHeadersAvailable(this);
		}
		oFlags["x-repliedwithfile"] = oFlags["x-replywithfile"];
		oFlags.Remove("x-replywithfile");
		return true;
	}

	private void _smValidateRequestPort()
	{
		if (port < 0 || port > 65535)
		{
			FiddlerApplication.HandleHTTPError(this, SessionFlags.ProtocolViolationInRequest, bPoisonClientConnection: true, bPoisonServerConnection: false, "HTTP Request specified an invalid port number.");
		}
	}

	private void _BuildReceiveFailureReply(string sErrorBody)
	{
		oResponse.headers = new HTTPResponseHeaders(CONFIG.oHeaderEncoding);
		oResponse.headers.SetStatus(504, "Fiddler - Receive Failure while streaming");
		oResponse.headers.Add("Date", DateTime.UtcNow.ToString("r"));
		oResponse.headers.Add("Content-Type", "text/html; charset=UTF-8");
		oResponse.headers.Add("Connection", "close");
		oResponse.headers.Add("Cache-Control", "no-cache, must-revalidate");
		oResponse.headers.Add("Timestamp", DateTime.Now.ToString("HH:mm:ss.fff"));
		responseBodyBytes = Encoding.ASCII.GetBytes(sErrorBody);
	}

	private void _BuildConnectionEstablishedReply()
	{
		SetBitFlag(SessionFlags.ResponseGeneratedByFiddler, b: true);
		oResponse.headers = new HTTPResponseHeaders();
		oResponse.headers.HTTPVersion = oRequest.headers.HTTPVersion;
		oResponse.headers.SetStatus(200, "Connection Established");
		oResponse.headers.Add("FiddlerGateway", "Direct");
		oResponse.headers.Add("StartTime", DateTime.Now.ToString("HH:mm:ss.fff"));
		if (!oFlags.ContainsKey("x-ConnectResponseRemoveConnectionClose"))
		{
			oResponse.headers.Add("Connection", "close");
		}
		responseBodyBytes = Utilities.emptyByteArray;
	}

	/// <summary>
	/// Ensure that the Session's state is &gt;= ss, updating state if necessary
	/// </summary>
	/// <param name="ss">TargetState</param>
	private void _EnsureStateAtLeast(SessionStates ss)
	{
		if (m_state < ss)
		{
			SessionStates oldState = m_state;
			m_state = ss;
			RaiseOnStateChangedIfNotIgnored(oldState, m_state);
		}
	}

	/// <summary>
	/// May this Session be resent on a different connection because reading of the response did not succeed?
	/// </summary>
	/// <returns>TRUE if the entire session may be resent on a new connection</returns>
	private bool _MayRetryWhenReceiveFailed()
	{
		if (!oResponse.bServerSocketReused || state == SessionStates.Aborted || oResponse.bLeakedHeaders)
		{
			return false;
		}
		if (isAnyFlagSet(SessionFlags.RequestBodyDropped))
		{
			return false;
		}
		return CONFIG.RetryOnReceiveFailure switch
		{
			RetryMode.Never => false, 
			RetryMode.IdempotentOnly => Utilities.HTTPMethodIsIdempotent(RequestMethod), 
			_ => true, 
		};
	}

	/// <summary>
	/// If the response demands credentials and the Session is configured to have Fiddler provide those
	/// credentials, try to do so now.
	/// </summary>
	/// <returns>TRUE if Fiddler has generated a response to an Auth challenge; FALSE otherwise.</returns>
	private bool _handledAsAutomaticAuth()
	{
		if (!_isResponseAuthChallenge() || !oFlags.ContainsKey("x-AutoAuth") || oFlags.ContainsKey("x-AutoAuth-Failed"))
		{
			__WebRequestForAuth = null;
			return false;
		}
		try
		{
			return _PerformInnerAuth();
		}
		catch (TypeLoadException ex)
		{
			FiddlerApplication.Log.LogFormat("!Warning: Automatic authentication failed. You should installl the latest .NET Framework 2.0/3.5 Service Pack from WindowsUpdate.\n" + ex);
			return false;
		}
	}

	/// <summary>
	/// This method will perform obtain authentication credentials from System.NET using a reflection trick to grab the internal value.
	/// It's needed to cope with Channel-Binding-Tokens (CBT).
	///
	/// This MUST live within its own non-inlined method such that when it's run on an outdated version of the .NET Framework, the outdated
	/// version of the target object triggers a TypeLoadException in such a way that the caller can catch it and warn the user without 
	/// killing Fiddler.exe.
	/// </summary>
	/// <returns>TRUE if we didn't hit any exceptions</returns>
	[MethodImpl(MethodImplOptions.NoInlining)]
	private bool _PerformInnerAuth()
	{
		bool bIsProxyAuth = 407 == oResponse.headers.HTTPResponseCode;
		if (bIsProxyAuth && isHTTPS && FiddlerApplication.Prefs.GetBoolPref("fiddler.security.ForbidServer407", bDefault: true))
		{
			return false;
		}
		try
		{
			string sUrl = oFlags["X-AutoAuth-URL"];
			if (string.IsNullOrEmpty(sUrl))
			{
				sUrl = ((!bIsProxyAuth) ? fullUrl : fullUrl);
			}
			Uri oUrl = new Uri(sUrl);
			if (CONFIG.bDebugSpew)
			{
				FiddlerApplication.DebugSpew("Performing automatic authentication to {0} in response to {1}", oUrl, oResponse.headers.HTTPResponseCode);
			}
			if (__WebRequestForAuth == null)
			{
				__WebRequestForAuth = WebRequest.Create(oUrl);
			}
			Type tWebReq = __WebRequestForAuth.GetType();
			tWebReq.InvokeMember("Async", BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.SetProperty, null, __WebRequestForAuth, new object[1] { false });
			object objServerAuthState = tWebReq.InvokeMember("ServerAuthenticationState", BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.GetProperty, null, __WebRequestForAuth, new object[0]);
			if (objServerAuthState == null)
			{
				throw new ApplicationException("Auth state is null");
			}
			Type tAuthState = objServerAuthState.GetType();
			tAuthState.InvokeMember("ChallengedUri", BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.SetField, null, objServerAuthState, new object[1] { oUrl });
			string sSPN = oFlags["X-AutoAuth-SPN"];
			if (sSPN == null && !bIsProxyAuth)
			{
				sSPN = _GetSPNForUri(oUrl);
			}
			if (sSPN != null)
			{
				if (CONFIG.bDebugSpew)
				{
					FiddlerApplication.DebugSpew("Authenticating to '{0}' with ChallengedSpn='{1}'", oUrl, sSPN);
				}
				bool bSetSPNUsingObject = false;
				if (bTrySPNTokenObject)
				{
					try
					{
						Assembly asm = Assembly.GetAssembly(typeof(AuthenticationManager));
						Type tspntoken = asm.GetType("System.Net.SpnToken", throwOnError: true);
						object[] args = new string[1] { sSPN };
						object oSPNToken = Activator.CreateInstance(tspntoken, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.CreateInstance, null, args, CultureInfo.InvariantCulture);
						tAuthState.InvokeMember("ChallengedSpn", BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.SetField, null, objServerAuthState, new object[1] { oSPNToken });
						bSetSPNUsingObject = true;
					}
					catch (Exception eX3)
					{
						FiddlerApplication.DebugSpew(FiddlerCore.Utilities.Utilities.DescribeException(eX3));
						bTrySPNTokenObject = false;
					}
				}
				if (!bSetSPNUsingObject)
				{
					tAuthState.InvokeMember("ChallengedSpn", BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.SetField, null, objServerAuthState, new object[1] { sSPN });
				}
			}
			try
			{
				if (oResponse.pipeServer != null && oResponse.pipeServer.bIsSecured)
				{
					TransportContext oTC = oResponse.pipeServer._GetTransportContext();
					if (oTC != null)
					{
						tAuthState.InvokeMember("_TransportContext", BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.SetField, null, objServerAuthState, new object[1] { oTC });
					}
				}
			}
			catch (Exception eX2)
			{
				FiddlerApplication.Log.LogFormat("Cannot get TransportContext. You may need to upgrade to a later .NET Framework. {0}", eX2.Message);
			}
			string sAuthString = (bIsProxyAuth ? oResponse["Proxy-Authenticate"] : oResponse["WWW-Authenticate"]);
			ICredentials oCreds;
			if (oFlags["x-AutoAuth"].Contains(":"))
			{
				string sUserName = Utilities.TrimAfter(oFlags["x-AutoAuth"], ':');
				string sDomain = null;
				if (sUserName.Contains("\\"))
				{
					sDomain = Utilities.TrimAfter(sUserName, '\\');
					sUserName = Utilities.TrimBefore(sUserName, '\\');
					oCreds = new NetworkCredential(sUserName, Utilities.TrimBefore(oFlags["x-AutoAuth"], ':'), sDomain);
				}
				else
				{
					oCreds = new NetworkCredential(sUserName, Utilities.TrimBefore(oFlags["x-AutoAuth"], ':'));
				}
			}
			else
			{
				oCreds = CredentialCache.DefaultCredentials;
			}
			__WebRequestForAuth.Method = RequestMethod;
			Authorization auth = AuthenticationManager.Authenticate(sAuthString, __WebRequestForAuth, oCreds);
			if (auth == null)
			{
				throw new Exception("AuthenticationManager.Authenticate returned null.");
			}
			string sAuth = auth.Message;
			nextSession = new Session(oRequest.pipeClient, oResponse.pipeServer);
			nextSession.propagateProcessInfo(this);
			FireContinueTransaction(this, nextSession, ContinueTransactionReason.Authenticate);
			if (!auth.Complete)
			{
				nextSession.__WebRequestForAuth = __WebRequestForAuth;
			}
			__WebRequestForAuth = null;
			nextSession.requestBodyBytes = requestBodyBytes;
			nextSession.oRequest.headers = (HTTPRequestHeaders)oRequest.headers.Clone();
			nextSession.oRequest.headers[bIsProxyAuth ? "Proxy-Authorization" : "Authorization"] = sAuth;
			nextSession.SetBitFlag(SessionFlags.RequestGeneratedByFiddler, b: true);
			if (oFlags.ContainsKey("x-From-Builder"))
			{
				nextSession.oFlags["x-From-Builder"] = oFlags["x-From-Builder"] + " > +Auth";
			}
			if (int.TryParse(oFlags["x-AutoAuth-Retries"], out var iRetries))
			{
				iRetries--;
				if (iRetries > 0)
				{
					nextSession.oFlags["x-AutoAuth"] = oFlags["x-AutoAuth"];
					nextSession.oFlags["x-AutoAuth-Retries"] = iRetries.ToString();
				}
				else
				{
					nextSession.oFlags["x-AutoAuth-Failed"] = "true";
				}
			}
			else
			{
				nextSession.oFlags["x-AutoAuth-Retries"] = "5";
				nextSession.oFlags["x-AutoAuth"] = oFlags["x-AutoAuth"];
			}
			if (oFlags.ContainsKey("x-Builder-Inspect"))
			{
				nextSession.oFlags["x-Builder-Inspect"] = oFlags["x-Builder-Inspect"];
			}
			if (oFlags.ContainsKey("x-Builder-MaxRedir"))
			{
				nextSession.oFlags["x-Builder-MaxRedir"] = oFlags["x-Builder-MaxRedir"];
			}
			state = SessionStates.Done;
			nextSession.state = SessionStates.AutoTamperRequestBefore;
			FinishUISession();
			return true;
		}
		catch (Exception eX)
		{
			FiddlerApplication.Log.LogFormat("Automatic authentication of Session #{0} was unsuccessful. {1}\n{2}", id, FiddlerCore.Utilities.Utilities.DescribeException(eX), eX.StackTrace);
			__WebRequestForAuth = null;
			return false;
		}
	}

	/// <summary>
	/// Copies process-owner information from a source session to a destination session. Used during handling of AutoRedirects
	/// and auto-Authentications
	/// </summary>
	/// <param name="sessionFrom"></param>
	internal void propagateProcessInfo(Session sessionFrom)
	{
		if (_LocalProcessID != 0)
		{
			return;
		}
		if (sessionFrom == null)
		{
			_LocalProcessID = FiddlerApplication.iPID;
			oFlags["x-ProcessInfo"] = FiddlerApplication.sProcessInfo;
			return;
		}
		_LocalProcessID = sessionFrom._LocalProcessID;
		if (sessionFrom.oFlags.ContainsKey("x-ProcessInfo"))
		{
			oFlags["x-ProcessInfo"] = sessionFrom.oFlags["x-ProcessInfo"];
		}
	}

	/// <summary>
	/// Returns a Kerberos-usable SPN for the target
	/// http://dev.chromium.org/developers/design-documents/http-authentication
	/// "HttpAuthHandlerNegotiate::CreateSPN"
	/// http://blog.michelbarneveld.nl/michel/archive/2009/11/14/the-reason-why-kb911149-and-kb908209-are-not-the-soluton.aspx
	/// </summary>
	/// <param name="uriTarget"></param>
	/// <returns></returns>
	private static string _GetSPNForUri(Uri uriTarget)
	{
		int iSPNMode = FiddlerApplication.Prefs.GetInt32Pref("fiddler.auth.SPNMode", 3);
		string sSPN;
		switch (iSPNMode)
		{
		case 0:
			return null;
		case 1:
			sSPN = uriTarget.DnsSafeHost;
			break;
		default:
			sSPN = uriTarget.DnsSafeHost;
			if (iSPNMode == 3 || (uriTarget.HostNameType != UriHostNameType.IPv6 && uriTarget.HostNameType != UriHostNameType.IPv4 && sSPN.IndexOf('.') == -1))
			{
				string sCName = DNSResolver.GetCanonicalName(uriTarget.DnsSafeHost);
				if (!string.IsNullOrEmpty(sCName))
				{
					sSPN = sCName;
				}
			}
			break;
		}
		sSPN = "HTTP/" + sSPN;
		if (uriTarget.Port != 80 && uriTarget.Port != 443 && FiddlerApplication.Prefs.GetBoolPref("fiddler.auth.SPNIncludesPort", bDefault: false))
		{
			sSPN = sSPN + ":" + uriTarget.Port;
		}
		return sSPN;
	}

	/// <summary>
	/// Returns the fully-qualified URL to which this Session's response points, or null.
	/// This method is needed because many servers (illegally) return a relative url in HTTP/3xx Location response headers.
	/// </summary>
	/// <returns>null, or Target URL. Note, you may want to call Utilities.TrimAfter(sTarget, '#'); on the response</returns>
	public string GetRedirectTargetURL()
	{
		if (!Utilities.IsRedirectStatus(responseCode) || !Utilities.HasHeaders(oResponse))
		{
			return null;
		}
		return GetRedirectTargetURL(fullUrl, oResponse["Location"]);
	}

	/// <summary>
	/// Gets a redirect-target from a base URI and a Location header
	/// </summary>
	/// <param name="sBase"></param>
	/// <param name="sLocation"></param>
	/// <returns>null, or Target URL. Note, you may want to call Utilities.TrimAfter(sTarget, '#');</returns>
	public static string GetRedirectTargetURL(string sBase, string sLocation)
	{
		int ixProtocolEnd = sLocation.IndexOf(":");
		if (ixProtocolEnd < 0 || sLocation.IndexOfAny(new char[3] { '/', '?', '#' }) < ixProtocolEnd)
		{
			try
			{
				Uri uriBase = new Uri(sBase);
				Uri uriNew = new Uri(uriBase, sLocation);
				return uriNew.ToString();
			}
			catch (UriFormatException)
			{
				return null;
			}
		}
		return sLocation;
	}

	/// <summary>
	/// Fiddler can only auto-follow redirects to HTTP/HTTPS/FTP.
	/// </summary>
	/// <param name="sBase">The BASE URL to which a relative redirection should be applied</param>
	/// <param name="sLocation">Response "Location" header</param>
	/// <returns>TRUE if the auto-redirect target is allowed</returns>
	private static bool isRedirectableURI(string sBase, string sLocation, out string sTarget)
	{
		sTarget = GetRedirectTargetURL(sBase, sLocation);
		if (sTarget == null)
		{
			return false;
		}
		return sTarget.OICStartsWithAny("http://", "https://", "ftp://");
	}

	/// <summary>
	/// Handles a Response's Redirect if the Session is configured to do so.
	/// </summary>
	/// <returns>TRUE if a redirect was handled, FALSE otherwise</returns>
	private bool _handledAsAutomaticRedirect()
	{
		if (oResponse.headers.HTTPResponseCode < 300 || oResponse.headers.HTTPResponseCode > 308 || HTTPMethodIs("CONNECT") || !oFlags.ContainsKey("x-Builder-MaxRedir") || !oResponse.headers.Exists("Location"))
		{
			return false;
		}
		if (!isRedirectableURI(fullUrl, oResponse["Location"], out var sTarget))
		{
			return false;
		}
		nextSession = new Session(oRequest.pipeClient, null);
		nextSession.propagateProcessInfo(this);
		nextSession.oRequest.headers = (HTTPRequestHeaders)oRequest.headers.Clone();
		sTarget = Utilities.TrimAfter(sTarget, '#');
		try
		{
			nextSession.fullUrl = new Uri(sTarget).AbsoluteUri;
		}
		catch (UriFormatException exU)
		{
			FiddlerApplication.HandleHTTPError(this, SessionFlags.ProtocolViolationInResponse, bPoisonClientConnection: false, bPoisonServerConnection: false, $"Redirect's Location header was malformed.\nLocation: {sTarget}\n\n{exU}");
			nextSession.fullUrl = sTarget;
		}
		if (oResponse.headers.HTTPResponseCode == 307 || oResponse.headers.HTTPResponseCode == 308)
		{
			nextSession.requestBodyBytes = Utilities.Dupe(requestBodyBytes);
		}
		else
		{
			if (!nextSession.HTTPMethodIs("HEAD"))
			{
				nextSession.RequestMethod = "GET";
			}
			nextSession.oRequest.headers.RemoveRange(new string[5] { "Content-Type", "Content-Length", "Transfer-Encoding", "Content-Encoding", "Expect" });
			nextSession.requestBodyBytes = Utilities.emptyByteArray;
		}
		if (FiddlerApplication.Prefs.GetBoolPref("fiddler.reissue.UpdateHeadersOnAutoRedirectedRequest", bDefault: true))
		{
			nextSession.oRequest.headers.RemoveRange(new string[11]
			{
				"Accept", "Pragma", "Connection", "X-Download-Initiator", "Range", "If-Modified-Since", "If-Unmodified-Since", "Unless-Modified-Since", "If-Range", "If-Match",
				"If-None-Match"
			});
			nextSession.oRequest.headers.RemoveRange(new string[4] { "Authorization", "Proxy-Authorization", "Cookie", "Cookie2" });
		}
		nextSession.SetBitFlag(SessionFlags.RequestGeneratedByFiddler, b: true);
		if (oFlags.ContainsKey("x-From-Builder"))
		{
			nextSession.oFlags["x-From-Builder"] = oFlags["x-From-Builder"] + " > +Redir";
		}
		if (oFlags.ContainsKey("x-AutoAuth"))
		{
			nextSession.oFlags["x-AutoAuth"] = oFlags["x-AutoAuth"];
		}
		if (oFlags.ContainsKey("x-Builder-Inspect"))
		{
			nextSession.oFlags["x-Builder-Inspect"] = oFlags["x-Builder-Inspect"];
		}
		if (int.TryParse(oFlags["x-Builder-MaxRedir"], out var iRedir))
		{
			iRedir--;
			if (iRedir > 0)
			{
				nextSession.oFlags["x-Builder-MaxRedir"] = iRedir.ToString();
			}
		}
		FireContinueTransaction(this, nextSession, ContinueTransactionReason.Redirect);
		oResponse.releaseServerPipe();
		nextSession.state = SessionStates.AutoTamperRequestBefore;
		state = SessionStates.Done;
		FinishUISession();
		return true;
	}

	private void ExecuteHTTPLintOnRequest()
	{
		if (oRequest.headers == null)
		{
			return;
		}
		if (fullUrl.Length > 2083)
		{
			FiddlerApplication.HandleHTTPError(this, SessionFlags.ProtocolViolationInRequest, bPoisonClientConnection: false, bPoisonServerConnection: false, $"[HTTPLint #M001] Request URL was {fullUrl.Length} characters. WinINET-based clients encounter problems when dealing with URLs longer than 2083 characters.");
		}
		if (fullUrl.Contains("#"))
		{
			FiddlerApplication.HandleHTTPError(this, SessionFlags.ProtocolViolationInRequest, bPoisonClientConnection: false, bPoisonServerConnection: false, "[HTTPLint #H002] Request URL contained '#'. URL Fragments should not be sent to the server.");
		}
		if (oRequest.headers.ByteCount() > 16000)
		{
			FiddlerApplication.HandleHTTPError(this, SessionFlags.ProtocolViolationInRequest, bPoisonClientConnection: false, bPoisonServerConnection: false, $"[HTTPLint #M003] Request headers were {oRequest.headers.ByteCount():N0} bytes long. Many servers will reject requests this large.");
		}
		string sReferer = oRequest["Referer"];
		if (string.IsNullOrEmpty(sReferer))
		{
			return;
		}
		if (sReferer.Contains("#"))
		{
			FiddlerApplication.HandleHTTPError(this, SessionFlags.ProtocolViolationInRequest, bPoisonClientConnection: false, bPoisonServerConnection: false, "[HTTPLint #M004] Referer Header contained '#'. URL Fragments should not be sent to the server.");
		}
		if (isHTTPS || sReferer.StartsWith("http:"))
		{
			return;
		}
		try
		{
			Uri uriReferer = new Uri(sReferer);
			if (uriReferer.AbsolutePath != "/" || uriReferer.Query != string.Empty)
			{
				FiddlerApplication.HandleHTTPError(this, SessionFlags.ProtocolViolationInRequest, bPoisonClientConnection: false, bPoisonServerConnection: false, "[HTTPLint #H005] Referer Header leaked a private URL on an unsecure request: '" + sReferer + "' Referrer Policy may be in use.");
			}
		}
		catch
		{
		}
	}

	/// <summary>
	/// Check for common mistakes in HTTP Responses and notify the user if they are found. Called only if Linting is enabled.
	/// </summary>
	private void ExecuteHTTPLintOnResponse()
	{
		if (responseBodyBytes == null || oResponse.headers == null)
		{
			return;
		}
		if (oResponse.headers.Exists("Content-Encoding"))
		{
			if (oResponse.headers.ExistsAndContains("Content-Encoding", ",") && !oResponse.headers.ExistsAndContains("Content-Encoding", "sdch"))
			{
				FiddlerApplication.HandleHTTPError(this, SessionFlags.ProtocolViolationInResponse, bPoisonClientConnection: false, bPoisonServerConnection: false, string.Format("[HTTPLint #M006] Response appears to specify multiple encodings: '{0}'. This will prevent decoding in Internet Explorer.", oResponse.headers["Content-Encoding"]));
			}
			if (oResponse.headers.ExistsAndContains("Content-Encoding", "gzip") && oRequest != null && oRequest.headers != null && !oRequest.headers.ExistsAndContains("Accept-Encoding", "gzip"))
			{
				FiddlerApplication.HandleHTTPError(this, SessionFlags.ProtocolViolationInResponse, bPoisonClientConnection: false, bPoisonServerConnection: false, "[HTTPLint #H008] Illegal response. Response specified Content-Encoding: gzip, but request did not specify GZIP in Accept-Encoding.");
			}
			if (oResponse.headers.ExistsAndContains("Content-Encoding", "deflate"))
			{
				if (oRequest != null && oRequest.headers != null && !oRequest.headers.ExistsAndContains("Accept-Encoding", "deflate"))
				{
					FiddlerApplication.HandleHTTPError(this, SessionFlags.ProtocolViolationInResponse, bPoisonClientConnection: false, bPoisonServerConnection: false, "[HTTPLint #H008] Illegal response. Response specified Content-Encoding: Deflate, but request did not specify Deflate in Accept-Encoding.");
				}
				if (responseBodyBytes != null && responseBodyBytes.Length > 2 && (responseBodyBytes[0] & 0xF) == 8 && (responseBodyBytes[0] & 0x80) == 0 && ((responseBodyBytes[0] << 8) + responseBodyBytes[1]) % 31 == 0)
				{
					FiddlerApplication.HandleHTTPError(this, SessionFlags.ProtocolViolationInResponse, bPoisonClientConnection: false, bPoisonServerConnection: false, "[HTTPLint #M028] Response specified Content-Encoding: Deflate, but content included RFC1950 header and footer bytes incompatible with many clients.");
				}
			}
			if (oResponse.headers.ExistsAndContains("Content-Encoding", "br") && oRequest != null && oRequest.headers != null && !oRequest.headers.ExistsAndContains("Accept-Encoding", "br"))
			{
				FiddlerApplication.HandleHTTPError(this, SessionFlags.ProtocolViolationInResponse, bPoisonClientConnection: false, bPoisonServerConnection: false, "[HTTPLint #H008] Illegal response. Response specified Content-Encoding: br, but request did not specify br (Brotli) in Accept-Encoding.");
			}
			if (oResponse.headers.ExistsAndContains("Content-Encoding", "chunked"))
			{
				FiddlerApplication.HandleHTTPError(this, SessionFlags.ProtocolViolationInResponse, bPoisonClientConnection: false, bPoisonServerConnection: false, "[HTTPLint #H009] Response specified Content-Encoding: chunked, but Chunked is a Transfer-Encoding.");
			}
		}
		if (oResponse.headers.ExistsAndContains("Transfer-Encoding", "chunked"))
		{
			if ((Utilities.HasHeaders(oRequest) && "HTTP/1.0".OICEquals(oRequest.headers.HTTPVersion)) || "HTTP/1.0".OICEquals(oResponse.headers.HTTPVersion))
			{
				FiddlerApplication.HandleHTTPError(this, SessionFlags.ProtocolViolationInResponse, bPoisonClientConnection: false, bPoisonServerConnection: false, "[HTTPLint #H010] Invalid response. Responses to HTTP/1.0 clients MUST NOT specify a Transfer-Encoding.");
			}
			if (oResponse.headers.Exists("Content-Length"))
			{
				FiddlerApplication.HandleHTTPError(this, SessionFlags.ProtocolViolationInResponse, bPoisonClientConnection: false, bPoisonServerConnection: false, "[HTTPLint #M011] Invalid response headers. Messages MUST NOT include both a Content-Length header field and a non-identity transfer-coding.");
			}
			if (!isAnyFlagSet(SessionFlags.ResponseBodyDropped))
			{
				long lZero = 0L;
				long lEnd = responseBodyBytes.Length;
				if (!Utilities.IsChunkedBodyComplete(this, responseBodyBytes, 0L, responseBodyBytes.Length, out lZero, out lEnd))
				{
					FiddlerApplication.HandleHTTPError(this, SessionFlags.ProtocolViolationInResponse, bPoisonClientConnection: true, bPoisonServerConnection: true, "[HTTPLint #M012] The HTTP Chunked response body was incomplete; most likely lacking the final 0-size chunk.");
				}
			}
		}
		List<HTTPHeaderItem> listETags = oResponse.headers.FindAll("ETAG");
		if (listETags.Count > 1)
		{
			FiddlerApplication.HandleHTTPError(this, SessionFlags.ProtocolViolationInResponse, bPoisonClientConnection: false, bPoisonServerConnection: false, $"[HTTPLint #H013] Response contained {listETags.Count} ETag headers");
		}
		if (listETags.Count > 0)
		{
			string sETag = listETags[0].Value;
			if (!sETag.EndsWith("\"") || (!sETag.StartsWith("\"") && !sETag.StartsWith("W/\"")))
			{
				FiddlerApplication.HandleHTTPError(this, SessionFlags.ProtocolViolationInResponse, bPoisonClientConnection: false, bPoisonServerConnection: false, $"[HTTPLint #L014] ETag values must be a quoted string. Response ETag: {sETag}");
			}
		}
		if (!oResponse.headers.Exists("Date") && responseCode > 199 && responseCode < 500 && !HTTPMethodIs("CONNECT"))
		{
			FiddlerApplication.HandleHTTPError(this, SessionFlags.ProtocolViolationInResponse, bPoisonClientConnection: false, bPoisonServerConnection: false, "[HTTPLint #L015] With rare exceptions, servers MUST include a DATE response header. RFC7231 Section 7.1.1.2");
		}
		if (responseCode > 299 && responseCode != 304 && responseCode < 399)
		{
			if (308 == responseCode)
			{
				FiddlerApplication.HandleHTTPError(this, SessionFlags.ProtocolViolationInResponse, bPoisonClientConnection: false, bPoisonServerConnection: false, "[HTTPLint #M016] Server returned a HTTP/308 redirect. Most clients do not handle HTTP/308; instead use a HTTP/307 with a Cache-Control header.");
			}
			if (oResponse.headers.Exists("Location"))
			{
				if (oResponse["Location"].StartsWith("/"))
				{
					FiddlerApplication.HandleHTTPError(this, SessionFlags.ProtocolViolationInResponse, bPoisonClientConnection: false, bPoisonServerConnection: false, string.Format("[HTTPLint #L017] HTTP Location header should specify a fully-qualified URL. Location: {0}", oResponse["Location"]));
				}
			}
			else
			{
				FiddlerApplication.HandleHTTPError(this, SessionFlags.ProtocolViolationInResponse, bPoisonClientConnection: false, bPoisonServerConnection: false, "[HTTPLint #H018] HTTP/3xx redirect response headers lacked a Location header.");
			}
		}
		string sCT = oResponse.headers["Content-Type"];
		if (sCT.OICContains("utf8"))
		{
			FiddlerApplication.HandleHTTPError(this, SessionFlags.ProtocolViolationInResponse, bPoisonClientConnection: false, bPoisonServerConnection: false, "[HTTPLint #M019] Content-Type header specified CharSet=UTF8; for better compatibility, use CharSet=UTF-8 instead.");
		}
		if (sCT.OICContains("image/jpg"))
		{
			FiddlerApplication.HandleHTTPError(this, SessionFlags.ProtocolViolationInResponse, bPoisonClientConnection: false, bPoisonServerConnection: false, "[HTTPLint #L026] Content-Type header specified 'image/jpg'; correct type is 'image/jpeg'.");
		}
		string sCacheControl = oResponse.headers.AllValues("Cache-Control");
		if (sCacheControl.OICContains("pre-check") || sCacheControl.OICContains("post-check"))
		{
			if (sCacheControl.OICContains("no-cache"))
			{
				FiddlerApplication.HandleHTTPError(this, SessionFlags.ProtocolViolationInResponse, bPoisonClientConnection: false, bPoisonServerConnection: false, "[HTTPLint #L024] The pre-check and post-check tokens are meaningless when Cache-Control: no-cache is specified.");
			}
			else
			{
				FiddlerApplication.HandleHTTPError(this, SessionFlags.ProtocolViolationInResponse, bPoisonClientConnection: false, bPoisonServerConnection: false, "[HTTPLint #L025] Cache-Control header contained non-standard tokens. pre-check and post-check are poorly supported and almost never used properly.");
			}
		}
		if (206 != responseCode && !Utilities.IsNullOrEmpty(responseBodyBytes) && !oResponse.headers.Exists("Transfer-Encoding") && !oResponse.headers.Exists("Content-Encoding"))
		{
			if (oResponse.headers.ExistsAndContains("Content-Type", "image/png"))
			{
				if (!Utilities.HasMagicBytes(responseBodyBytes, new byte[4] { 137, 80, 78, 71 }))
				{
					FiddlerApplication.HandleHTTPError(this, SessionFlags.ProtocolViolationInResponse, bPoisonClientConnection: false, bPoisonServerConnection: false, "[HTTPLint #M027] Declared 'Content-Type: image/png' does not match response body content.");
				}
			}
			else if (oResponse.headers.ExistsAndContains("Content-Type", "image/gif"))
			{
				if (!Utilities.HasMagicBytes(responseBodyBytes, new byte[4] { 71, 73, 70, 56 }))
				{
					FiddlerApplication.HandleHTTPError(this, SessionFlags.ProtocolViolationInResponse, bPoisonClientConnection: false, bPoisonServerConnection: false, "[HTTPLint #M027] Declared 'Content-Type: image/gif' does not match response body content.");
				}
			}
			else if (oResponse.headers.ExistsAndContains("Content-Type", "image/jpeg") && !Utilities.HasMagicBytes(responseBodyBytes, new byte[2] { 255, 216 }))
			{
				FiddlerApplication.HandleHTTPError(this, SessionFlags.ProtocolViolationInResponse, bPoisonClientConnection: false, bPoisonServerConnection: false, "[HTTPLint #M027] Declared 'Content-Type: image/jpeg' does not match response body content.");
			}
		}
		List<HTTPHeaderItem> listSetCookies = oResponse.headers.FindAll("Set-Cookie");
		if (listSetCookies.Count <= 0)
		{
			return;
		}
		if (hostname.Contains("_"))
		{
			FiddlerApplication.HandleHTTPError(this, SessionFlags.ProtocolViolationInResponse, bPoisonClientConnection: false, bPoisonServerConnection: false, "[HTTPLint #M020] Response sets a cookie, and server's hostname contains '_'. Internet Explorer does not permit cookies to be set on hostnames containing underscores. See http://support.microsoft.com/kb/316112");
		}
		foreach (HTTPHeaderItem oHI in listSetCookies)
		{
			string sAttrs = Utilities.TrimBefore(oHI.Value, ";");
			string sDomainAttr = Utilities.GetCommaTokenValue(sAttrs, "domain");
			if (!Utilities.IsNullOrWhiteSpace(sDomainAttr))
			{
				sDomainAttr = sDomainAttr.Trim();
				if (sDomainAttr.StartsWith("."))
				{
					sDomainAttr = sDomainAttr.Substring(1);
				}
				if (!hostname.EndsWith(sDomainAttr))
				{
					FiddlerApplication.HandleHTTPError(this, SessionFlags.ProtocolViolationInResponse, bPoisonClientConnection: false, bPoisonServerConnection: false, $"[HTTPLint #H021] Illegal DOMAIN in Set-Cookie. Cookie from '{hostname}' specified 'domain={sDomainAttr}'");
				}
			}
			string sCookie = Utilities.TrimAfter(oHI.Value, ';');
			string text = sCookie;
			foreach (char c in text)
			{
				if (c == ',')
				{
					FiddlerApplication.HandleHTTPError(this, SessionFlags.ProtocolViolationInResponse, bPoisonClientConnection: false, bPoisonServerConnection: false, $"[HTTPLint #L022] Illegal comma in cookie. Set-Cookie: {sCookie}.");
				}
				else if (c >= '\u0080')
				{
					FiddlerApplication.HandleHTTPError(this, SessionFlags.ProtocolViolationInResponse, bPoisonClientConnection: false, bPoisonServerConnection: false, $"[HTTPLint #M023] Non-ASCII character found in Set-Cookie: {sCookie}. Some browsers (Safari) may corrupt this cookie.");
				}
			}
		}
	}

	/// <summary>
	/// Assign a Session ID. Called by ClientChatter when headers are available
	/// </summary>
	[DoNotObfuscate]
	internal void _AssignID()
	{
		m_requestID = Interlocked.Increment(ref cRequests);
	}

	internal void EnsureID()
	{
		if (m_requestID == 0)
		{
			m_requestID = Interlocked.Increment(ref cRequests);
		}
	}

	/// <summary>
	/// Called only by InnerExecute, this method reads a request from the client and performs tampering/manipulation on it.
	/// </summary>
	/// <returns>TRUE if there's a Request object and we should continue processing. FALSE if reading the request failed
	/// *OR* if script or an extension changed the session's State to DONE or ABORTED.
	/// </returns>
	private bool _executeObtainRequest()
	{
		if (state > SessionStates.ReadingRequest)
		{
			Timers.ClientBeginRequest = (Timers.FiddlerGotRequestHeaders = (Timers.ClientDoneRequest = DateTime.Now));
			_AssignID();
		}
		else
		{
			state = SessionStates.ReadingRequest;
			if (!oRequest.ReadRequest())
			{
				_HandleFailedReadRequest();
				return false;
			}
			Timers.ClientDoneRequest = DateTime.Now;
			if (CONFIG.bDebugSpew)
			{
				FiddlerApplication.DebugSpew("Request for Session #{0} for read from {1}.", m_requestID, oRequest.pipeClient);
			}
			try
			{
				requestBodyBytes = oRequest.TakeEntity();
			}
			catch (Exception eX)
			{
				FiddlerApplication.HandleHTTPError(this, SessionFlags.ProtocolViolationInRequest, bPoisonClientConnection: true, bPoisonServerConnection: false, "Failed to obtain request body. " + FiddlerCore.Utilities.Utilities.DescribeException(eX));
				CloseSessionPipes(bNullThemToo: true);
				state = SessionStates.Aborted;
				return false;
			}
		}
		_replaceVirtualHostnames();
		if (isHTTPS)
		{
			SetBitFlag(SessionFlags.IsHTTPS, b: true);
			SetBitFlag(SessionFlags.IsFTP, b: false);
		}
		else if (isFTP)
		{
			SetBitFlag(SessionFlags.IsFTP, b: true);
			SetBitFlag(SessionFlags.IsHTTPS, b: false);
		}
		_smValidateRequest();
		state = SessionStates.AutoTamperRequestBefore;
		FiddlerApplication.DoBeforeRequest(this);
		if (m_state >= SessionStates.Done)
		{
			FinishUISession();
			return false;
		}
		return true;
	}

	private void _smCheckForAutoReply()
	{
	}

	private void _smValidateRequest()
	{
		if (Utilities.IsNullOrEmpty(requestBodyBytes) && Utilities.HTTPMethodRequiresBody(RequestMethod) && !isAnyFlagSet(SessionFlags.RequestStreamed | SessionFlags.IsRPCTunnel))
		{
			FiddlerApplication.HandleHTTPError(this, SessionFlags.ProtocolViolationInRequest, bPoisonClientConnection: true, bPoisonServerConnection: false, "This HTTP method requires a request body.");
		}
		string sOriginalHostHeader = oFlags["X-Original-Host"];
		if (sOriginalHostHeader == null)
		{
			return;
		}
		if (sOriginalHostHeader.Length < 1)
		{
			FiddlerApplication.HandleHTTPError(this, SessionFlags.ProtocolViolationInRequest, bPoisonClientConnection: false, bPoisonServerConnection: false, "HTTP/1.1 Request was missing the required HOST header.");
			return;
		}
		if (!FiddlerApplication.Prefs.GetBoolPref("fiddler.network.SetHostHeaderFromURL", bDefault: true))
		{
			oFlags["X-OverrideHost"] = oFlags["X-URI-Host"];
		}
		FiddlerApplication.HandleHTTPError(this, SessionFlags.ProtocolViolationInRequest, bPoisonClientConnection: false, bPoisonServerConnection: false, string.Format("The Request's Host header did not match the URL's host component.\n\nURL Host:\t{0}\nHeader Host:\t{1}", oFlags["X-URI-Host"], oFlags["X-Original-Host"]));
	}

	/// <summary>
	/// If the executeObtainRequest called failed, we perform cleanup
	/// </summary>
	private void _HandleFailedReadRequest()
	{
		if (oRequest.headers == null)
		{
			oFlags["ui-hide"] = "stealth-NewOrReusedClosedWithoutRequest";
		}
		try
		{
			requestBodyBytes = oRequest.TakeEntity();
		}
		catch (Exception eX)
		{
			oFlags["X-FailedToReadRequestBody"] = FiddlerCore.Utilities.Utilities.DescribeException(eX);
		}
		if (oResponse != null)
		{
			oResponse._detachServerPipe();
		}
		CloseSessionPipes(bNullThemToo: true);
		state = SessionStates.Aborted;
	}

	/// <summary>
	/// Returns TRUE if response is a NTLM or NEGO challenge
	/// </summary>
	/// <returns>True for HTTP/401,407 with NEGO or NTLM demand</returns>
	private bool _isResponseMultiStageAuthChallenge()
	{
		if (!Utilities.HasHeaders(oResponse))
		{
			return false;
		}
		return (401 == oResponse.headers.HTTPResponseCode && oResponse.headers["WWW-Authenticate"].OICStartsWith("N")) || (407 == oResponse.headers.HTTPResponseCode && oResponse.headers["Proxy-Authenticate"].OICStartsWith("N"));
	}

	/// <summary>
	/// Returns TRUE if response is a Digest, NTLM, or Nego challenge
	/// </summary>
	/// <returns>True for HTTP/401,407 with Digest, NEGO, NTLM demand</returns>
	private bool _isResponseAuthChallenge()
	{
		if (401 == oResponse.headers.HTTPResponseCode)
		{
			return oResponse.headers.ExistsAndContains("WWW-Authenticate", "NTLM") || oResponse.headers.ExistsAndContains("WWW-Authenticate", "Negotiate") || oResponse.headers.ExistsAndContains("WWW-Authenticate", "Digest");
		}
		if (407 == oResponse.headers.HTTPResponseCode)
		{
			return oResponse.headers.ExistsAndContains("Proxy-Authenticate", "NTLM") || oResponse.headers.ExistsAndContains("Proxy-Authenticate", "Negotiate") || oResponse.headers.ExistsAndContains("Proxy-Authenticate", "Digest");
		}
		return false;
	}

	/// <summary>
	/// Replace the "ipv*.fiddler "fake" hostnames with the IP-literal equvalents.
	/// </summary>
	private void _replaceVirtualHostnames()
	{
		if (hostname.OICEndsWith(".fiddler"))
		{
			string sInboundHost = hostname.ToLowerInvariant();
			switch (sInboundHost)
			{
			default:
				return;
			case "ipv4.fiddler":
				hostname = "127.0.0.1";
				break;
			case "localhost.fiddler":
				hostname = "localhost";
				break;
			case "ipv6.fiddler":
				hostname = "[::1]";
				break;
			}
			oFlags["x-UsedVirtualHost"] = sInboundHost;
			bypassGateway = true;
			if (HTTPMethodIs("CONNECT"))
			{
				oFlags["x-OverrideCertCN"] = Utilities.StripIPv6LiteralBrackets(sInboundHost);
			}
		}
	}

	/// <summary>
	/// Determines if request host is pointing directly at Fiddler.
	/// </summary>
	/// <returns></returns>
	private bool _isDirectRequestToFiddler()
	{
		if (port != CONFIG.ListenPort)
		{
			return false;
		}
		if (host.OICEquals(CONFIG.sFiddlerListenHostPort))
		{
			return true;
		}
		string _hostname = hostname.ToLowerInvariant();
		if (_hostname == "localhost" || _hostname == "localhost." || _hostname == CONFIG.sAlternateHostname)
		{
			return true;
		}
		if (_hostname.StartsWith("[") && _hostname.EndsWith("]"))
		{
			_hostname = _hostname.Substring(1, _hostname.Length - 2);
		}
		IPAddress ipTarget = Utilities.IPFromString(_hostname);
		if (ipTarget != null)
		{
			try
			{
				if (IPAddress.IsLoopback(ipTarget))
				{
					return true;
				}
				NetworkInterface[] networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();
				NetworkInterface[] array = networkInterfaces;
				foreach (NetworkInterface networkInterface in array)
				{
					if (networkInterface.NetworkInterfaceType == NetworkInterfaceType.Loopback)
					{
						continue;
					}
					IPInterfaceProperties properties = networkInterface.GetIPProperties();
					foreach (UnicastIPAddressInformation ip in properties.UnicastAddresses)
					{
						if (ipTarget.Equals(ip.Address))
						{
							return true;
						}
					}
				}
			}
			catch (Exception)
			{
			}
			return false;
		}
		return _hostname.StartsWith(CONFIG.sMachineName) && (_hostname.Length == CONFIG.sMachineName.Length || _hostname == CONFIG.sMachineName + "." + CONFIG.sMachineDomain);
	}

	/// <summary>
	/// Echo the client's request back as a HTTP Response, encoding to prevent XSS.
	/// </summary>
	private void _returnEchoServiceResponse()
	{
		if (!FiddlerApplication.Prefs.GetBoolPref("fiddler.echoservice.enabled", bDefault: true))
		{
			if (oRequest != null && oRequest.pipeClient != null)
			{
				oRequest.pipeClient.EndWithRST();
			}
			state = SessionStates.Aborted;
			return;
		}
		if (HTTPMethodIs("CONNECT"))
		{
			oRequest.FailSession(405, "Method Not Allowed", "This endpoint does not support HTTP CONNECTs. Try GET or POST instead.");
			return;
		}
		int iResultCode = 200;
		Action<Session> oDel = null;
		if (PathAndQuery.Length == 4 && Regex.IsMatch(PathAndQuery, "/\\d{3}"))
		{
			iResultCode = int.Parse(PathAndQuery.Substring(1));
			if (Utilities.IsRedirectStatus(iResultCode))
			{
				oDel = delegate(Session s)
				{
					s.oResponse["Location"] = "/200";
				};
			}
		}
		StringBuilder sEcho = new StringBuilder();
		sEcho.AppendFormat("<!doctype html>\n<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\"><title>");
		if (iResultCode != 200)
		{
			sEcho.AppendFormat("[{0}] - ", iResultCode);
		}
		sEcho.Append("Fiddler Echo Service</title></head><body style=\"font-family: arial,sans-serif;\"><h1>Fiddler Echo Service</h1><br /><pre>");
		sEcho.Append(Utilities.HtmlEncode(oRequest.headers.ToString(prependVerbLine: true, appendEmptyLine: true)));
		if (requestBodyBytes != null && requestBodyBytes.LongLength > 0)
		{
			sEcho.Append(Utilities.HtmlEncode(Encoding.UTF8.GetString(requestBodyBytes)));
		}
		sEcho.Append("</pre>");
		sEcho.AppendFormat("This page returned a <b>HTTP/{0}</b> response <br />", iResultCode);
		if (oFlags.ContainsKey("X-ProcessInfo"))
		{
			sEcho.AppendFormat("Originating Process Information: <code>{0}</code><br />", oFlags["X-ProcessInfo"]);
		}
		sEcho.Append("<hr />");
		if (fullUrl.Contains("troubleshooter.cgi"))
		{
			sEcho.Append("<h3>Alternate hostname test</h3>\n");
			sEcho.Append("<iframe src='http://ipv4.fiddler:" + CONFIG.ListenPort + "/' width=300></iframe>");
			sEcho.Append("<iframe src='http://ipv6.fiddler:" + CONFIG.ListenPort + "/' width=300></iframe>");
			sEcho.Append("<iframe src='http://localhost.fiddler:" + CONFIG.ListenPort + "/' width=300></iframe>");
			sEcho.Append("<img src='http://www.example.com/' width=0 height=0 />");
		}
		else
		{
			sEcho.Append("<ul><li>To configure Fiddler as a reverse proxy instead of seeing this page, see <a href='" + CONFIG.GetRedirUrl("REVERSEPROXY") + "'>Reverse Proxy Setup</a><li>You can download the <a href=\"FiddlerRoot.cer\">FiddlerRoot certificate</a></ul>");
		}
		sEcho.Append("</body></html>");
		oRequest.BuildAndReturnResponse(iResultCode, "Fiddler Generated", sEcho.ToString(), oDel);
		state = SessionStates.Aborted;
	}

	/// <summary>
	/// Send a Proxy Configuration script back to the client.
	/// </summary>
	private void _returnPACFileResponse()
	{
		utilCreateResponseAndBypassServer();
		oResponse.headers["Content-Type"] = "application/x-ns-proxy-autoconfig";
		oResponse.headers["Cache-Control"] = "max-age=60";
		oResponse.headers["Connection"] = "close";
		utilSetResponseBody(FiddlerApplication.oProxy._GetPACScriptText());
		state = SessionStates.Aborted;
		FiddlerApplication.DoResponseHeadersAvailable(this);
		ReturnResponse(bForceClientServerPipeAffinity: false);
	}

	/// <summary>
	/// Send a Proxy Configuration script back to WinHTTP, so that Fiddler can use an upstream proxy specified
	/// by a script on a fileshare. (WinHTTP only allows HTTP/HTTPS-hosted script files)
	/// </summary>
	private void _returnUpstreamPACFileResponse()
	{
		utilCreateResponseAndBypassServer();
		oResponse.headers["Content-Type"] = "application/x-ns-proxy-autoconfig";
		oResponse.headers["Connection"] = "close";
		oResponse.headers["Cache-Control"] = "max-age=300";
		string sBody = FiddlerApplication.oProxy._GetUpstreamPACScriptText();
		if (string.IsNullOrEmpty(sBody))
		{
			responseCode = 404;
		}
		utilSetResponseBody(sBody);
		state = SessionStates.Aborted;
		ReturnResponse(bForceClientServerPipeAffinity: false);
	}

	/// <summary>
	/// Send the Fiddler Root certificate back to the client
	/// </summary>
	private static void _returnRootCert(Session oS)
	{
		oS.utilCreateResponseAndBypassServer();
		oS.oResponse.headers["Connection"] = "close";
		oS.oResponse.headers["Cache-Control"] = "max-age=0";
		byte[] arrRootCert = CertMaker.getRootCertBytes();
		if (arrRootCert != null)
		{
			oS.oResponse.headers["Content-Type"] = "application/x-x509-ca-cert";
			oS.responseBodyBytes = arrRootCert;
			oS.oResponse.headers["Content-Length"] = oS.responseBodyBytes.Length.ToString();
		}
		else
		{
			oS.responseCode = 404;
			oS.oResponse.headers["Content-Type"] = "text/html; charset=UTF-8";
			oS.utilSetResponseBody("No root certificate was found. Have you enabled HTTPS traffic decryption in Fiddler yet?".PadRight(512, ' '));
		}
		FiddlerApplication.DoResponseHeadersAvailable(oS);
		oS.ReturnResponse(bForceClientServerPipeAffinity: false);
	}

	/// <summary>
	/// This method indicates to the client that a secure tunnel was created,
	/// without actually talking to an upstream server.
	///
	/// If Fiddler's AutoResponder is enabled, and that autoresponder denies passthrough,
	/// then Fiddler itself will always indicate "200 Connection Established" and wait for
	/// another request from the client. That subsequent request can then potentially be 
	/// handled by the AutoResponder engine.
	///
	/// BUG BUG: This occurs even if Fiddler isn't configured for HTTPS Decryption
	///
	/// </summary>
	/// <param name="sHostname">The hostname to use in the Certificate returned to the client</param>
	private void _ReturnSelfGeneratedCONNECTTunnel(string sHostname)
	{
		SetBitFlag(SessionFlags.ResponseGeneratedByFiddler | SessionFlags.IsDecryptingTunnel, b: true);
		oResponse.headers = new HTTPResponseHeaders();
		oResponse.headers.SetStatus(200, "DecryptEndpoint Created");
		oResponse.headers.Add("Timestamp", DateTime.Now.ToString("HH:mm:ss.fff"));
		oResponse.headers.Add("FiddlerGateway", "AutoResponder");
		oResponse.headers.Add("Connection", "close");
		responseBodyBytes = Encoding.UTF8.GetBytes("This is a Fiddler-generated response to the client's request for a CONNECT tunnel.\n\n");
		oFlags["ui-backcolor"] = "Lavender";
		oFlags.Remove("x-no-decrypt");
		FiddlerApplication.DoBeforeResponse(this);
		state = SessionStates.Done;
		FiddlerApplication.DoAfterSessionComplete(this);
		if (CONFIG.bUseSNIForCN && !oFlags.ContainsKey("x-OverrideCertCN"))
		{
			string sSNI = oFlags["https-Client-SNIHostname"];
			if (!string.IsNullOrEmpty(sSNI) && sSNI != sHostname)
			{
				oFlags["x-OverrideCertCN"] = oFlags["https-Client-SNIHostname"];
			}
		}
		string sCertCN = oFlags["x-OverrideCertCN"] ?? Utilities.StripIPv6LiteralBrackets(sHostname);
		if (oRequest.pipeClient == null || !oRequest.pipeClient.SecureClientPipe(sCertCN, oResponse.headers))
		{
			CloseSessionPipes(bNullThemToo: false);
			return;
		}
		Session oFauxSecureSession = new Session(oRequest.pipeClient, null);
		oRequest.pipeClient = null;
		oFauxSecureSession.oFlags["x-serversocket"] = "AUTO-RESPONDER-GENERATED";
		oFauxSecureSession.Execute(null);
	}

	/// <summary>
	/// This method adds a Proxy-Support: Session-Based-Authentication header and indicates whether the response is Nego:Type2.
	/// </summary>
	/// <returns>Returns TRUE if server returned a credible Type2 NTLM Message</returns>
	private bool _isNTLMType2()
	{
		if (!oFlags.ContainsKey("x-SuppressProxySupportHeader"))
		{
			oResponse.headers["Proxy-Support"] = "Session-Based-Authentication";
		}
		if (407 == oResponse.headers.HTTPResponseCode)
		{
			if (oRequest.headers["Proxy-Authorization"].Length < 1)
			{
				return false;
			}
			if (!oResponse.headers.Exists("Proxy-Authenticate") || oResponse.headers["Proxy-Authenticate"].Length < 6)
			{
				return false;
			}
		}
		else
		{
			if (string.IsNullOrEmpty(oRequest.headers["Authorization"]))
			{
				return false;
			}
			if (!oResponse.headers.Exists("WWW-Authenticate") || oResponse.headers["WWW-Authenticate"].Length < 6)
			{
				return false;
			}
		}
		return true;
	}

	/// <summary>
	/// This helper evaluates the conditions for client socket reuse.
	/// </summary>
	/// <returns></returns>
	private bool _MayReuseMyClientPipe()
	{
		return CONFIG.ReuseClientSockets && _bAllowClientPipeReuse && !oResponse.headers.ExistsAndEquals("Connection", "close") && !oRequest.headers.ExistsAndEquals("Connection", "close") && !oResponse.headers.ExistsAndEquals("Proxy-Connection", "close") && !oRequest.headers.ExistsAndEquals("Proxy-Connection", "close") && (oResponse.headers.HTTPVersion == "HTTP/1.1" || oResponse.headers.ExistsAndContains("Connection", "Keep-Alive"));
	}

	/// <summary>
	/// Sends the Response that Fiddler received from the server back to the client socket.
	/// </summary>
	/// <param name="bForceClientServerPipeAffinity">Should the client and server pipes be tightly-bound together?</param>
	/// <returns>True, if the response was successfully sent to the client</returns>
	internal bool ReturnResponse(bool bForceClientServerPipeAffinity)
	{
		state = SessionStates.SendingResponse;
		bool result = false;
		Timers.ClientBeginResponse = (Timers.ClientDoneResponse = DateTime.Now);
		try
		{
			if (oRequest.pipeClient != null)
			{
				if (oFlags.ContainsKey("response-trickle-delay"))
				{
					int iDelayPerK = int.Parse(oFlags["response-trickle-delay"]);
					oRequest.pipeClient.TransmitDelay = iDelayPerK;
				}
				oRequest.pipeClient.Send(oResponse.headers.ToByteArray(prependStatusLine: true, appendEmptyLine: true));
				if (responseBodyBytes == Utilities.emptyByteArray && !string.IsNullOrEmpty(__sResponseFileToStream))
				{
					using FileStream file = File.OpenRead(__sResponseFileToStream);
					byte[] buffer = new byte[65536];
					int bytesRead;
					while ((bytesRead = file.Read(buffer, 0, buffer.Length)) > 0)
					{
						oRequest.pipeClient.Send(buffer, 0, bytesRead);
					}
				}
				else
				{
					oRequest.pipeClient.Send(responseBodyBytes);
				}
				Timers.ClientDoneResponse = DateTime.Now;
				if (responseCode == 101 && Utilities.HasHeaders(oRequest) && oRequest.headers.ExistsAndContains("Upgrade", "WebSocket") && Utilities.HasHeaders(oResponse) && oResponse.headers.ExistsAndContains("Upgrade", "WebSocket"))
				{
					FiddlerApplication.DebugSpew("Upgrading Session #{0} to Websocket", id);
					WebSocket.CreateTunnel(this);
					state = SessionStates.Done;
					FinishUISession();
					return true;
				}
				if (responseCode != 200 || !HTTPMethodIs("CONNECT") || oRequest.pipeClient == null)
				{
					goto IL_0612;
				}
				bForceClientServerPipeAffinity = true;
				if (isAnyFlagSet(SessionFlags.Ignored) || (oFlags.ContainsKey("x-no-decrypt") && oFlags.ContainsKey("x-no-parse")))
				{
					oFlags["x-CONNECT-Peek"] = "Skipped";
					oFlags["x-no-decrypt"] += "Skipped";
					oFlags["x-no-parse"] += "Skipped";
					FiddlerApplication.DebugSpew("Session #{0} set to act like a blind tunnel", id);
					CONNECTTunnel.CreateTunnel(this);
					result = true;
				}
				else
				{
					FiddlerApplication.DebugSpew("Returned Session #{0} CONNECT's 200 response to client; sniffing for client data in tunnel", id);
					Socket sockClient = oRequest.pipeClient.GetRawSocket();
					if (sockClient == null)
					{
						goto IL_0612;
					}
					byte[] arrTmp = new byte[1024];
					int iCNT = sockClient.Receive(arrTmp, SocketFlags.Peek);
					if (iCNT == 0)
					{
						oFlags["x-CONNECT-Peek"] = "After the client received notice of the established CONNECT, it failed to send any data.";
						requestBodyBytes = Encoding.UTF8.GetBytes("After the client received notice of the established CONNECT, it failed to send any data.\n");
						if (isFlagSet(SessionFlags.SentToGateway))
						{
							PoisonServerPipe();
						}
						PoisonClientPipe();
						oRequest.pipeClient.End();
						result = true;
					}
					else
					{
						if (CONFIG.bDebugSpew)
						{
							FiddlerApplication.DebugSpew("Peeking at the first bytes from CONNECT'd client session {0} yielded:\n{1}", id, Utilities.ByteArrayToHexView(arrTmp, 32, iCNT));
						}
						if (arrTmp[0] == 22 || arrTmp[0] == 128)
						{
							FiddlerApplication.DebugSpew("Session [{0}] looks like a HTTPS tunnel!", id);
							try
							{
								HTTPSClientHello oHello = new HTTPSClientHello();
								if (oHello.LoadFromStream(new MemoryStream(arrTmp, 0, iCNT, writable: false)))
								{
									requestBodyBytes = Encoding.UTF8.GetBytes(oHello.ToString() + "\n");
									this["https-Client-SessionID"] = oHello.SessionID;
									if (!string.IsNullOrEmpty(oHello.ServerNameIndicator))
									{
										this["https-Client-SNIHostname"] = oHello.ServerNameIndicator;
									}
								}
							}
							catch (Exception)
							{
							}
							CONNECTTunnel.CreateTunnel(this);
							result = true;
						}
						else
						{
							if (iCNT > 4 && ((arrTmp[0] == 71 && arrTmp[1] == 69 && arrTmp[2] == 84 && arrTmp[3] == 32) || (arrTmp[0] == 80 && arrTmp[1] == 79 && arrTmp[2] == 83 && arrTmp[3] == 84) || (arrTmp[0] == 80 && arrTmp[1] == 85 && arrTmp[2] == 84 && arrTmp[3] == 32) || (arrTmp[0] == 72 && arrTmp[1] == 69 && arrTmp[2] == 65 && arrTmp[3] == 68)))
							{
								FiddlerApplication.DebugSpew("Session [{0}] looks like it's going to be an unencrypted WebSocket tunnel!", id);
								SetBitFlag(SessionFlags.IsRPCTunnel, b: true);
								goto IL_0612;
							}
							FiddlerApplication.DebugSpew("Session [{0}] CONNECT Peek yielded unknown protocol!", id);
							oFlags["x-CONNECT-Peek"] = BitConverter.ToString(arrTmp, 0, Math.Min(iCNT, 16));
							oFlags["x-no-decrypt"] = "PeekYieldedUnknownProtocol";
							CONNECTTunnel.CreateTunnel(this);
							result = true;
						}
					}
				}
			}
			else
			{
				result = true;
			}
			goto end_IL_002a;
			IL_0612:
			if (bForceClientServerPipeAffinity || _MayReuseMyClientPipe())
			{
				FiddlerApplication.DebugSpew("Creating next session with pipes from {0}.", id);
				_createNextSession(bForceClientServerPipeAffinity);
				result = true;
			}
			else
			{
				if (CONFIG.bDebugSpew)
				{
					FiddlerApplication.DebugSpew("fiddler.network.clientpipereuse> Closing client socket since bReuseClientSocket was false after returning [{0}]", url);
				}
				oRequest.pipeClient.End();
				result = true;
			}
			end_IL_002a:;
		}
		catch (Exception eX2)
		{
			if (CONFIG.bDebugSpew)
			{
				FiddlerApplication.DebugSpew("Write to client failed for Session #{0}; exception was {1}", id, eX2.ToString());
			}
			state = SessionStates.Aborted;
			PoisonClientPipe();
		}
		oRequest.pipeClient = null;
		if (result)
		{
			state = SessionStates.Done;
			try
			{
				FinishUISession();
			}
			catch (Exception)
			{
			}
		}
		FiddlerApplication.DoAfterSessionComplete(this);
		if (oFlags.ContainsKey("log-drop-response-body") && !Utilities.IsNullOrEmpty(responseBodyBytes))
		{
			oFlags["x-ResponseBodyFinalLength"] = responseBodyBytes.LongLength.ToString("N0");
			SetBitFlag(SessionFlags.ResponseBodyDropped, b: true);
			responseBodyBytes = Utilities.emptyByteArray;
		}
		if (oFlags.ContainsKey("log-drop-request-body") && !Utilities.IsNullOrEmpty(requestBodyBytes))
		{
			oFlags["x-RequestBodyFinalLength"] = requestBodyBytes.LongLength.ToString("N0");
			SetBitFlag(SessionFlags.RequestBodyDropped, b: true);
			requestBodyBytes = Utilities.emptyByteArray;
		}
		return result;
	}

	/// <summary>
	/// Sets up the next Session on these pipes, binding this Session's pipes to that new Session, as appropriate. When this method is called,
	/// the nextSession variable is populated with the new Session, and that object is executed at the appropriate time.
	/// </summary>
	/// <param name="bForceClientServerPipeAffinity">TRUE if both the client and server pipes should be bound regardless of the serverPipe's ReusePolicy</param>
	private void _createNextSession(bool bForceClientServerPipeAffinity)
	{
		if (oResponse != null && oResponse.pipeServer != null && (bForceClientServerPipeAffinity || oResponse.pipeServer.ReusePolicy == PipeReusePolicy.MarriedToClientPipe || oFlags.ContainsKey("X-ClientServerPipeAffinity")))
		{
			nextSession = new Session(oRequest.pipeClient, oResponse.pipeServer);
			oResponse.pipeServer = null;
		}
		else
		{
			nextSession = new Session(oRequest.pipeClient, null);
		}
	}

	internal void FinishUISession()
	{
	}

	private void RaiseSessionCreated()
	{
		Session.SessionCreated?.Invoke(this, this);
	}

	internal void RaiseSessionFieldChanged()
	{
		Session.SessionFieldChanged?.Invoke(this, this);
	}
}
