using System;
using System.Collections.Specialized;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security;
using System.Security.Authentication;
using System.Text;
using System.Threading;
using FiddlerCore.Utilities;

namespace Fiddler;

/// <summary>
/// The ServerChatter object is responsible for transmitting the Request to the destination server and retrieving its Response.
/// </summary>
/// <remarks>
/// This class maintains its own PipeReadBuffer that it fills from the created or reused ServerPipe. After it determines that
/// a complete response is present, it allows the caller to grab that array using the TakeEntity method. If
/// unsatisfied with the result (e.g. a network error), the caller can call Initialize() and SendRequest() again.
/// </remarks>
public class ServerChatter
{
	/// <summary>
	/// The ExecutionState object holds information that is used by the Connect-to-Host state machine
	/// </summary>
	internal class MakeConnectionExecutionState
	{
		internal StateConnecting CurrentState;

		internal AsyncCallback OnDone;

		internal string sPoolKeyContext = null;

		internal string sTarget = null;

		internal bool bUseSOCKSGateway = false;

		internal IPEndPoint[] ipepGateways = null;

		internal IPEndPoint[] arrIPEPDest = null;

		internal string sServerHostname = null;

		internal string sSuitableConnectionID = null;

		internal Socket newSocket = null;

		internal Exception lastException = null;

		internal int iServerPort = -1;
	}

	internal enum StateConnecting : byte
	{
		BeginFindGateway,
		EndFindGateway,
		BeginGenerateIPEndPoint,
		EndGenerateIPEndPoint,
		BeginConnectSocket,
		EndConnectSocket,
		Established,
		Failed
	}

	/// <summary>
	/// Size of buffer passed to pipe.Receive when reading from the server
	/// </summary>
	/// <remarks>
	/// PERF: Currently, I use [32768]; but I'd assume bigger buffers are faster. Does ReceiveBufferSize/SO_RCVBUF figure in here?
	/// Anecdotal data suggests that current reads rarely fill the full 32k buffer.
	/// </remarks>
	internal static int s_cbServerReadBuffer = 32768;

	internal static int s_SO_SNDBUF_Option = -1;

	internal static int s_SO_RCVBUF_Option = -1;

	/// <summary>
	/// Interval, in milliseconds, after which Fiddler will check to see whether a response should continue to be read. Otherwise,
	/// a never-ending network stream can accumulate ever larger amounts of data that will never be seen by the garbage collector.
	/// </summary>
	internal static int s_WATCHDOG_INTERVAL = FiddlerApplication.Prefs.GetInt32Pref("fiddler.network.timeouts.serverpipe.watchdoginterval", (int)new TimeSpan(0, 5, 0).TotalMilliseconds);

	/// <summary>
	/// The pipeServer represents Fiddler's connection to the server.
	/// </summary>
	public ServerPipe pipeServer;

	/// <summary>
	/// The session to which this ServerChatter belongs
	/// </summary>
	private Session m_session;

	/// <summary>
	/// The inbound headers on this response
	/// </summary>
	private HTTPResponseHeaders m_inHeaders;

	/// <summary>
	/// Indicates whether this request was sent to a (non-SOCKS) Gateway, which influences whether the protocol and host are
	/// mentioned in the Request line
	/// When True, the session should have SessionFlags.SentToGateway set.
	/// </summary>
	internal bool m_bWasForwarded;

	/// <summary>
	/// Buffer holds this response's data as it is read from the pipe.
	/// </summary>
	private PipeReadBuffer m_responseData;

	/// <summary>
	/// The total count of bytes read for this response. Typically equals m_responseData.Length unless 
	/// Streaming &amp; Log-Drop-Response-Body - in which case it will be larger since the m_responseData is cleared after every read.
	///
	/// BUG BUG: This value is reset to 0 when clearing streamed data. It probably shouldn't be; the problem is that this field is getting used for two purposes
	/// </summary>
	internal long m_responseTotalDataCount;

	/// <summary>
	/// Pointer to first byte of Entity body (or to the start of the next set of headers in the case where there's a HTTP/1xx intermediate header)
	/// Note: This gets reset to 0 if we're streaming and dropping the response body.
	/// </summary>
	private int m_iEntityBodyOffset;

	/// <summary>
	/// Optimization: tracks how far we've looked into the Request when determining iEntityBodyOffset
	/// </summary>
	private int m_iBodySeekProgress;

	/// <summary>
	/// True if final (non-1xx) HTTP Response headers have been returned to the client.
	/// </summary>
	private bool m_bLeakedHeaders;

	/// <summary>
	/// Indicates how much of _responseData buffer has already been streamed to the client
	/// </summary>
	private long m_lngLeakedOffset;

	/// <summary>
	/// Position in responseData of the start of the latest parsed chunk size information
	/// </summary>
	private long m_lngLastChunkInfoOffset = -1L;

	/// <summary>
	/// Locals used by the Connect-to-Host state machine
	/// </summary>
	private MakeConnectionExecutionState _esState;

	private readonly object _esStateLock = new object();

	internal bool bLeakedHeaders => m_bLeakedHeaders;

	/// <summary>
	/// Peek at number of bytes downloaded thus far.
	/// </summary>
	internal long _PeekDownloadProgress => (m_responseData == null) ? (-1) : m_responseTotalDataCount;

	/// <summary>
	/// Get the MIME type (sans Character set or other attributes) from the HTTP Content-Type response header, or String.Empty if missing.
	/// </summary>
	public string MIMEType
	{
		get
		{
			if (headers == null)
			{
				return string.Empty;
			}
			string sMIME = headers["Content-Type"];
			if (sMIME.Length > 0)
			{
				sMIME = Utilities.TrimAfter(sMIME, ';').Trim();
			}
			return sMIME;
		}
	}

	/// <summary>
	/// DEPRECATED: You should use the Timers object on the Session object instead.
	/// The number of milliseconds between the start of sending the request to the server to the first byte of the server's response
	/// </summary>
	public int iTTFB
	{
		get
		{
			int i = (int)(m_session.Timers.ServerBeginResponse - m_session.Timers.FiddlerBeginRequest).TotalMilliseconds;
			return (i > 0) ? i : 0;
		}
	}

	/// <summary>
	/// DEPRECATED: You should use the Timers object on the Session object instead.
	/// The number of milliseconds between the start of sending the request to the server to the last byte of the server's response.
	/// </summary>
	public int iTTLB
	{
		get
		{
			int i = (int)(m_session.Timers.ServerDoneResponse - m_session.Timers.FiddlerBeginRequest).TotalMilliseconds;
			return (i > 0) ? i : 0;
		}
	}

	/// <summary>
	/// Was this request forwarded to a gateway?
	/// </summary>
	public bool bWasForwarded => m_bWasForwarded;

	/// <summary>
	/// Was this request serviced from a reused server connection?
	/// </summary>
	public bool bServerSocketReused => m_session.isFlagSet(SessionFlags.ServerPipeReused);

	/// <summary>
	/// The HTTP headers of the server's response
	/// </summary>
	public HTTPResponseHeaders headers
	{
		get
		{
			return m_inHeaders;
		}
		set
		{
			if (value != null)
			{
				m_inHeaders = value;
			}
		}
	}

	/// <summary>
	/// Simple indexer into the Response Headers object
	/// </summary>
	public string this[string sHeader]
	{
		get
		{
			if (m_inHeaders != null)
			{
				return m_inHeaders[sHeader];
			}
			return string.Empty;
		}
		set
		{
			if (m_inHeaders != null)
			{
				m_inHeaders[sHeader] = value;
				return;
			}
			throw new InvalidDataException("Response Headers object does not exist");
		}
	}

	internal ServerChatter(Session oSession)
	{
		m_session = oSession;
		m_responseData = new PipeReadBuffer(bIsRequest: false);
	}

	/// <summary>
	/// Create a ServerChatter object and initialize its headers from the specified string
	/// </summary>
	/// <param name="oSession"></param>
	/// <param name="sHeaders"></param>
	internal ServerChatter(Session oSession, string sHeaders)
	{
		m_session = oSession;
		m_inHeaders = Parser.ParseResponse(sHeaders);
	}

	/// <summary>
	/// Reset the response-reading fields on the object. Also used on a retry.
	/// </summary>
	/// <param name="bAllocatePipeReadBuffer">If TRUE, allocates a buffer (m_responseData) to read from a pipe. If FALSE, nulls m_responseData.</param>
	internal void Initialize(bool bAllocatePipeReadBuffer)
	{
		m_responseData = (bAllocatePipeReadBuffer ? new PipeReadBuffer(bIsRequest: false) : null);
		m_responseTotalDataCount = (m_lngLeakedOffset = (m_iBodySeekProgress = (m_iEntityBodyOffset = 0)));
		m_lngLastChunkInfoOffset = -1L;
		m_inHeaders = null;
		m_bLeakedHeaders = false;
		if (pipeServer != null)
		{
			FiddlerApplication.DebugSpew("Reinitializing ServerChatter; detaching ServerPipe.");
			pipeServer.End();
			pipeServer = null;
		}
		m_bWasForwarded = false;
		m_session.SetBitFlag(SessionFlags.ServerPipeReused, b: false);
	}

	/// <summary>
	/// Peek at the current response body and return it as an array
	/// </summary>
	/// <returns>The response body as an array, or byte[0]</returns>
	internal byte[] _PeekAtBody()
	{
		if (m_iEntityBodyOffset < 1 || m_responseData == null || m_responseData.Length < 1)
		{
			return Utilities.emptyByteArray;
		}
		int lngSize = (int)m_responseData.Length - m_iEntityBodyOffset;
		if (lngSize < 1)
		{
			return Utilities.emptyByteArray;
		}
		byte[] arrBody = new byte[lngSize];
		Buffer.BlockCopy(m_responseData.GetBuffer(), m_iEntityBodyOffset, arrBody, 0, lngSize);
		return arrBody;
	}

	/// <summary>
	/// Get the response body byte array from the PipeReadBuffer, then dispose of it.
	///
	/// WARNING: This eats all of the bytes in the Pipe, even if that includes bytes of a 
	/// future, as-yet-unrequested response. Fiddler does not pipeline requests, so that works okay for now.
	/// For now, the caller should validate that the returned entity is of the expected size (e.g. based on Content-Length)
	/// </summary>
	internal byte[] TakeEntity()
	{
		long iSize = m_responseData.Length - m_iEntityBodyOffset;
		if (iSize < 1)
		{
			FreeResponseDataBuffer();
			return Utilities.emptyByteArray;
		}
		byte[] arrResult;
		try
		{
			arrResult = new byte[iSize];
			Buffer.BlockCopy(m_responseData.GetBuffer(), m_iEntityBodyOffset, arrResult, 0, arrResult.Length);
		}
		catch (OutOfMemoryException oOOM)
		{
			string title = "HTTP Response Too Large";
			FiddlerApplication.Log.LogFormat("{0}: {1}", title, oOOM.ToString());
			arrResult = Encoding.ASCII.GetBytes("Fiddler: Out-of-memory/contiguous-address-space");
			m_session.PoisonServerPipe();
		}
		FreeResponseDataBuffer();
		return arrResult;
	}

	internal void FreeResponseDataBuffer()
	{
		if (m_responseData != null)
		{
			m_responseData.Dispose();
			m_responseData = null;
		}
	}

	/// <summary>
	/// Scans responseData stream for the \r\n\r\n (or variants) sequence
	/// which indicates that the header block is complete.
	///
	/// SIDE EFFECTS:
	///     iBodySeekProgress is updated and maintained across calls to this function
	///     iEntityBodyOffset is updated if the end of headers is found
	/// </summary>
	/// <returns>True, if responseData contains a full set of headers</returns>
	private bool HeadersAvailable()
	{
		if (m_iEntityBodyOffset > 0)
		{
			return true;
		}
		if (m_responseData == null)
		{
			return false;
		}
		byte[] arrData = m_responseData.GetBuffer();
		if (Parser.FindEndOfHeaders(arrData, ref m_iBodySeekProgress, m_responseData.Length, out var oHPW))
		{
			m_iEntityBodyOffset = m_iBodySeekProgress + 1;
			switch (oHPW)
			{
			case HTTPHeaderParseWarnings.EndedWithLFLF:
				FiddlerApplication.HandleHTTPError(m_session, SessionFlags.ProtocolViolationInResponse, bPoisonClientConnection: false, bPoisonServerConnection: true, "The Server did not return properly formatted HTTP Headers. HTTP headers\nshould be terminated with CRLFCRLF. These were terminated with LFLF.");
				break;
			case HTTPHeaderParseWarnings.EndedWithLFCRLF:
				FiddlerApplication.HandleHTTPError(m_session, SessionFlags.ProtocolViolationInResponse, bPoisonClientConnection: false, bPoisonServerConnection: true, "The Server did not return properly formatted HTTP Headers. HTTP headers\nshould be terminated with CRLFCRLF. These were terminated with LFCRLF.");
				break;
			}
			return true;
		}
		return false;
	}

	/// <summary>
	/// Parse the HTTP Response into Headers and Body.
	/// </summary>
	/// <returns></returns>
	private bool ParseResponseForHeaders()
	{
		if (m_responseData == null || m_iEntityBodyOffset < 4)
		{
			return false;
		}
		m_inHeaders = new HTTPResponseHeaders(CONFIG.oHeaderEncoding);
		byte[] arrResponse = m_responseData.GetBuffer();
		string sResponseHeaders = CONFIG.oHeaderEncoding.GetString(arrResponse, 0, m_iEntityBodyOffset).Trim();
		if (sResponseHeaders == null || sResponseHeaders.Length < 1)
		{
			m_inHeaders = null;
			return false;
		}
		string[] arrHeaderLines = sResponseHeaders.Replace("\r\n", "\n").Split(new char[1] { '\n' });
		if (arrHeaderLines.Length < 1)
		{
			return false;
		}
		int ixToken = arrHeaderLines[0].IndexOf(' ');
		if (ixToken > 0)
		{
			m_inHeaders.HTTPVersion = arrHeaderLines[0].Substring(0, ixToken).ToUpperInvariant();
			arrHeaderLines[0] = arrHeaderLines[0].Substring(ixToken + 1).Trim();
			if (!m_inHeaders.HTTPVersion.OICStartsWith("HTTP/"))
			{
				if (!m_inHeaders.HTTPVersion.OICStartsWith("ICY"))
				{
					FiddlerApplication.HandleHTTPError(m_session, SessionFlags.ProtocolViolationInResponse, bPoisonClientConnection: false, bPoisonServerConnection: true, "Response does not start with HTTP. Data:\n\n\t" + arrHeaderLines[0]);
					return false;
				}
				m_session.bBufferResponse = false;
				m_session.oFlags["log-drop-response-body"] = "ICY";
			}
			m_inHeaders.HTTPResponseStatus = arrHeaderLines[0];
			bool bGotStatusCode = false;
			ixToken = arrHeaderLines[0].IndexOf(' ');
			if (ixToken > 0)
			{
				bGotStatusCode = int.TryParse(arrHeaderLines[0].Substring(0, ixToken).Trim(), NumberStyles.Integer, NumberFormatInfo.InvariantInfo, out m_inHeaders.HTTPResponseCode);
			}
			else
			{
				string sRestOfLine = arrHeaderLines[0].Trim();
				bGotStatusCode = int.TryParse(sRestOfLine, NumberStyles.Integer, NumberFormatInfo.InvariantInfo, out m_inHeaders.HTTPResponseCode);
				if (!bGotStatusCode)
				{
					for (int iXFirstChar = 0; iXFirstChar < sRestOfLine.Length; iXFirstChar++)
					{
						if (!char.IsDigit(sRestOfLine[iXFirstChar]))
						{
							bGotStatusCode = int.TryParse(sRestOfLine.Substring(0, iXFirstChar), NumberStyles.Integer, NumberFormatInfo.InvariantInfo, out m_inHeaders.HTTPResponseCode);
							if (bGotStatusCode)
							{
								FiddlerApplication.HandleHTTPError(m_session, SessionFlags.ProtocolViolationInResponse, bPoisonClientConnection: false, bPoisonServerConnection: false, "The response's status line was missing a space between ResponseCode and ResponseStatus. Data:\n\n\t" + sRestOfLine);
							}
							break;
						}
					}
				}
			}
			if (!bGotStatusCode)
			{
				FiddlerApplication.HandleHTTPError(m_session, SessionFlags.ProtocolViolationInResponse, bPoisonClientConnection: false, bPoisonServerConnection: true, "The response's status line did not contain a ResponseCode. Data:\n\n\t" + arrHeaderLines[0]);
				return false;
			}
			string sErrs = string.Empty;
			if (!Parser.ParseNVPHeaders(m_inHeaders, arrHeaderLines, 1, ref sErrs))
			{
				FiddlerApplication.HandleHTTPError(m_session, SessionFlags.ProtocolViolationInResponse, bPoisonClientConnection: false, bPoisonServerConnection: true, "Incorrectly formed response headers.\n" + sErrs);
			}
			if (m_inHeaders.Exists("Content-Length") && m_inHeaders.ExistsAndContains("Transfer-Encoding", "chunked"))
			{
				FiddlerApplication.HandleHTTPError(m_session, SessionFlags.ProtocolViolationInRequest, bPoisonClientConnection: false, bPoisonServerConnection: false, "Content-Length response header MUST NOT be present when Transfer-Encoding is used (RFC2616 Section 4.4)");
			}
			return true;
		}
		FiddlerApplication.HandleHTTPError(m_session, SessionFlags.ProtocolViolationInResponse, bPoisonClientConnection: false, bPoisonServerConnection: true, "Cannot parse HTTP response; Status line contains no spaces. Data:\n\n\t" + arrHeaderLines[0]);
		return false;
	}

	/// <summary>
	/// Attempt to pull the final (non-1xx) Headers from the stream. If HTTP/100 messages are found, the method
	/// will recurse into itself to find the next set of headers.
	/// </summary>
	private bool GetHeaders()
	{
		if (!HeadersAvailable())
		{
			return false;
		}
		if (!ParseResponseForHeaders())
		{
			m_session.SetBitFlag(SessionFlags.ProtocolViolationInResponse, b: true);
			_PoisonPipe();
			string sDetailedError = ((m_responseData == null) ? "{Fiddler:no data}" : ("<plaintext>\n" + Utilities.ByteArrayToHexView(m_responseData.GetBuffer(), 24, (int)Math.Min(m_responseData.Length, 2048L))));
			m_session.oRequest.FailSession(500, "Fiddler - Bad Response", string.Format("[Fiddler] Response Header parsing failed.\n{0}Response Data:\n{1}", m_session.isFlagSet(SessionFlags.ServerPipeReused) ? "This can be caused by an illegal HTTP response earlier on this reused server socket-- for instance, a HTTP/304 response which illegally contains a body.\n" : string.Empty, sDetailedError));
			return true;
		}
		if (m_inHeaders.HTTPResponseCode > 99 && m_inHeaders.HTTPResponseCode < 200)
		{
			if (m_inHeaders.Exists("Content-Length") && "0" != m_inHeaders["Content-Length"].Trim())
			{
				FiddlerApplication.HandleHTTPError(m_session, SessionFlags.ProtocolViolationInResponse, bPoisonClientConnection: false, bPoisonServerConnection: true, "HTTP/1xx responses MUST NOT contain a body, but a non-zero content-length was returned.");
			}
			if (m_inHeaders.HTTPResponseCode != 101 || !m_inHeaders.ExistsAndContains("Upgrade", "WebSocket"))
			{
				if (FiddlerApplication.Prefs.GetBoolPref("fiddler.network.leakhttp1xx", bDefault: true) && m_session.oRequest.pipeClient != null)
				{
					try
					{
						m_session.oRequest.pipeClient.Send(m_inHeaders.ToByteArray(prependStatusLine: true, appendEmptyLine: true));
						StringDictionary oFlags = m_session.oFlags;
						oFlags["x-fiddler-Stream1xx"] = oFlags["x-fiddler-Stream1xx"] + "Returned a HTTP/" + m_inHeaders.HTTPResponseCode + " message from the server.";
					}
					catch (Exception eXInner)
					{
						if (FiddlerApplication.Prefs.GetBoolPref("fiddler.network.streaming.abortifclientaborts", bDefault: false))
						{
							throw new Exception("Leaking HTTP/1xx response to client failed", eXInner);
						}
						FiddlerApplication.Log.LogFormat("fiddler.network.streaming> Streaming of HTTP/1xx headers from #{0} to client failed: {1}", m_session.id, eXInner.Message);
					}
				}
				else
				{
					StringDictionary oFlags = m_session.oFlags;
					oFlags["x-fiddler-streaming"] = oFlags["x-fiddler-streaming"] + "Eating a HTTP/" + m_inHeaders.HTTPResponseCode + " message from the stream.";
				}
				_deleteInformationalMessage();
				return GetHeaders();
			}
		}
		return true;
	}

	private bool isResponseBodyComplete()
	{
		if (m_session.HTTPMethodIs("HEAD"))
		{
			return true;
		}
		if (m_session.HTTPMethodIs("CONNECT") && m_inHeaders.HTTPResponseCode == 200)
		{
			return true;
		}
		if (m_inHeaders.HTTPResponseCode == 200 && m_session.isFlagSet(SessionFlags.IsRPCTunnel))
		{
			m_session.bBufferResponse = true;
			return true;
		}
		if (m_inHeaders.HTTPResponseCode == 204 || m_inHeaders.HTTPResponseCode == 205 || m_inHeaders.HTTPResponseCode == 304 || (m_inHeaders.HTTPResponseCode > 99 && m_inHeaders.HTTPResponseCode < 200))
		{
			if (m_inHeaders.Exists("Content-Length") && "0" != m_inHeaders["Content-Length"].Trim())
			{
				FiddlerApplication.HandleHTTPError(m_session, SessionFlags.ProtocolViolationInResponse, bPoisonClientConnection: false, bPoisonServerConnection: true, "This type of HTTP response MUST NOT contain a body, but a non-zero content-length was returned.");
				return true;
			}
			return true;
		}
		if (m_inHeaders.ExistsAndEquals("Transfer-Encoding", "chunked"))
		{
			if (m_lngLastChunkInfoOffset < m_iEntityBodyOffset)
			{
				m_lngLastChunkInfoOffset = m_iEntityBodyOffset;
			}
			long lngEndOfEntity;
			return Utilities.IsChunkedBodyComplete(m_session, m_responseData, m_lngLastChunkInfoOffset, out m_lngLastChunkInfoOffset, out lngEndOfEntity);
		}
		if (m_inHeaders.Exists("Content-Length"))
		{
			if (!long.TryParse(m_inHeaders["Content-Length"], NumberStyles.Integer, NumberFormatInfo.InvariantInfo, out var iEntityLength) || iEntityLength < 0)
			{
				FiddlerApplication.HandleHTTPError(m_session, SessionFlags.ProtocolViolationInResponse, bPoisonClientConnection: true, bPoisonServerConnection: true, "Content-Length response header is not a valid unsigned integer.\nContent-Length: " + m_inHeaders["Content-Length"]);
				return true;
			}
			return m_responseTotalDataCount >= m_iEntityBodyOffset + iEntityLength;
		}
		if (m_inHeaders.ExistsAndEquals("Connection", "close") || m_inHeaders.ExistsAndEquals("Proxy-Connection", "close") || (m_inHeaders.HTTPVersion != "HTTP/1.1" && !m_inHeaders.ExistsAndContains("Connection", "Keep-Alive")))
		{
			return false;
		}
		FiddlerApplication.HandleHTTPError(m_session, SessionFlags.ProtocolViolationInResponse, bPoisonClientConnection: true, bPoisonServerConnection: true, "No Connection: close, no Content-Length. No way to tell if the response is complete.");
		return false;
	}

	/// <summary>
	/// Deletes a single HTTP/1xx header block from the Response stream
	/// and adjusts all header-reading state to start over from the top of the stream. 
	/// Note: If 'fiddler.network.leakhttp1xx' is TRUE, then the 1xx message will have been leaked before calling this method.
	/// </summary>
	private void _deleteInformationalMessage()
	{
		m_inHeaders = null;
		int cbNextResponse = (int)m_responseData.Length - m_iEntityBodyOffset;
		PipeReadBuffer newResponse = new PipeReadBuffer(cbNextResponse);
		newResponse.Write(m_responseData.GetBuffer(), m_iEntityBodyOffset, cbNextResponse);
		m_responseData = newResponse;
		m_responseTotalDataCount = m_responseData.Length;
		m_iEntityBodyOffset = (m_iBodySeekProgress = 0);
	}

	/// <summary>
	/// Adjusts PipeServer's ReusePolicy if response headers require closure. Then calls _detachServerPipe()
	/// </summary>
	internal void releaseServerPipe()
	{
		if (pipeServer != null)
		{
			if (headers.ExistsAndEquals("Connection", "close") || headers.ExistsAndEquals("Proxy-Connection", "close") || (headers.HTTPVersion != "HTTP/1.1" && !headers.ExistsAndContains("Connection", "Keep-Alive")) || !pipeServer.Connected)
			{
				pipeServer.ReusePolicy = PipeReusePolicy.NoReuse;
			}
			_detachServerPipe();
		}
	}

	/// <summary>
	/// Queues or End()s the ServerPipe, depending on its ReusePolicy
	/// </summary>
	internal void _detachServerPipe()
	{
		if (pipeServer != null)
		{
			if (pipeServer.ReusePolicy != PipeReusePolicy.NoReuse && pipeServer.ReusePolicy != PipeReusePolicy.MarriedToClientPipe && pipeServer.isClientCertAttached && !pipeServer.isAuthenticated)
			{
				pipeServer.MarkAsAuthenticated(m_session.LocalProcessID);
			}
			Proxy.htServerPipePool.PoolOrClosePipe(pipeServer);
			pipeServer = null;
		}
	}

	/// <summary>
	/// Determines whether a given PIPE is suitable for a given Session, based on that Session's SID
	/// </summary>
	/// <param name="iPID">The Client Process ID, if any</param>
	/// <param name="sIDSession">The base (no PID) PoolKey expected by the session</param>
	/// <param name="sIDPipe">The pipe's pool key</param>
	/// <returns>TRUE if the connection should be used, FALSE otherwise</returns>
	private static bool SIDsMatch(int iPID, string sIDSession, string sIDPipe)
	{
		if (sIDSession.OICEquals(sIDPipe))
		{
			return true;
		}
		if (iPID != 0 && sIDPipe.OICEquals($"pid{iPID}*{sIDSession}"))
		{
			return true;
		}
		return false;
	}

	internal void BeginAsyncConnectToHost(AsyncCallback OnDone)
	{
		if (m_session.isFTP && !m_session.isFlagSet(SessionFlags.SentToGateway))
		{
			OnDone(null);
			return;
		}
		_esState = new MakeConnectionExecutionState();
		_esState.OnDone = OnDone;
		_esState.CurrentState = StateConnecting.BeginFindGateway;
		RunConnectionStateMachine();
	}

	internal void RunConnectionStateMachine()
	{
		bool bAsyncExit = false;
		do
		{
			if (_esState == null)
			{
				Exception eX = new NullReferenceException("Fatal Error in Session #" + m_session.id + ". Looping RunConnectionStateMachine, _esState null for " + m_session.fullUrl + "\r\nState: " + m_session.state);
				FiddlerApplication.Log.LogString(eX.ToString());
				throw eX;
			}
			switch (_esState.CurrentState)
			{
			case StateConnecting.BeginFindGateway:
				_esState.sTarget = m_session.oFlags["x-overrideHostName"];
				if (_esState.sTarget != null)
				{
					m_session.oFlags["x-overrideHost"] = $"{_esState.sTarget}:{m_session.port}";
				}
				_esState.sTarget = m_session.oFlags["x-overrideHost"];
				if (_esState.sTarget == null)
				{
					if (m_session.HTTPMethodIs("CONNECT"))
					{
						_esState.sTarget = m_session.PathAndQuery;
					}
					else
					{
						_esState.sTarget = m_session.host;
					}
				}
				else
				{
					_esState.sPoolKeyContext = $"-for-{m_session.host}";
				}
				if (m_session.oFlags["x-overrideGateway"] != null)
				{
					if ("DIRECT".OICEquals(m_session.oFlags["x-overrideGateway"]))
					{
						m_session.bypassGateway = true;
					}
					else
					{
						string sGatewayOverride = m_session.oFlags["x-overrideGateway"];
						if (sGatewayOverride.OICStartsWith("socks="))
						{
							_esState.bUseSOCKSGateway = true;
							sGatewayOverride = sGatewayOverride.Substring(6);
						}
						_esState.ipepGateways = Utilities.IPEndPointListFromHostPortString(sGatewayOverride);
						if (_esState.ipepGateways == null)
						{
							FiddlerApplication.DebugSpew("DNS lookup failed for X-OverrideGateway: '{0}'", sGatewayOverride);
							if (_esState.bUseSOCKSGateway)
							{
								m_session.oRequest.FailSession(502, "Fiddler - SOCKS Proxy DNS Lookup Failed", string.Format("[Fiddler] DNS Lookup for SOCKS Proxy \"{0}\" failed. {1}", Utilities.HtmlEncode(sGatewayOverride), NetworkInterface.GetIsNetworkAvailable() ? string.Empty : "The system reports that no network connection is available. \n"));
								_esState.CurrentState = StateConnecting.Failed;
								break;
							}
							if (!FiddlerApplication.Prefs.GetBoolPref("fiddler.proxy.IgnoreGatewayOverrideIfUnreachable", bDefault: false))
							{
								m_session.oRequest.FailSession(502, "Fiddler - Proxy DNS Lookup Failed", string.Format("[Fiddler] DNS Lookup for Proxy \"{0}\" failed. {1}", Utilities.HtmlEncode(sGatewayOverride), NetworkInterface.GetIsNetworkAvailable() ? string.Empty : "The system reports that no network connection is available. \n"));
								_esState.CurrentState = StateConnecting.Failed;
								break;
							}
						}
					}
				}
				else if (!m_session.bypassGateway)
				{
					int iGWDTC = Environment.TickCount;
					string sScheme = m_session.oRequest.headers.UriScheme;
					if (sScheme == "http" && m_session.HTTPMethodIs("CONNECT"))
					{
						sScheme = "https";
					}
					IPEndPoint ipepMyGateway = FiddlerApplication.oProxy.FindGatewayForOrigin(sScheme, _esState.sTarget);
					if (ipepMyGateway != null)
					{
						if (CONFIG.bDebugSpew)
						{
							FiddlerApplication.DebugSpew("Using Gateway: '{0}' for request to '{1}'", ipepMyGateway.ToString(), m_session.fullUrl);
						}
						_esState.ipepGateways = new IPEndPoint[1];
						_esState.ipepGateways[0] = ipepMyGateway;
					}
					m_session.Timers.GatewayDeterminationTime = Environment.TickCount - iGWDTC;
				}
				_esState.CurrentState++;
				break;
			case StateConnecting.EndFindGateway:
				if (_esState.ipepGateways != null)
				{
					m_bWasForwarded = true;
				}
				else if (m_session.isFTP)
				{
					_esState.CurrentState = StateConnecting.Established;
					break;
				}
				_esState.iServerPort = (m_session.isHTTPS ? 443 : (m_session.isFTP ? 21 : 80));
				Utilities.CrackHostAndPort(_esState.sTarget, out _esState.sServerHostname, ref _esState.iServerPort);
				if (_esState.ipepGateways != null)
				{
					if (m_session.isHTTPS || _esState.bUseSOCKSGateway)
					{
						_esState.sSuitableConnectionID = string.Format("{0}:{1}->{2}/{3}:{4}", _esState.bUseSOCKSGateway ? "socks" : "gw", _esState.ipepGateways[0], m_session.isHTTPS ? "https" : "http", _esState.sServerHostname, _esState.iServerPort);
					}
					else
					{
						_esState.sSuitableConnectionID = $"gw:{_esState.ipepGateways[0]}->*";
					}
				}
				else
				{
					_esState.sSuitableConnectionID = string.Format("direct->http{0}/{1}:{2}{3}", m_session.isHTTPS ? "s" : string.Empty, _esState.sServerHostname, _esState.iServerPort, _esState.sPoolKeyContext);
				}
				if (pipeServer != null && !m_session.oFlags.ContainsKey("X-ServerPipe-Marriage-Trumps-All") && !SIDsMatch(m_session.LocalProcessID, _esState.sSuitableConnectionID, pipeServer.sPoolKey))
				{
					FiddlerApplication.Log.LogFormat("Session #{0} detaching ServerPipe. Had: '{1}' but needs: '{2}'", m_session.id, pipeServer.sPoolKey, _esState.sSuitableConnectionID);
					m_session.oFlags["X-Divorced-ServerPipe"] = $"Had: '{pipeServer.sPoolKey}' but needs: '{_esState.sSuitableConnectionID}'";
					_detachServerPipe();
				}
				if (pipeServer == null && !m_session.oFlags.ContainsKey("X-Bypass-ServerPipe-Reuse-Pool"))
				{
					pipeServer = Proxy.htServerPipePool.TakePipe(_esState.sSuitableConnectionID, m_session.LocalProcessID, m_session.id);
				}
				if (pipeServer != null)
				{
					m_session.Timers.ServerConnected = pipeServer.dtConnected;
					StringDictionary oFlags = m_session.oFlags;
					oFlags["x-serversocket"] = oFlags["x-serversocket"] + "REUSE " + pipeServer._sPipeName;
					if (pipeServer.Address != null && !pipeServer.isConnectedToGateway)
					{
						m_session.m_hostIP = pipeServer.Address.ToString();
						m_session.oFlags["x-hostIP"] = m_session.m_hostIP;
					}
					if (CONFIG.bDebugSpew)
					{
						FiddlerApplication.DebugSpew("Session #{0} ({1} {2}): Reusing {3}\r\n", m_session.id, m_session.RequestMethod, m_session.fullUrl, pipeServer.ToString());
					}
					_esState.CurrentState = StateConnecting.Established;
				}
				else
				{
					if (m_session.oFlags.ContainsKey("x-serversocket"))
					{
						m_session.oFlags["x-serversocket"] += "*NEW*";
					}
					_esState.CurrentState++;
				}
				break;
			case StateConnecting.BeginGenerateIPEndPoint:
				if (_esState.ipepGateways != null)
				{
					_esState.arrIPEPDest = _esState.ipepGateways;
					_esState.CurrentState = StateConnecting.BeginConnectSocket;
					break;
				}
				if (_esState.iServerPort < 0 || _esState.iServerPort > 65535)
				{
					m_session.oRequest.FailSession(400, "Fiddler - Bad Request", "[Fiddler] HTTP Request specified an invalid port number.");
					_esState.CurrentState = StateConnecting.Failed;
					break;
				}
				try
				{
					if (DNSResolver.ResolveWentAsync(_esState, m_session.Timers, delegate
					{
						if (_esState == null)
						{
							_esState = new MakeConnectionExecutionState();
							_esState.CurrentState = StateConnecting.Failed;
						}
						else
						{
							_esState.CurrentState = StateConnecting.EndGenerateIPEndPoint;
						}
						RunConnectionStateMachine();
					}))
					{
						bAsyncExit = true;
						break;
					}
				}
				catch (Exception eX3)
				{
					_esState.lastException = eX3;
					_esState.CurrentState = StateConnecting.EndGenerateIPEndPoint;
					break;
				}
				_esState.CurrentState = StateConnecting.EndGenerateIPEndPoint;
				break;
			case StateConnecting.EndGenerateIPEndPoint:
				if (_esState.lastException != null)
				{
					m_session.oRequest.FailSession(502, "Fiddler - DNS Lookup Failed", string.Format("[Fiddler] DNS Lookup for \"{0}\" failed. {1}{2}", Utilities.HtmlEncode(_esState.sServerHostname), NetworkInterface.GetIsNetworkAvailable() ? string.Empty : "The system reports that no network connection is available. \n", FiddlerCore.Utilities.Utilities.DescribeException(_esState.lastException)));
					_esState.CurrentState = StateConnecting.Failed;
				}
				else
				{
					_esState.CurrentState++;
				}
				break;
			case StateConnecting.BeginConnectSocket:
				try
				{
					if (m_session.isHTTPS && m_bWasForwarded)
					{
						ManualResetEvent oWaitForTunnel = new ManualResetEvent(initialState: false);
						string sUA = m_session.oRequest["User-Agent"];
						string sProxyCreds = FiddlerApplication.Prefs.GetStringPref("fiddler.composer.HTTPSProxyBasicCreds", null);
						if (!string.IsNullOrEmpty(sProxyCreds))
						{
							sProxyCreds = Convert.ToBase64String(Encoding.UTF8.GetBytes(sProxyCreds));
						}
						HTTPRequestHeaders oRH = new HTTPRequestHeaders();
						oRH.HTTPMethod = "CONNECT";
						string sHostname = _esState.sServerHostname;
						if (sHostname.Contains(":") && !sHostname.Contains("["))
						{
							sHostname = "[" + sHostname + "]";
						}
						oRH.RequestPath = sHostname + ":" + _esState.iServerPort;
						oRH["Host"] = sHostname + ":" + _esState.iServerPort;
						if (!string.IsNullOrEmpty(sUA))
						{
							oRH["User-Agent"] = sUA;
						}
						if (!string.IsNullOrEmpty(sProxyCreds))
						{
							oRH["Proxy-Authorization"] = "Basic " + sProxyCreds;
						}
						Session oTunnel = new Session(oRH, null);
						oTunnel.SetBitFlag(SessionFlags.RequestGeneratedByFiddler, b: true);
						oTunnel.oFlags["X-AutoAuth"] = m_session["X-AutoAuth"];
						oTunnel.oFlags["x-CreatedTunnel"] = "Fiddler-Created-This-CONNECT-Tunnel";
						int iFinalResultCode = 0;
						oTunnel.OnCompleteTransaction += delegate(object s, EventArgs oEA)
						{
							if (!(s is Session session))
							{
								throw new InvalidDataException("Session must not be null when OnCompleteTransaction is called");
							}
							iFinalResultCode = session.responseCode;
							if (200 == iFinalResultCode)
							{
								ServerChatter oResponse = session.oResponse;
								if (oResponse != null)
								{
									ServerPipe serverPipe = oResponse.pipeServer;
									if (serverPipe != null)
									{
										lock (_esStateLock)
										{
											if (_esState != null)
											{
												_esState.newSocket = serverPipe.GetRawSocket();
											}
										}
										oResponse.pipeServer = null;
									}
								}
							}
							oWaitForTunnel.Set();
						};
						ThreadPool.UnsafeQueueUserWorkItem(oTunnel.Execute, null);
						if (!oWaitForTunnel.WaitOne(30000, exitContext: false))
						{
							throw new Exception("Upstream Gateway timed out CONNECT.");
						}
						if (iFinalResultCode != 200)
						{
							throw new Exception("Upstream Gateway refused requested CONNECT. " + iFinalResultCode);
						}
						if (_esState.newSocket == null)
						{
							throw new Exception("Upstream Gateway CONNECT failed.");
						}
						m_session.oFlags["x-CreatedTunnel"] = "Fiddler-Created-A-CONNECT-Tunnel";
					}
					else
					{
						_esState.newSocket = CreateConnectedSocket(_esState.arrIPEPDest, m_session);
						if (_esState.bUseSOCKSGateway)
						{
							_esState.newSocket = _SOCKSifyConnection(_esState.sServerHostname, _esState.iServerPort, _esState.newSocket);
						}
					}
					pipeServer = new ServerPipe(_esState.newSocket, "ServerPipe#" + m_session.id, m_bWasForwarded, _esState.sSuitableConnectionID);
					if (_esState.bUseSOCKSGateway)
					{
						pipeServer.isConnectedViaSOCKS = true;
					}
					if (m_session.isHTTPS)
					{
						SslProtocols sslprot = SslProtocols.None;
						if (m_session.oRequest != null && m_session.oRequest.pipeClient != null)
						{
							sslprot = m_session.oRequest.pipeClient.SecureProtocol;
						}
						if (!pipeServer.SecureExistingConnection(m_session, _esState.sServerHostname, m_session.oFlags["https-Client-Certificate"], sslprot, ref m_session.Timers.HTTPSHandshakeTime))
						{
							string sError = "Failed to negotiate HTTPS connection with server.";
							if (!Utilities.IsNullOrEmpty(m_session.responseBodyBytes))
							{
								sError += Encoding.UTF8.GetString(m_session.responseBodyBytes);
							}
							throw new SecurityException(sError);
						}
					}
					_esState.CurrentState = StateConnecting.Established;
				}
				catch (Exception eX2)
				{
					_smHandleConnectionException(eX2);
					_esState.CurrentState = StateConnecting.Failed;
				}
				break;
			case StateConnecting.EndConnectSocket:
				_esState.CurrentState++;
				break;
			case StateConnecting.Established:
				_smNotifyCSMDone();
				bAsyncExit = true;
				break;
			case StateConnecting.Failed:
				_smNotifyCSMDone();
				bAsyncExit = true;
				break;
			default:
			{
				Exception eeX = new InvalidOperationException("Fatal Error in Session #" + m_session.id + ". In RunConnectionStateMachine, _esState is " + _esState.CurrentState.ToString() + "\n" + m_session.fullUrl + "\r\nState: " + m_session.state);
				FiddlerApplication.Log.LogString(eeX.ToString());
				bAsyncExit = true;
				break;
			}
			}
		}
		while (!bAsyncExit);
	}

	private void _smNotifyCSMDone()
	{
		AsyncCallback acb = null;
		lock (_esStateLock)
		{
			if (_esState != null)
			{
				acb = _esState.OnDone;
				_esState = null;
			}
		}
		acb?.Invoke(null);
	}

	/// <summary>
	/// If a Connection cannot be established, we need to report the failure to our caller
	/// </summary>
	/// <param name="eX"></param>
	private void _smHandleConnectionException(Exception eX)
	{
		string sAdditionalTips = string.Empty;
		bool bGiveNetworkProxyAdvice = true;
		if (eX is SecurityException)
		{
			bGiveNetworkProxyAdvice = false;
		}
		if (eX is SocketException eXS)
		{
			if (eXS.SocketErrorCode == SocketError.AccessDenied || eXS.SocketErrorCode == SocketError.NetworkDown || eXS.SocketErrorCode == SocketError.InvalidArgument)
			{
				sAdditionalTips = $"A Firewall may be blocking Fiddler's traffic.<br />Error: {eXS.SocketErrorCode} (0x{(int)eXS.SocketErrorCode:x}).";
				bGiveNetworkProxyAdvice = false;
			}
			else
			{
				sAdditionalTips = $"<br />Error: {eXS.SocketErrorCode} (0x{(int)eXS.SocketErrorCode:x}).";
			}
		}
		string sStatusLine;
		string sErrorBody;
		if (m_bWasForwarded)
		{
			sStatusLine = "Fiddler - Gateway Connection Failed";
			sErrorBody = "[Fiddler] The connection to the upstream proxy/gateway failed.";
			if (bGiveNetworkProxyAdvice)
			{
				sAdditionalTips = $"Closing Fiddler, changing your system proxy settings, and restarting Fiddler may help. {sAdditionalTips}";
			}
		}
		else
		{
			sStatusLine = "Fiddler - Connection Failed";
			sErrorBody = $"[Fiddler] The connection to '{Utilities.HtmlEncode(_esState.sServerHostname)}' failed.";
		}
		m_session.oRequest.FailSession(502, sStatusLine, $"{sErrorBody} {sAdditionalTips} <br />{Utilities.HtmlEncode(FiddlerCore.Utilities.Utilities.DescribeException(eX))}");
	}

	/// <summary>
	/// Given an address list and port, attempts to create a socket to the first responding host in the list (retrying via DNS Failover if needed).
	/// </summary>
	/// <param name="arrDest">IPEndpoints to attempt to reach</param>
	/// <param name="_oSession">Session object to annotate with timings and errors</param>
	/// <returns>Connected Socket. Throws Exceptions on errors.</returns>
	private static Socket CreateConnectedSocket(IPEndPoint[] arrDest, Session _oSession)
	{
		Socket oSocket = null;
		bool bGotConnection = false;
		Stopwatch oSW = Stopwatch.StartNew();
		Exception exLast = null;
		foreach (IPEndPoint ipepDest in arrDest)
		{
			try
			{
				oSocket = new Socket(ipepDest.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
				oSocket.NoDelay = true;
				if (FiddlerApplication.oProxy._DefaultEgressEndPoint != null)
				{
					oSocket.Bind(FiddlerApplication.oProxy._DefaultEgressEndPoint);
				}
				oSocket.Connect(ipepDest);
				_oSession.m_hostIP = ipepDest.Address.ToString();
				_oSession.oFlags["x-hostIP"] = _oSession.m_hostIP;
				if (s_SO_RCVBUF_Option >= 0)
				{
					oSocket.ReceiveBufferSize = s_SO_RCVBUF_Option;
				}
				if (s_SO_SNDBUF_Option >= 0)
				{
					oSocket.SendBufferSize = s_SO_SNDBUF_Option;
				}
				FiddlerApplication.DoAfterSocketConnect(_oSession, oSocket);
				if (CONFIG.bDebugSpew)
				{
					FiddlerApplication.DebugSpew("[ServerPipe]\n SendBufferSize:\t{0}\n ReceiveBufferSize:\t{1}\n SendTimeout:\t{2}\n ReceiveTimeOut:\t{3}\n NoDelay:\t{4}\n EgressEP:\t{5}\n", oSocket.SendBufferSize, oSocket.ReceiveBufferSize, oSocket.SendTimeout, oSocket.ReceiveTimeout, oSocket.NoDelay, (FiddlerApplication.oProxy._DefaultEgressEndPoint != null) ? FiddlerApplication.oProxy._DefaultEgressEndPoint.ToString() : "none");
				}
				bGotConnection = true;
			}
			catch (Exception eX)
			{
				exLast = eX;
				if (!FiddlerApplication.Prefs.GetBoolPref("fiddler.network.dns.fallback", bDefault: true))
				{
					break;
				}
				_oSession.oFlags["x-DNS-Failover"] = _oSession.oFlags["x-DNS-Failover"] + "+1";
				continue;
			}
			break;
		}
		_oSession.Timers.ServerConnected = DateTime.Now;
		_oSession.Timers.TCPConnectTime = (int)oSW.ElapsedMilliseconds;
		if (!bGotConnection)
		{
			throw exLast;
		}
		return oSocket;
	}

	/// <summary>
	/// If the Session was configured to stream the request body, we need to read from the client
	/// and send it to the server here.
	/// </summary>
	/// <returns>
	/// FALSE on transfer error, TRUE otherwise.
	/// </returns>
	internal bool StreamRequestBody()
	{
		long cBytesRemaining = 0L;
		long cBytesSentToServer = 0L;
		ChunkReader oChunkReader = null;
		if (long.TryParse(m_session.oRequest["Content-Length"], NumberStyles.Integer, NumberFormatInfo.InvariantInfo, out cBytesRemaining))
		{
			cBytesRemaining -= m_session.requestBodyBytes.Length;
		}
		else if (m_session.oRequest.headers.ExistsAndContains("Transfer-Encoding", "chunked"))
		{
			oChunkReader = new ChunkReader();
			oChunkReader.pushBytes(m_session.requestBodyBytes, 0, m_session.requestBodyBytes.Length);
		}
		else
		{
			cBytesRemaining = 0L;
		}
		if (cBytesRemaining < 1 && oChunkReader == null)
		{
			return true;
		}
		bool bUpdateRequestBody = !m_session.oFlags.ContainsKey("log-drop-request-body");
		PipeReadBuffer _requestData = null;
		if (bUpdateRequestBody)
		{
			_requestData = new PipeReadBuffer(bIsRequest: true);
			_requestData.Write(m_session.requestBodyBytes, 0, m_session.requestBodyBytes.Length);
		}
		else
		{
			if (!Utilities.IsNullOrEmpty(m_session.requestBodyBytes))
			{
				cBytesSentToServer = m_session.requestBodyBytes.Length;
			}
			m_session.requestBodyBytes = Utilities.emptyByteArray;
			m_session.SetBitFlag(SessionFlags.RequestBodyDropped, b: true);
		}
		ClientPipe pipeClient = m_session.oRequest.pipeClient;
		if (pipeClient == null)
		{
			return false;
		}
		bool bAbort = false;
		bool bDone = false;
		byte[] _arrReadFromPipe = new byte[ClientChatter.s_cbClientReadBuffer];
		int cbLastReceive = 0;
		SessionTimers.NetTimestamps oNTS = SessionTimers.NetTimestamps.FromCopy(m_session.Timers.ClientReads);
		Stopwatch oSW = Stopwatch.StartNew();
		do
		{
			try
			{
				cbLastReceive = pipeClient.Receive(_arrReadFromPipe);
				oNTS.AddRead(oSW.ElapsedMilliseconds, cbLastReceive);
			}
			catch (SocketException eeX2)
			{
				bAbort = true;
				if (CONFIG.bDebugSpew)
				{
					FiddlerApplication.DebugSpew("STREAMReadRequest {0} threw #{1} - {2}", pipeClient.ToString(), eeX2.ErrorCode, eeX2.Message);
				}
				if (eeX2.SocketErrorCode == SocketError.TimedOut)
				{
					m_session.oFlags["X-ClientPipeError"] = $"STREAMReadRequest timed out; total of ?{_requestData.Length}? bytes read from client.";
					m_session.oRequest.FailSession(408, "Request Timed Out", "The client failed to send a complete request before the timeout period elapsed.");
					return false;
				}
				continue;
			}
			catch (Exception ex2)
			{
				bAbort = true;
				if (CONFIG.bDebugSpew)
				{
					FiddlerApplication.DebugSpew("STREAMReadRequest {0} threw {1}", pipeClient.ToString(), ex2.Message);
				}
				continue;
			}
			if (cbLastReceive < 1)
			{
				bDone = true;
				FiddlerApplication.DoReadRequestBuffer(m_session, _arrReadFromPipe, 0);
				if (CONFIG.bDebugSpew)
				{
					FiddlerApplication.DebugSpew("STREAMReadRequest {0} returned {1}", pipeClient.ToString(), cbLastReceive);
				}
				continue;
			}
			if (CONFIG.bDebugSpew)
			{
				FiddlerApplication.DebugSpew("STREAMREAD FROM {0}:\n{1}", pipeClient, Utilities.ByteArrayToHexView(_arrReadFromPipe, 32, cbLastReceive));
			}
			if (!FiddlerApplication.DoReadRequestBuffer(m_session, _arrReadFromPipe, cbLastReceive))
			{
				FiddlerApplication.DebugSpew("ReadRequest() aborted by OnReadRequestBuffer");
				return false;
			}
			oChunkReader?.pushBytes(_arrReadFromPipe, 0, cbLastReceive);
			if (oChunkReader != null)
			{
				if (oChunkReader.state == ChunkedTransferState.Overread)
				{
					byte[] arrExcess2 = new byte[oChunkReader.getOverage()];
					FiddlerApplication.Log.LogFormat("HTTP Pipelining Client detected; {0:N0} bytes of excess data on client socket for Session #{1}.", arrExcess2.Length, m_session.id);
					Buffer.BlockCopy(_arrReadFromPipe, cbLastReceive - arrExcess2.Length, arrExcess2, 0, arrExcess2.Length);
					cbLastReceive -= arrExcess2.Length;
				}
			}
			else if (cbLastReceive > cBytesRemaining)
			{
				byte[] arrExcess = new byte[cbLastReceive - cBytesRemaining];
				FiddlerApplication.Log.LogFormat("HTTP Pipelining Client detected; {0:N0} bytes of excess data on client socket for Session #{1}.", arrExcess.Length, m_session.id);
				Buffer.BlockCopy(_arrReadFromPipe, (int)cBytesRemaining, arrExcess, 0, arrExcess.Length);
				cbLastReceive = (int)cBytesRemaining;
			}
			if (bUpdateRequestBody)
			{
				_requestData.Write(_arrReadFromPipe, 0, cbLastReceive);
			}
			if (pipeServer != null)
			{
				try
				{
					pipeServer.Send(_arrReadFromPipe, 0, cbLastReceive);
				}
				catch (SocketException eeX)
				{
					bAbort = true;
					FiddlerApplication.Log.LogFormat("STREAMSendRequest {0} threw #{1} - {2}", pipeServer.ToString(), eeX.ErrorCode, eeX.Message);
					if (CONFIG.bDebugSpew)
					{
						FiddlerApplication.DebugSpew("STREAMSendRequest {0} threw #{1} - {2}", pipeServer.ToString(), eeX.ErrorCode, eeX.Message);
					}
					continue;
				}
				catch (Exception ex)
				{
					bAbort = true;
					FiddlerApplication.Log.LogFormat("STREAMSendRequest {0} threw {1}", pipeServer.ToString(), ex.Message);
					if (CONFIG.bDebugSpew)
					{
						FiddlerApplication.DebugSpew("STREAMSendRequest {0} threw {1}", pipeServer.ToString(), ex.Message);
					}
					continue;
				}
			}
			cBytesSentToServer += cbLastReceive;
			if (oChunkReader == null)
			{
				cBytesRemaining -= cbLastReceive;
				FiddlerApplication.DebugSpew("Streaming Session #{0} to server. Wrote {1} bytes, {2} remain...", m_session.id, cbLastReceive, cBytesRemaining);
				bDone = cBytesRemaining < 1;
			}
			else
			{
				bDone = oChunkReader.state >= ChunkedTransferState.Completed;
			}
		}
		while (!bDone && !bAbort);
		_arrReadFromPipe = null;
		oSW = null;
		m_session.Timers.ClientReads = oNTS;
		m_session.Timers.ClientDoneRequest = DateTime.Now;
		if (oChunkReader != null)
		{
			m_session["X-UnchunkedBodySize"] = oChunkReader.getEntityLength().ToString();
			if (oChunkReader.state == ChunkedTransferState.Malformed)
			{
				bAbort = true;
			}
		}
		if (bAbort)
		{
			FiddlerApplication.DebugSpew("Reading from client or writing to server set bAbort");
			return false;
		}
		if (bUpdateRequestBody)
		{
			m_session.requestBodyBytes = _requestData.ToArray();
		}
		else
		{
			m_session.oFlags["x-RequestBodyLength"] = cBytesSentToServer.ToString("N0");
		}
		return true;
	}

	/// <summary>
	/// Sends (or resends) the Request to the server or upstream proxy. If the request is a CONNECT and there's no
	/// gateway, this method ~only~ establishes the connection to the target, but does NOT send a request.
	///
	/// Note: THROWS on failures
	/// </summary>
	internal void SendRequest()
	{
		if (m_session.isFTP && !m_session.isFlagSet(SessionFlags.SentToGateway))
		{
			return;
		}
		if (pipeServer == null)
		{
			throw new InvalidOperationException("Cannot SendRequest unless pipeServer is set!");
		}
		pipeServer.IncrementUse(m_session.id);
		pipeServer.setTimeouts();
		m_session.Timers.ServerConnected = pipeServer.dtConnected;
		m_bWasForwarded = pipeServer.isConnectedToGateway;
		m_session.SetBitFlag(SessionFlags.ServerPipeReused, pipeServer.iUseCount > 1);
		m_session.SetBitFlag(SessionFlags.SentToGateway, m_bWasForwarded);
		if (pipeServer.isConnectedViaSOCKS)
		{
			m_session.SetBitFlag(SessionFlags.SentToSOCKSGateway, b: true);
		}
		if (!m_bWasForwarded && !m_session.isHTTPS)
		{
			m_session.oRequest.headers.RenameHeaderItems("Proxy-Connection", "Connection");
		}
		if (!pipeServer.isAuthenticated)
		{
			string __requestAuth = m_session.oRequest.headers["Authorization"];
			if (__requestAuth != null && __requestAuth.OICStartsWith("N"))
			{
				pipeServer.MarkAsAuthenticated(m_session.LocalProcessID);
			}
		}
		if (m_session.oFlags.ContainsKey("request-trickle-delay"))
		{
			int iDelayPerK = int.Parse(m_session.oFlags["request-trickle-delay"]);
			pipeServer.TransmitDelay = iDelayPerK;
		}
		m_session.Timers.FiddlerBeginRequest = DateTime.Now;
		if (m_bWasForwarded || !m_session.HTTPMethodIs("CONNECT"))
		{
			bool bSendFullyQualifiedUrl = m_bWasForwarded && !m_session.isHTTPS;
			byte[] arrHeaderBytes = m_session.oRequest.headers.ToByteArray(prependVerbLine: true, appendEmptyLine: true, bSendFullyQualifiedUrl, m_session.oFlags["X-OverrideHost"]);
			pipeServer.Send(arrHeaderBytes);
			if (!Utilities.IsNullOrEmpty(m_session.requestBodyBytes))
			{
				if (m_session.oFlags.ContainsKey("request-body-delay"))
				{
					int iDelayMS = int.Parse(m_session.oFlags["request-body-delay"]);
					Thread.Sleep(iDelayMS);
				}
				pipeServer.Send(m_session.requestBodyBytes);
			}
		}
		m_session.oFlags["x-EgressPort"] = pipeServer.LocalPort.ToString();
	}

	/// <summary>
	/// May request be resent on a different connection because the .Send() of the request did not complete?
	/// </summary>
	/// <returns>TRUE if the request may be resent</returns>
	internal bool _MayRetryWhenSendFailed()
	{
		return bServerSocketReused && m_session.state != SessionStates.Aborted;
	}

	/// <summary>
	/// Performs a SOCKSv4A handshake on the socket
	/// </summary>
	private Socket _SOCKSifyConnection(string sServerHostname, int iServerPort, Socket newSocket)
	{
		m_bWasForwarded = false;
		FiddlerApplication.DebugSpew("Creating SOCKS connection for {0}:{1}.", sServerHostname, iServerPort);
		byte[] arrSOCKSHandshake = _BuildSOCKS4ConnectHandshakeForTarget(sServerHostname, iServerPort);
		newSocket.Send(arrSOCKSHandshake);
		byte[] oResponse = new byte[64];
		int iReadCount = newSocket.Receive(oResponse);
		if (iReadCount > 1 && oResponse[0] == 0 && oResponse[1] == 90)
		{
			if (iReadCount > 7)
			{
				string addrDest = $"{oResponse[4]}.{oResponse[5]}.{oResponse[6]}.{oResponse[7]}";
				m_session.m_hostIP = addrDest;
				m_session.oFlags["x-hostIP"] = addrDest;
			}
			return newSocket;
		}
		try
		{
			newSocket.Close();
		}
		catch
		{
		}
		string sError = string.Empty;
		if (iReadCount <= 1 || oResponse[0] != 0)
		{
			sError = ((iReadCount <= 0) ? "Gateway returned no data." : ("Gateway returned a malformed response:\n" + Utilities.ByteArrayToHexView(oResponse, 8, iReadCount)));
		}
		else
		{
			int iError = oResponse[1];
			sError = $"Gateway returned error 0x{iError:x}";
			sError = iError switch
			{
				91 => sError + "-'request rejected or failed'", 
				92 => sError + "-'request failed because client is not running identd (or not reachable from the server)'", 
				93 => sError + "-'request failed because client's identd could not confirm the user ID string in the request'", 
				_ => sError + "-'unknown'", 
			};
		}
		throw new InvalidDataException("SOCKS gateway failed: " + sError);
	}

	/// <summary>
	/// Build the SOCKS4 outbound connection handshake as a byte array.
	/// http://en.wikipedia.org/wiki/SOCKS#SOCKS4a
	/// </summary>
	private static byte[] _BuildSOCKS4ConnectHandshakeForTarget(string sTargetHost, int iPort)
	{
		byte[] arrHostname = Encoding.ASCII.GetBytes(sTargetHost);
		byte[] arrHandshake = new byte[10 + arrHostname.Length];
		arrHandshake[0] = 4;
		arrHandshake[1] = 1;
		arrHandshake[2] = (byte)(iPort >> 8);
		arrHandshake[3] = (byte)((uint)iPort & 0xFFu);
		arrHandshake[7] = 127;
		Buffer.BlockCopy(arrHostname, 0, arrHandshake, 9, arrHostname.Length);
		return arrHandshake;
	}

	/// <summary>
	/// Replaces body with an error message
	/// </summary>
	/// <param name="sRemoteError">Error to send if client was remote</param>
	/// <param name="sTrustedError">Error to send if cilent was local</param>
	private void _ReturnFileReadError(string sRemoteError, string sTrustedError)
	{
		Initialize(bAllocatePipeReadBuffer: false);
		string sErrorBody = ((m_session.LocalProcessID <= 0 && !m_session.isFlagSet(SessionFlags.RequestGeneratedByFiddler)) ? sRemoteError : sTrustedError);
		sErrorBody = sErrorBody.PadRight(512, ' ');
		m_session.responseBodyBytes = Encoding.UTF8.GetBytes(sErrorBody);
		m_inHeaders = new HTTPResponseHeaders(CONFIG.oHeaderEncoding);
		m_inHeaders.SetStatus(404, "Not Found");
		m_inHeaders.Add("Content-Length", m_session.responseBodyBytes.Length.ToString());
		m_inHeaders.Add("Cache-Control", "max-age=0, must-revalidate");
	}

	/// <summary>
	/// The Session object will call this method if it wishes to stream a file from disk instead
	/// of loading it into memory. This method sets default headers.
	/// </summary>
	/// <param name="sFilename"></param>
	internal void GenerateHeadersForLocalFile(string sFilename)
	{
		FileInfo oFI = new FileInfo(sFilename);
		Initialize(bAllocatePipeReadBuffer: false);
		m_inHeaders = new HTTPResponseHeaders(CONFIG.oHeaderEncoding);
		m_inHeaders.SetStatus(200, "OK with automatic headers");
		m_inHeaders["Date"] = DateTime.UtcNow.ToString("r");
		m_inHeaders["Content-Length"] = oFI.Length.ToString();
		m_inHeaders["Cache-Control"] = "max-age=0, must-revalidate";
		string sContentTypeHint = Utilities.ContentTypeForFilename(sFilename);
		if (sContentTypeHint != null)
		{
			m_inHeaders["Content-Type"] = sContentTypeHint;
		}
	}

	private bool ReadResponseFromArray(byte[] arrResponse, bool bAllowBOM, string sContentTypeHint)
	{
		Initialize(bAllocatePipeReadBuffer: true);
		int iLength = arrResponse.Length;
		int iStart = 0;
		bool bHasUTF8Preamble = false;
		if (bAllowBOM)
		{
			bHasUTF8Preamble = arrResponse.Length > 3 && arrResponse[0] == 239 && arrResponse[1] == 187 && arrResponse[2] == 191;
			if (bHasUTF8Preamble)
			{
				iStart = 3;
				iLength -= 3;
			}
		}
		bool bSmellsLikeHTTP = arrResponse.Length > 5 + iStart && arrResponse[iStart] == 72 && arrResponse[iStart + 1] == 84 && arrResponse[iStart + 2] == 84 && arrResponse[iStart + 3] == 80 && arrResponse[iStart + 4] == 47;
		if (bHasUTF8Preamble && !bSmellsLikeHTTP)
		{
			iLength += 3;
			iStart = 0;
		}
		m_responseData.Capacity = iLength;
		m_responseData.Write(arrResponse, iStart, iLength);
		if (bSmellsLikeHTTP && HeadersAvailable() && ParseResponseForHeaders())
		{
			m_session.responseBodyBytes = TakeEntity();
		}
		else
		{
			Initialize(bAllocatePipeReadBuffer: false);
			m_inHeaders = new HTTPResponseHeaders(CONFIG.oHeaderEncoding);
			m_inHeaders.SetStatus(200, "OK with automatic headers");
			m_inHeaders["Date"] = DateTime.UtcNow.ToString("r");
			m_inHeaders["Content-Length"] = arrResponse.LongLength.ToString();
			m_inHeaders["Cache-Control"] = "max-age=0, must-revalidate";
			if (sContentTypeHint != null)
			{
				m_inHeaders["Content-Type"] = sContentTypeHint;
			}
			m_session.responseBodyBytes = arrResponse;
		}
		return true;
	}

	/// <summary>
	/// Loads a HTTP response from a file
	/// </summary>
	/// <param name="sFilename">The name of the file from which a response should be loaded</param>
	/// <returns>False if the file wasn't found. Throws on other errors.</returns>
	internal bool ReadResponseFromFile(string sFilename, string sOptionalContentTypeHint)
	{
		if (!File.Exists(sFilename))
		{
			_ReturnFileReadError("Fiddler - The requested file was not found.", "Fiddler - The file '" + sFilename + "' was not found.");
			return false;
		}
		byte[] arrTmp;
		try
		{
			arrTmp = File.ReadAllBytes(sFilename);
		}
		catch (Exception eX)
		{
			_ReturnFileReadError("Fiddler - The requested file could not be read.", "Fiddler - The requested file could not be read. " + FiddlerCore.Utilities.Utilities.DescribeException(eX));
			return false;
		}
		return ReadResponseFromArray(arrTmp, bAllowBOM: true, sOptionalContentTypeHint);
	}

	internal bool ReadResponseFromStream(Stream oResponse, string sContentTypeHint)
	{
		MemoryStream oMS = new MemoryStream();
		byte[] buffer = new byte[32768];
		int bytesRead = 0;
		while ((bytesRead = oResponse.Read(buffer, 0, buffer.Length)) > 0)
		{
			oMS.Write(buffer, 0, bytesRead);
		}
		byte[] arrTmp = oMS.ToArray();
		return ReadResponseFromArray(arrTmp, bAllowBOM: false, sContentTypeHint);
	}

	/// <summary>
	/// Reads the response from the ServerPipe.
	/// </summary>
	/// <returns>TRUE if a response was read</returns>
	internal bool ReadResponse()
	{
		if (pipeServer == null)
		{
			return IsWorkableFTPRequest();
		}
		int cbLastReceive = 0;
		bool bGotFIN = false;
		bool bAbort = false;
		bool bDiscardResponseBodyBytes = false;
		bool bLeakWriteFailed = false;
		byte[] _arrReadFromPipe = new byte[s_cbServerReadBuffer];
		SessionTimers.NetTimestamps oNTS = new SessionTimers.NetTimestamps();
		Stopwatch oSW = Stopwatch.StartNew();
		do
		{
			try
			{
				cbLastReceive = pipeServer.Receive(_arrReadFromPipe);
				oNTS.AddRead(oSW.ElapsedMilliseconds, cbLastReceive);
				if (m_session.Timers.ServerBeginResponse.Ticks == 0)
				{
					m_session.Timers.ServerBeginResponse = DateTime.Now;
				}
				if (cbLastReceive < 1)
				{
					bGotFIN = true;
					FiddlerApplication.DoReadResponseBuffer(m_session, _arrReadFromPipe, 0);
					if (CONFIG.bDebugSpew)
					{
						FiddlerApplication.DebugSpew("END-OF-STREAM: Read from {0}: returned {1}", pipeServer, cbLastReceive);
					}
					continue;
				}
				if (CONFIG.bDebugSpew)
				{
					FiddlerApplication.DebugSpew("READ {0:N0} FROM {1}:\n{2}", cbLastReceive, pipeServer, Utilities.ByteArrayToHexView(_arrReadFromPipe, 32, cbLastReceive));
				}
				if (!FiddlerApplication.DoReadResponseBuffer(m_session, _arrReadFromPipe, cbLastReceive))
				{
					FiddlerApplication.DebugSpew("ReadResponse() aborted by OnReadResponseBuffer");
					m_session.state = SessionStates.Aborted;
					return false;
				}
				m_responseData.Write(_arrReadFromPipe, 0, cbLastReceive);
				m_responseTotalDataCount += cbLastReceive;
				if (m_inHeaders != null)
				{
					goto IL_0423;
				}
				if (!GetHeaders())
				{
					continue;
				}
				m_session.Timers.FiddlerGotResponseHeaders = DateTime.Now;
				if (m_session.state == SessionStates.Aborted && m_session.isAnyFlagSet(SessionFlags.ProtocolViolationInResponse))
				{
					return false;
				}
				uint uiLikelySize = 0u;
				if (!m_session.HTTPMethodIs("HEAD") && m_inHeaders.TryGetEntitySize(out uiLikelySize) && uiLikelySize != 0)
				{
					uiLikelySize = (uint)(m_iEntityBodyOffset + Math.Min(CONFIG.cbAutoStreamAndForget, uiLikelySize));
					m_responseData.HintTotalSize(uiLikelySize);
				}
				FiddlerApplication.DoResponseHeadersAvailable(m_session);
				if (407 == m_inHeaders.HTTPResponseCode && (!m_session.isAnyFlagSet(SessionFlags.SentToGateway) || m_session.isHTTPS) && FiddlerApplication.Prefs.GetBoolPref("fiddler.security.ForbidServer407", bDefault: true))
				{
					m_session.SetBitFlag(SessionFlags.ProtocolViolationInResponse, b: true);
					_PoisonPipe();
					string sDetailedError = "<plaintext>\n[Fiddler] Security Warning\nA HTTP/407 response was received on a request not sent to an upstream proxy.\nThis may reflect an attempt to compromise your credentials.\nPreference 'fiddler.security.ForbidServer407' is set to true.";
					m_session.oRequest.FailSession(500, "Fiddler - Illegal Response", sDetailedError);
					return false;
				}
				_EnableStreamingIfAppropriate();
				if (uiLikelySize > CONFIG.cbAutoStreamAndForget)
				{
					m_session.oFlags["log-drop-response-body"] = "OverToolsOptionsLimit";
					m_session.bBufferResponse = false;
				}
				if (m_session.isAnyFlagSet(SessionFlags.IsRPCTunnel) && 200 == m_inHeaders.HTTPResponseCode)
				{
					m_session.bBufferResponse = true;
				}
				m_session.SetBitFlag(SessionFlags.ResponseStreamed, !m_session.bBufferResponse);
				if (!m_session.bBufferResponse)
				{
					if (m_session.oFlags.ContainsKey("response-trickle-delay"))
					{
						int iDelayPerK2 = int.Parse(m_session.oFlags["response-trickle-delay"]);
						m_session.oRequest.pipeClient.TransmitDelay = iDelayPerK2;
					}
					if (m_session.oFlags.ContainsKey("log-drop-response-body") || FiddlerApplication.Prefs.GetBoolPref("fiddler.network.streaming.ForgetStreamedData", bDefault: false))
					{
						bDiscardResponseBodyBytes = true;
					}
				}
				goto IL_0423;
				IL_0423:
				if (!bDiscardResponseBodyBytes && m_responseData.Length - m_iEntityBodyOffset > CONFIG.cbAutoStreamAndForget)
				{
					if (CONFIG.bDebugSpew)
					{
						FiddlerApplication.DebugSpew("While reading response, exceeded CONFIG.cbAutoStreamAndForget when stream reached {0:N0} bytes. Enabling streaming now", m_responseData.Length);
					}
					m_session.SetBitFlag(SessionFlags.ResponseStreamed, b: true);
					m_session.oFlags["log-drop-response-body"] = "OverToolsOptionsLimit";
					m_session.bBufferResponse = false;
					bDiscardResponseBodyBytes = true;
					if (m_session.oFlags.ContainsKey("response-trickle-delay"))
					{
						int iDelayPerK = int.Parse(m_session.oFlags["response-trickle-delay"]);
						m_session.oRequest.pipeClient.TransmitDelay = iDelayPerK;
					}
				}
				if (!m_session.isFlagSet(SessionFlags.ResponseStreamed))
				{
					continue;
				}
				if (!bLeakWriteFailed && !LeakResponseBytes())
				{
					bLeakWriteFailed = true;
				}
				if (bDiscardResponseBodyBytes)
				{
					m_session.SetBitFlag(SessionFlags.ResponseBodyDropped, b: true);
					if (m_lngLastChunkInfoOffset > -1)
					{
						ReleaseStreamedChunkedData();
					}
					else if (m_inHeaders.ExistsAndContains("Transfer-Encoding", "chunked"))
					{
						ReleaseStreamedChunkedData();
					}
					else
					{
						ReleaseStreamedData();
					}
				}
			}
			catch (SocketException eXS)
			{
				bAbort = true;
				if (CONFIG.bDebugSpew)
				{
					FiddlerApplication.DebugSpew("ReadResponse() failure {0}", FiddlerCore.Utilities.Utilities.DescribeException(eXS));
				}
				if (eXS.SocketErrorCode == SocketError.TimedOut)
				{
					m_session.oFlags["X-ServerPipeError"] = "Timed out while reading response.";
					continue;
				}
				FiddlerApplication.Log.LogFormat("fiddler.network.readresponse.failure> Session #{0} raised exception {1}", m_session.id, FiddlerCore.Utilities.Utilities.DescribeException(eXS));
			}
			catch (Exception eX)
			{
				bAbort = true;
				if (CONFIG.bDebugSpew)
				{
					FiddlerApplication.DebugSpew("ReadResponse() failure {0}\n{1}", FiddlerCore.Utilities.Utilities.DescribeException(eX), Utilities.ByteArrayToHexView(m_responseData.ToArray(), 32));
				}
				if (eX is OperationCanceledException)
				{
					m_session.state = SessionStates.Aborted;
					FiddlerApplication.Log.LogFormat("fiddler.network.readresponse.failure> Session #{0} was aborted {1}", m_session.id, FiddlerCore.Utilities.Utilities.DescribeException(eX));
				}
				else if (eX is OutOfMemoryException)
				{
					FiddlerApplication.Log.LogString(eX.ToString());
					m_session.state = SessionStates.Aborted;
					FiddlerApplication.Log.LogFormat("fiddler.network.readresponse.failure> Session #{0} Out of Memory", m_session.id);
				}
				else
				{
					FiddlerApplication.Log.LogFormat("fiddler.network.readresponse.failure> Session #{0} raised exception {1}", m_session.id, FiddlerCore.Utilities.Utilities.DescribeException(eX));
				}
			}
		}
		while (!bGotFIN && !bAbort && (m_inHeaders == null || !isResponseBodyComplete()));
		m_session.Timers.ServerDoneResponse = DateTime.Now;
		if (m_session.isFlagSet(SessionFlags.ResponseStreamed))
		{
			m_session.Timers.ClientDoneResponse = m_session.Timers.ServerDoneResponse;
		}
		_arrReadFromPipe = null;
		oSW = null;
		m_session.Timers.ServerReads = oNTS;
		FiddlerApplication.DebugSpew("Finished reading server response: {0:N0} bytes.", m_responseTotalDataCount);
		if (m_responseTotalDataCount == 0L && m_inHeaders == null)
		{
			bAbort = true;
		}
		if (bAbort)
		{
			if (m_bLeakedHeaders)
			{
				FiddlerApplication.DebugSpew("*** Aborted on a Response  #{0} which had partially streamed ****", m_session.id);
			}
			FiddlerApplication.DebugSpew("*** Abort on Read from Server for Session #{0} ****", m_session.id);
			return false;
		}
		if (m_inHeaders == null)
		{
			FiddlerApplication.HandleHTTPError(m_session, SessionFlags.ProtocolViolationInResponse, bPoisonClientConnection: true, bPoisonServerConnection: true, "The Server did not return properly-formatted HTTP Headers. Maybe missing altogether (e.g. HTTP/0.9), maybe only \\r\\r instead of \\r\\n\\r\\n?\n");
			m_session.SetBitFlag(SessionFlags.ResponseStreamed, b: false);
			m_inHeaders = new HTTPResponseHeaders(CONFIG.oHeaderEncoding);
			m_inHeaders.HTTPVersion = "HTTP/1.0";
			m_inHeaders.SetStatus(200, "This buggy server did not return headers");
			m_iEntityBodyOffset = 0;
			return true;
		}
		if (bGotFIN)
		{
			FiddlerApplication.DebugSpew("Got FIN reading Response to #{0}.", m_session.id);
			_PoisonPipe();
			if (m_inHeaders.ExistsAndEquals("Transfer-Encoding", "chunked"))
			{
				FiddlerApplication.DebugSpew("^ Previous FIN unexpected; chunked body ended abnormally for #{0}.", m_session.id);
				FiddlerApplication.HandleHTTPError(m_session, SessionFlags.ProtocolViolationInResponse, bPoisonClientConnection: true, bPoisonServerConnection: true, "Transfer-Encoding: Chunked response did not terminate with a proper zero-size chunk.");
			}
		}
		if (bDiscardResponseBodyBytes)
		{
			m_session["x-ResponseBodyTransferLength"] = m_responseTotalDataCount.ToString("N0");
		}
		return true;
	}

	/// <summary>
	/// When the headers first arrive, update bBufferResponse based on their contents.
	/// </summary>
	private void _EnableStreamingIfAppropriate()
	{
		string sContentType = m_inHeaders["Content-Type"];
		if (sContentType.OICStartsWithAny("text/event-stream", "multipart/x-mixed-replace") && FiddlerApplication.Prefs.GetBoolPref("fiddler.network.streaming.AutoStreamByMIME", bDefault: true))
		{
			m_session.bBufferResponse = false;
		}
		else if (CONFIG.StreamAudioVideo && sContentType.OICStartsWithAny("video/", "audio/", "application/x-mms-framed"))
		{
			m_session.bBufferResponse = false;
		}
		if (!m_session.bBufferResponse)
		{
			if (m_session.HTTPMethodIs("CONNECT"))
			{
				m_session.bBufferResponse = true;
			}
			else if (101 == m_inHeaders.HTTPResponseCode)
			{
				m_session.bBufferResponse = true;
			}
			else if (m_session.oRequest.pipeClient == null)
			{
				m_session.bBufferResponse = true;
			}
			else if ((401 == m_inHeaders.HTTPResponseCode || 407 == m_inHeaders.HTTPResponseCode) && m_session.oFlags.ContainsKey("x-AutoAuth"))
			{
				m_session.bBufferResponse = true;
			}
		}
	}

	/// <summary>
	/// Detects whether this is an direct FTP request and if so executes it and returns true.
	/// </summary>
	/// <returns>FALSE if the request wasn't FTP or wasn't direct.</returns>
	private bool IsWorkableFTPRequest()
	{
		if (m_session.isFTP && !m_session.isFlagSet(SessionFlags.SentToGateway))
		{
			try
			{
				FTPGateway.MakeFTPRequest(m_session, m_responseData, out m_inHeaders);
				return true;
			}
			catch (Exception eX)
			{
				m_session.oFlags["X-ServerPipeError"] = FiddlerCore.Utilities.Utilities.DescribeException(eX);
				FiddlerApplication.Log.LogFormat("fiddler.network.readresponse.failure> FTPSession #{0} raised exception: {1}", m_session.id, FiddlerCore.Utilities.Utilities.DescribeException(eX));
				return false;
			}
		}
		return false;
	}

	/// <summary>
	/// Remove from memory the response data that we have already returned to the client.
	/// </summary>
	private void ReleaseStreamedData()
	{
		m_responseData = new PipeReadBuffer(bIsRequest: false);
		m_lngLeakedOffset = 0L;
		if (m_iEntityBodyOffset > 0)
		{
			m_responseTotalDataCount -= m_iEntityBodyOffset;
			m_iEntityBodyOffset = 0;
		}
	}

	/// <summary>
	/// Remove from memory the response data that we have already returned to the client, up to the last chunk
	/// size indicator, which we need to keep around for chunk-integrity purposes.
	/// </summary>
	private void ReleaseStreamedChunkedData()
	{
		if (m_iEntityBodyOffset > m_lngLastChunkInfoOffset)
		{
			m_lngLastChunkInfoOffset = m_iEntityBodyOffset;
		}
		Utilities.IsChunkedBodyComplete(m_session, m_responseData, m_lngLastChunkInfoOffset, out m_lngLastChunkInfoOffset, out var _);
		int iBytesLeakedAlreadyButSavedForChunkIntegrity = (int)(m_responseData.Length - m_lngLastChunkInfoOffset);
		PipeReadBuffer newMS = new PipeReadBuffer(iBytesLeakedAlreadyButSavedForChunkIntegrity);
		newMS.Write(m_responseData.GetBuffer(), (int)m_lngLastChunkInfoOffset, iBytesLeakedAlreadyButSavedForChunkIntegrity);
		m_responseData = newMS;
		m_lngLeakedOffset = iBytesLeakedAlreadyButSavedForChunkIntegrity;
		m_lngLastChunkInfoOffset = 0L;
		m_iEntityBodyOffset = 0;
	}

	/// <summary>
	/// Leak the current bytes of the response to client. We wait for the full header
	/// set before starting to stream for a variety of impossible-to-change reasons.
	/// </summary>
	/// <returns>Returns TRUE if response bytes were leaked, false otherwise (e.g. write error). THROWS if "fiddler.network.streaming.abortifclientaborts" is TRUE</returns>
	private bool LeakResponseBytes()
	{
		try
		{
			if (m_session.oRequest.pipeClient == null)
			{
				return false;
			}
			if (!m_bLeakedHeaders)
			{
				if ((401 == m_inHeaders.HTTPResponseCode && m_inHeaders["WWW-Authenticate"].OICStartsWith("N")) || (407 == m_inHeaders.HTTPResponseCode && m_inHeaders["Proxy-Authenticate"].OICStartsWith("N")))
				{
					m_inHeaders["Proxy-Support"] = "Session-Based-Authentication";
				}
				m_session.Timers.ClientBeginResponse = DateTime.Now;
				m_bLeakedHeaders = true;
				m_session.oRequest.pipeClient.Send(m_inHeaders.ToByteArray(prependStatusLine: true, appendEmptyLine: true));
				m_lngLeakedOffset = m_iEntityBodyOffset;
			}
			m_session.oRequest.pipeClient.Send(m_responseData.GetBuffer(), (int)m_lngLeakedOffset, (int)(m_responseData.Length - m_lngLeakedOffset));
			m_lngLeakedOffset = m_responseData.Length;
			return true;
		}
		catch (Exception eXInner)
		{
			m_session.PoisonClientPipe();
			FiddlerApplication.Log.LogFormat("fiddler.network.streaming> Streaming of response #{0} to client failed: {1}. Leaking aborted.", m_session.id, eXInner.Message);
			if (FiddlerApplication.Prefs.GetBoolPref("fiddler.network.streaming.abortifclientaborts", bDefault: false))
			{
				throw new OperationCanceledException("Leaking response to client failed", eXInner);
			}
			return false;
		}
	}

	/// <summary>
	/// Mark this connection as non-reusable
	/// </summary>
	internal void _PoisonPipe()
	{
		if (pipeServer != null)
		{
			pipeServer.ReusePolicy = PipeReusePolicy.NoReuse;
		}
	}
}
