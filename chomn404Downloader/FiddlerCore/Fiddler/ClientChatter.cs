using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net.Sockets;
using System.Text;
using FiddlerCore.Utilities;

namespace Fiddler;

/// <summary>
/// The ClientChatter object, exposed as the oRequest object on the Session object, represents a single web request.
/// </summary>
public class ClientChatter
{
	/// <summary>
	/// Discardable State of Read Operation
	///
	/// While it is reading a request from the client, the ClientChatter class uses a RequestReaderState object to track
	/// the state of the read. This state is discarded when the request has been completely read.
	/// </summary>
	private class RequestReaderState : IDisposable
	{
		/// <summary>
		/// The Host pulled from the URI
		/// </summary>
		internal string m_sHostFromURI;

		/// <summary>
		/// Buffer holds this request's data as it is read from the pipe.
		/// </summary>
		internal PipeReadBuffer m_requestData;

		/// <summary>
		/// Offset to first byte of body in m_requestData
		/// </summary>
		internal int iEntityBodyOffset;

		/// <summary>
		/// Optimization: Offset of most recent transfer-encoded chunk
		/// </summary>
		internal long m_lngLastChunkInfoOffset;

		/// <summary>
		/// Optimization: tracks how far we've previously looked when determining iEntityBodyOffset
		/// </summary>
		internal int iBodySeekProgress;

		/// <summary>
		/// Did the request specify Transfer-Encoding: chunked
		/// </summary>
		internal bool bIsChunkedBody;

		/// <summary>
		/// The integer value of the Content-Length header, if any
		/// </summary>
		internal long iContentLength = 0L;

		internal RequestReaderState()
		{
			m_requestData = new PipeReadBuffer(bIsRequest: true);
		}

		/// <summary>
		/// Count of body bytes read from the client. If no body bytes have yet been read, returns count of header bytes.
		/// </summary>
		/// <returns></returns>
		internal long GetBodyBytesRead()
		{
			PipeReadBuffer prb = m_requestData;
			if (prb == null)
			{
				return 0L;
			}
			long iBytesRead = prb.Length;
			if (iBytesRead > iEntityBodyOffset)
			{
				return iBytesRead - iEntityBodyOffset;
			}
			return iBytesRead;
		}

		/// <summary>
		/// Scans requestData stream for the \r\n\r\n (or variants) sequence
		/// which indicates that the header block is complete.
		///
		/// SIDE EFFECTS:
		///             		iBodySeekProgress is updated and maintained across calls to this function
		///             		iEntityBodyOffset is updated if the end of headers is found
		/// </summary>
		/// <returns>True, if requestData contains a full set of headers</returns>
		internal bool _areHeadersAvailable(Session oS)
		{
			if (m_requestData.Length < 16)
			{
				return false;
			}
			long lngDataLen = m_requestData.Length;
			byte[] arrData = m_requestData.GetBuffer();
			if (Parser.FindEndOfHeaders(arrData, ref iBodySeekProgress, lngDataLen, out var oHPW))
			{
				iEntityBodyOffset = iBodySeekProgress + 1;
				switch (oHPW)
				{
				case HTTPHeaderParseWarnings.EndedWithLFLF:
					FiddlerApplication.HandleHTTPError(oS, SessionFlags.ProtocolViolationInRequest, bPoisonClientConnection: false, bPoisonServerConnection: false, "The Client did not send properly formatted HTTP Headers. HTTP headers\nshould be terminated with CRLFCRLF. These were terminated with LFLF.");
					break;
				case HTTPHeaderParseWarnings.EndedWithLFCRLF:
					FiddlerApplication.HandleHTTPError(oS, SessionFlags.ProtocolViolationInRequest, bPoisonClientConnection: false, bPoisonServerConnection: false, "The Client did not send properly formatted HTTP Headers. HTTP headers\nshould be terminated with CRLFCRLF. These were terminated with LFCRLF.");
					break;
				}
				return true;
			}
			return false;
		}

		public void Dispose()
		{
			if (m_requestData != null)
			{
				m_requestData.Dispose();
				m_requestData = null;
			}
		}
	}

	/// <summary>
	/// Size of buffer passed to pipe.Receive when reading from the client. 
	/// </summary>
	internal static int s_cbClientReadBuffer = 8192;

	internal static int s_SO_SNDBUF_Option = -1;

	internal static int s_SO_RCVBUF_Option = -1;

	/// <summary>
	/// Tracks the progress of reading the request from the client. Because of the multi-threaded nature 
	/// of some users of this field, most will make a local copy before accessing its members.
	/// </summary>
	private RequestReaderState stateRead;

	/// <summary>
	/// The ClientPipe object which is connected to the client, or null.
	/// </summary>
	public ClientPipe pipeClient;

	/// <summary>
	/// Parsed Headers
	/// </summary>
	private HTTPRequestHeaders m_headers;

	/// <summary>
	/// The Session object which owns this ClientChatter
	/// </summary>
	private Session m_session;

	/// <summary>
	/// Returns the port on which Fiddler read the request (typically 8888)
	/// </summary>
	[CodeDescription("Returns the port on which Fiddler read the request (typically 8888). Only available while the request is alive.")]
	public int InboundPort
	{
		get
		{
			try
			{
				if (pipeClient != null)
				{
					return pipeClient.LocalPort;
				}
			}
			catch
			{
			}
			return 0;
		}
	}

	/// <summary>
	/// Count of body bytes read from the client. If no body bytes have yet been read, returns count of header bytes.
	/// </summary>
	internal long _PeekUploadProgress => stateRead?.GetBodyBytesRead() ?? (-1);

	/// <summary>
	/// HTTP Headers sent in the client request, or null.
	/// </summary>
	public HTTPRequestHeaders headers
	{
		get
		{
			return m_headers;
		}
		set
		{
			m_headers = value;
		}
	}

	/// <summary>
	/// Was this request received from a reused client connection? Looks at SessionFlags.ClientPipeReused flag on owning Session.
	/// </summary>
	public bool bClientSocketReused => m_session.isFlagSet(SessionFlags.ClientPipeReused);

	/// <summary>
	/// Note: This returns the request's HOST header, which may include a trailing port #.
	/// If the Host is an IPv6 literal, it will be enclosed in brackets '[' and ']'
	/// </summary>
	public string host
	{
		get
		{
			if (m_headers != null)
			{
				return m_headers["Host"];
			}
			return string.Empty;
		}
		internal set
		{
			if (m_headers != null)
			{
				if (value == null)
				{
					value = string.Empty;
				}
				if (value.EndsWith(":80") && "HTTP".OICEquals(m_headers.UriScheme))
				{
					value = value.Substring(0, value.Length - 3);
				}
				m_headers["Host"] = value;
				if ("CONNECT".OICEquals(m_headers.HTTPMethod))
				{
					m_headers.RequestPath = value;
				}
			}
		}
	}

	/// <summary>
	/// Controls whether the request body is streamed to the server as it is read from the client.
	/// </summary>
	[CodeDescription("Controls whether the request body is streamed to the server as it is read from the client.")]
	public bool BufferRequest
	{
		get
		{
			return m_session.isFlagSet(SessionFlags.RequestStreamed);
		}
		set
		{
			if (m_session.state > SessionStates.ReadingRequest)
			{
				throw new InvalidOperationException("Too late. BufferRequest may only be set before or while ReadingRequest.");
			}
			m_session.SetBitFlag(SessionFlags.RequestStreamed, !value);
		}
	}

	/// <summary>
	/// Simple indexer into the Request Headers object
	/// </summary>
	public string this[string sHeader]
	{
		get
		{
			if (m_headers == null)
			{
				return string.Empty;
			}
			return m_headers[sHeader];
		}
		set
		{
			if (m_headers == null)
			{
				throw new InvalidDataException("Request Headers object does not exist");
			}
			m_headers[sHeader] = value;
		}
	}

	internal ClientChatter(Session oSession)
	{
		m_session = oSession;
	}

	/// <summary>
	/// Create a ClientChatter object initialized with a set of HTTP headers
	/// Called primarily when loading session data from a file.
	/// </summary>
	/// <param name="oSession">The Session object which will own this request</param>
	/// <param name="sData">The string containing the request data</param>
	internal ClientChatter(Session oSession, string sData)
	{
		m_session = oSession;
		headers = Parser.ParseRequest(sData);
		if (headers != null)
		{
			if ("CONNECT" == m_headers.HTTPMethod)
			{
				m_session.isTunnel = true;
			}
		}
		else
		{
			headers = new HTTPRequestHeaders("/MALFORMED", new string[1] { "Fiddler: Malformed header string" });
		}
	}

	/// <summary>
	/// Loads a HTTP request body from a file rather than a memory stream.
	/// </summary>
	/// <param name="sFilename">The file to load</param>
	/// <returns>TRUE if the file existed. THROWS on most errors other than File-Not-Found</returns>
	internal bool ReadRequestBodyFromFile(string sFilename)
	{
		if (!File.Exists(sFilename))
		{
			m_session.utilSetRequestBody("File not found: " + sFilename);
			return false;
		}
		m_session.RequestBody = File.ReadAllBytes(sFilename);
		return true;
	}

	/// <summary>
	/// Based on this session's data, determine the expected Transfer-Size of the request body. See RFC2616 Section 4.4 Message Length.
	/// Note, there's currently no support for "multipart/byteranges" requests anywhere in Fiddler.
	/// </summary>
	/// <returns>Expected Transfer-Size of the body, in bytes.</returns>
	private long _calculateExpectedEntityTransferSize()
	{
		if (m_headers == null)
		{
			throw new InvalidDataException("HTTP Request did not contain headers");
		}
		long cbExpected = 0L;
		if (m_headers.ExistsAndEquals("Transfer-Encoding", "chunked"))
		{
			if (m_session.isAnyFlagSet(SessionFlags.RequestStreamed | SessionFlags.IsRPCTunnel))
			{
				return stateRead.m_requestData.Length - stateRead.iEntityBodyOffset;
			}
			RequestReaderState _rrs = stateRead;
			if (_rrs.iEntityBodyOffset >= _rrs.m_requestData.Length)
			{
				throw new InvalidDataException("Bad request: Chunked Body was missing entirely.");
			}
			if (!Utilities.IsChunkedBodyComplete(m_session, _rrs.m_requestData, _rrs.iEntityBodyOffset, out var _, out var lngEndOfEntity))
			{
				throw new InvalidDataException("Bad request: Chunked Body was incomplete.");
			}
			if (lngEndOfEntity < _rrs.iEntityBodyOffset)
			{
				throw new InvalidDataException("Bad request: Chunked Body was malformed. Entity ends before it starts!");
			}
			return lngEndOfEntity - _rrs.iEntityBodyOffset;
		}
		if (!long.TryParse(m_headers["Content-Length"], NumberStyles.Integer, NumberFormatInfo.InvariantInfo, out cbExpected) || cbExpected < 0)
		{
			return 0L;
		}
		return cbExpected;
	}

	/// <summary>
	/// Free Request data. Called by TakeEntity or by ReadRequest method on request failure
	/// </summary>
	private void _freeRequestData()
	{
		RequestReaderState _rrs = stateRead;
		stateRead = null;
		_rrs?.Dispose();
	}

	/// <summary>
	/// Extract byte array representing the entity, put any excess bytes back in the pipe, free the RequestReadState, and 
	/// return the entity.
	/// </summary>
	/// <returns>Byte array containing the entity body</returns>
	internal byte[] TakeEntity()
	{
		if (stateRead == null)
		{
			return Utilities.emptyByteArray;
		}
		if (stateRead.m_requestData.Length < 1)
		{
			_freeRequestData();
			return Utilities.emptyByteArray;
		}
		long cbAvailableEntityData = stateRead.m_requestData.Length - stateRead.iEntityBodyOffset;
		long cbExpectedEntitySize = _calculateExpectedEntityTransferSize();
		if (cbAvailableEntityData != cbExpectedEntitySize)
		{
			if (cbAvailableEntityData > cbExpectedEntitySize)
			{
				try
				{
					byte[] arrExcess = new byte[cbAvailableEntityData - cbExpectedEntitySize];
					FiddlerApplication.Log.LogFormat("HTTP Pipelining Client detected; {0:N0} bytes of excess data on client socket for Session #{1}.", arrExcess.Length, m_session.id);
					Buffer.BlockCopy(stateRead.m_requestData.GetBuffer(), stateRead.iEntityBodyOffset + (int)cbExpectedEntitySize, arrExcess, 0, arrExcess.Length);
					pipeClient.putBackSomeBytes(arrExcess);
				}
				catch (OutOfMemoryException oOOM2)
				{
					m_session.PoisonClientPipe();
					FiddlerApplication.Log.LogFormat("HTTP Request Pipelined data too large to store. Abandoning it" + FiddlerCore.Utilities.Utilities.DescribeException(oOOM2));
				}
				cbAvailableEntityData = cbExpectedEntitySize;
			}
			else if (!m_session.isAnyFlagSet(SessionFlags.RequestStreamed | SessionFlags.IsRPCTunnel))
			{
				FiddlerApplication.HandleHTTPError(m_session, SessionFlags.ProtocolViolationInRequest, bPoisonClientConnection: true, bPoisonServerConnection: true, $"Content-Length mismatch: Request Header indicated {cbExpectedEntitySize:N0} bytes, but client sent {cbAvailableEntityData:N0} bytes.");
				if (!m_session.isAnyFlagSet(SessionFlags.RequestGeneratedByFiddler))
				{
					if (FiddlerApplication.Prefs.GetBoolPref("fiddler.network.RejectIncompleteRequests", bDefault: true))
					{
						FailSession(408, "Request body incomplete", $"The request body did not contain the specified number of bytes. Got {cbAvailableEntityData:N0}, expected {cbExpectedEntitySize:N0}");
						throw new InvalidDataException($"The request body did not contain the specified number of bytes. Got {cbAvailableEntityData:N0}, expected {cbExpectedEntitySize:N0}");
					}
					if (FiddlerApplication.Prefs.GetBoolPref("fiddler.network.FixRequestContentLength", bDefault: true))
					{
						m_headers.RenameHeaderItems("Content-Length", "Original-Content-Length");
						m_headers["Content-Length"] = cbAvailableEntityData.ToString();
					}
				}
			}
		}
		byte[] arrResult;
		try
		{
			arrResult = new byte[cbAvailableEntityData];
			Buffer.BlockCopy(stateRead.m_requestData.GetBuffer(), stateRead.iEntityBodyOffset, arrResult, 0, arrResult.Length);
		}
		catch (OutOfMemoryException oOOM)
		{
			string title = "HTTP Request Too Large";
			FiddlerApplication.Log.LogFormat("{0}: {1}", title, oOOM.ToString());
			arrResult = Encoding.ASCII.GetBytes("Fiddler: Out of memory");
			m_session.PoisonClientPipe();
		}
		_freeRequestData();
		return arrResult;
	}

	/// <summary>
	/// Send a HTTP/XXX Error Message to the Client, calling FiddlerApplication.BeforeReturningError and DoReturningError in FiddlerScript.
	/// Note: This method does not poison the Server pipe, so if poisoning is desired, it's the caller's responsibility to do that.
	/// Note: Because this method uses Connection: close on the returned response, it has the effect of poisoning the client pipe
	/// </summary>
	/// <param name="iError">Response code</param>
	/// <param name="sErrorStatusText">Response status text</param>
	/// <param name="sErrorBody">Body of the HTTP Response</param>
	public void FailSession(int iError, string sErrorStatusText, string sErrorBody)
	{
		m_session.EnsureID();
		m_session.oFlags["X-FailSession-When"] = m_session.state.ToString();
		BuildAndReturnResponse(iError, sErrorStatusText, sErrorBody, null);
	}

	/// <summary>
	/// Return a HTTP response and signal that the client should close the connection
	/// </summary>
	/// <param name="delLastChance">A Delegate that fires to give one final chance to modify the Session before
	/// calling the DoBeforeReturningError and returning the response</param>
	internal void BuildAndReturnResponse(int iStatus, string sStatusText, string sBodyText, Action<Session> delLastChance)
	{
		m_session.SetBitFlag(SessionFlags.ResponseGeneratedByFiddler, b: true);
		if (iStatus >= 400 && sBodyText.Length < 512)
		{
			sBodyText = sBodyText.PadRight(512, ' ');
		}
		m_session.responseBodyBytes = Encoding.UTF8.GetBytes(sBodyText);
		m_session.oResponse.headers = new HTTPResponseHeaders(CONFIG.oHeaderEncoding);
		m_session.oResponse.headers.SetStatus(iStatus, sStatusText);
		m_session.oResponse.headers.Add("Date", DateTime.UtcNow.ToString("r"));
		m_session.oResponse.headers.Add("Content-Type", "text/html; charset=UTF-8");
		m_session.oResponse.headers.Add("Connection", "close");
		m_session.oResponse.headers.Add("Cache-Control", "no-cache, must-revalidate");
		m_session.oResponse.headers.Add("Timestamp", DateTime.Now.ToString("HH:mm:ss.fff"));
		m_session.state = SessionStates.Aborted;
		delLastChance?.Invoke(m_session);
		FiddlerApplication.DoBeforeReturningError(m_session);
		m_session.ReturnResponse(bForceClientServerPipeAffinity: false);
	}

	/// <summary>
	/// Parse the headers from the requestData buffer.  
	/// Precondition: Call AFTER having set the correct iEntityBodyOffset.
	///
	/// Note: This code used to be a lot simpler before, when it used strings instead of byte[]s. Sadly,
	/// we've gotta use byte[]s to ensure nothing in the URI gets lost.
	/// </summary>
	/// <returns>TRUE if successful.</returns>
	private bool _ParseRequestForHeaders()
	{
		if (stateRead.m_requestData == null || stateRead.iEntityBodyOffset < 4)
		{
			return false;
		}
		m_headers = new HTTPRequestHeaders(CONFIG.oHeaderEncoding);
		byte[] arrRequest = stateRead.m_requestData.GetBuffer();
		Parser.CrackRequestLine(arrRequest, out var ixURIOffset, out var iURILen, out var ixHeaderNVPOffset, out var sOtherErrors);
		if (ixURIOffset < 1 || iURILen < 1)
		{
			FiddlerApplication.HandleHTTPError(m_session, SessionFlags.ProtocolViolationInRequest, bPoisonClientConnection: true, bPoisonServerConnection: false, "Incorrectly formed Request-Line");
			FiddlerApplication.Log.LogFormat("!CrackRequestLine couldn't find URI.\n{0}\n", Utilities.ByteArrayToHexView(arrRequest, 16, 256, bShowASCII: true));
			return false;
		}
		if (!string.IsNullOrEmpty(sOtherErrors))
		{
			FiddlerApplication.HandleHTTPError(m_session, SessionFlags.ProtocolViolationInRequest, bPoisonClientConnection: true, bPoisonServerConnection: false, sOtherErrors);
			FiddlerApplication.Log.LogFormat("!CrackRequestLine returned '{0}'.\n{1}\n", sOtherErrors, Utilities.ByteArrayToHexView(arrRequest, 16, 256, bShowASCII: true));
		}
		string sMethod = Encoding.ASCII.GetString(arrRequest, 0, ixURIOffset - 1);
		m_headers.HTTPMethod = sMethod.ToUpperInvariant();
		if (sMethod != m_headers.HTTPMethod)
		{
			FiddlerApplication.HandleHTTPError(m_session, SessionFlags.ProtocolViolationInRequest, bPoisonClientConnection: false, bPoisonServerConnection: false, $"Per RFC2616, HTTP Methods are case-sensitive. Client sent '{sMethod}', expected '{m_headers.HTTPMethod}'.");
		}
		m_headers.HTTPVersion = Encoding.ASCII.GetString(arrRequest, ixURIOffset + iURILen + 1, ixHeaderNVPOffset - iURILen - ixURIOffset - 2).Trim().ToUpperInvariant();
		int ixSlashPrecedingHost = 0;
		if (arrRequest[ixURIOffset] != 47)
		{
			if (iURILen > 7 && arrRequest[ixURIOffset + 4] == 58 && arrRequest[ixURIOffset + 5] == 47 && arrRequest[ixURIOffset + 6] == 47)
			{
				m_headers.UriScheme = Encoding.ASCII.GetString(arrRequest, ixURIOffset, 4);
				ixSlashPrecedingHost = ixURIOffset + 6;
				ixURIOffset += 7;
				iURILen -= 7;
			}
			else if (iURILen > 8 && arrRequest[ixURIOffset + 5] == 58 && arrRequest[ixURIOffset + 6] == 47 && arrRequest[ixURIOffset + 7] == 47)
			{
				m_headers.UriScheme = Encoding.ASCII.GetString(arrRequest, ixURIOffset, 5);
				ixSlashPrecedingHost = ixURIOffset + 7;
				ixURIOffset += 8;
				iURILen -= 8;
			}
			else if (iURILen > 6 && arrRequest[ixURIOffset + 3] == 58 && arrRequest[ixURIOffset + 4] == 47 && arrRequest[ixURIOffset + 5] == 47)
			{
				m_headers.UriScheme = Encoding.ASCII.GetString(arrRequest, ixURIOffset, 3);
				ixSlashPrecedingHost = ixURIOffset + 5;
				ixURIOffset += 6;
				iURILen -= 6;
			}
		}
		if (ixSlashPrecedingHost == 0)
		{
			if (pipeClient != null && pipeClient.bIsSecured)
			{
				m_headers.UriScheme = "https";
			}
			else
			{
				m_headers.UriScheme = "http";
			}
		}
		if (ixSlashPrecedingHost > 0)
		{
			if (iURILen == 0)
			{
				FiddlerApplication.HandleHTTPError(m_session, SessionFlags.ProtocolViolationInRequest, bPoisonClientConnection: true, bPoisonServerConnection: false, "Incorrectly formed Request-Line. Request-URI component was missing.\r\n\r\n" + Encoding.ASCII.GetString(arrRequest, 0, ixHeaderNVPOffset));
				return false;
			}
			while (iURILen > 0 && arrRequest[ixURIOffset] != 47 && arrRequest[ixURIOffset] != 63)
			{
				ixURIOffset++;
				iURILen--;
			}
			int ixStartHost = ixSlashPrecedingHost + 1;
			int iHostLen = ixURIOffset - ixStartHost;
			if (iHostLen > 0)
			{
				stateRead.m_sHostFromURI = CONFIG.oHeaderEncoding.GetString(arrRequest, ixStartHost, iHostLen);
				if (m_headers.UriScheme == "ftp" && stateRead.m_sHostFromURI.Contains("@"))
				{
					int ixHostOffset = stateRead.m_sHostFromURI.LastIndexOf("@") + 1;
					m_headers.UriUserInfo = stateRead.m_sHostFromURI.Substring(0, ixHostOffset);
					stateRead.m_sHostFromURI = stateRead.m_sHostFromURI.Substring(ixHostOffset);
				}
			}
		}
		byte[] rawURI = new byte[iURILen];
		Buffer.BlockCopy(arrRequest, ixURIOffset, rawURI, 0, iURILen);
		m_headers.RawPath = rawURI;
		if (string.IsNullOrEmpty(m_headers.RequestPath))
		{
			FiddlerApplication.HandleHTTPError(m_session, SessionFlags.ProtocolViolationInRequest, bPoisonClientConnection: false, bPoisonServerConnection: false, "Incorrectly formed Request-Line. abs_path was empty (e.g. missing /). RFC2616 Section 5.1.2");
		}
		string sHeaders = CONFIG.oHeaderEncoding.GetString(arrRequest, ixHeaderNVPOffset, stateRead.iEntityBodyOffset - ixHeaderNVPOffset).Trim();
		arrRequest = null;
		if (sHeaders.Length >= 1)
		{
			string[] arrLines = sHeaders.Replace("\r\n", "\n").Split(new char[1] { '\n' });
			string sErrs = string.Empty;
			if (!Parser.ParseNVPHeaders(m_headers, arrLines, 0, ref sErrs))
			{
				FiddlerApplication.HandleHTTPError(m_session, SessionFlags.ProtocolViolationInRequest, bPoisonClientConnection: true, bPoisonServerConnection: false, "Incorrectly formed request headers.\n" + sErrs);
			}
		}
		if (m_headers.Exists("Content-Length") && m_headers.ExistsAndContains("Transfer-Encoding", "chunked"))
		{
			FiddlerApplication.HandleHTTPError(m_session, SessionFlags.ProtocolViolationInRequest, bPoisonClientConnection: false, bPoisonServerConnection: false, "Content-Length request header MUST NOT be present when Transfer-Encoding is used (RFC2616 Section 4.4)");
		}
		return true;
	}

	/// <summary>
	/// This function decides if the request string represents a complete HTTP request
	/// </summary>
	/// <returns></returns>
	private bool _isRequestComplete()
	{
		if (m_headers == null)
		{
			if (!stateRead._areHeadersAvailable(m_session))
			{
				if (stateRead.m_requestData.Length > ClientPipe._cbLimitRequestHeaders)
				{
					m_headers = new HTTPRequestHeaders();
					m_headers.HTTPMethod = "BAD";
					m_headers["Host"] = "BAD-REQUEST";
					m_headers.RequestPath = "/REQUEST_TOO_LONG";
					FailSession(414, "Fiddler - Request Too Long", "[Fiddler] Request Header parsing failed. Headers not found in the first " + stateRead.m_requestData.Length + " bytes.");
					return true;
				}
				return false;
			}
			if (!_ParseRequestForHeaders())
			{
				string sDetailedError = ((stateRead.m_requestData == null) ? "{Fiddler:no data}" : Utilities.ByteArrayToHexView(stateRead.m_requestData.GetBuffer(), 24, (int)Math.Min(stateRead.m_requestData.Length, 2048L)));
				if (m_headers == null)
				{
					m_headers = new HTTPRequestHeaders();
					m_headers.HTTPMethod = "BAD";
					m_headers["Host"] = "BAD-REQUEST";
					m_headers.RequestPath = "/BAD_REQUEST";
				}
				FailSession(400, "Fiddler - Bad Request", "[Fiddler] Request Header parsing failed. Request was:\n" + sDetailedError);
				return true;
			}
			m_session.Timers.FiddlerGotRequestHeaders = DateTime.Now;
			m_session._AssignID();
			FiddlerApplication.DoRequestHeadersAvailable(m_session);
			if (m_session.isFlagSet(SessionFlags.RequestStreamed))
			{
				if (!("CONNECT" == m_headers.HTTPMethod) && !m_headers.ExistsAndEquals("Content-Length", "0") && (m_headers.Exists("Content-Length") || m_headers.Exists("Transfer-Encoding")))
				{
					return true;
				}
				m_session.SetBitFlag(SessionFlags.RequestStreamed, b: false);
			}
			if (Utilities.isRPCOverHTTPSMethod(m_headers.HTTPMethod) && !m_headers.ExistsAndEquals("Content-Length", "0"))
			{
				m_session.SetBitFlag(SessionFlags.IsRPCTunnel, b: true);
				return true;
			}
			if (m_headers.ExistsAndEquals("Transfer-Encoding", "chunked"))
			{
				stateRead.bIsChunkedBody = true;
			}
			else if (m_headers.Exists("Content-Length"))
			{
				long iHeaderCL = 0L;
				if (!long.TryParse(m_headers["Content-Length"], NumberStyles.Integer, NumberFormatInfo.InvariantInfo, out iHeaderCL) || iHeaderCL < 0)
				{
					FiddlerApplication.HandleHTTPError(m_session, SessionFlags.ProtocolViolationInRequest, bPoisonClientConnection: true, bPoisonServerConnection: true, "Request content length was invalid.\nContent-Length: " + m_headers["Content-Length"]);
					FailSession(400, "Fiddler - Bad Request", "[Fiddler] Request Content-Length header parsing failed.\nContent-Length: " + m_headers["Content-Length"]);
					return true;
				}
				stateRead.iContentLength = iHeaderCL;
				if (iHeaderCL > 0)
				{
					stateRead.m_requestData.HintTotalSize((uint)(iHeaderCL + stateRead.iEntityBodyOffset));
				}
			}
		}
		if (stateRead.bIsChunkedBody)
		{
			if (stateRead.m_lngLastChunkInfoOffset < stateRead.iEntityBodyOffset)
			{
				stateRead.m_lngLastChunkInfoOffset = stateRead.iEntityBodyOffset;
			}
			long lngDontCare;
			return Utilities.IsChunkedBodyComplete(m_session, stateRead.m_requestData, stateRead.m_lngLastChunkInfoOffset, out stateRead.m_lngLastChunkInfoOffset, out lngDontCare);
		}
		return stateRead.m_requestData.Length >= stateRead.iEntityBodyOffset + stateRead.iContentLength;
	}

	/// <summary>
	/// Read a (usually complete) request from pipeClient. If RequestStreamed flag is set, only the headers have been read.
	/// </summary>
	/// <returns>TRUE, if a request could be read. FALSE, otherwise.</returns>
	internal bool ReadRequest()
	{
		if (stateRead != null)
		{
			string exceptionMessage = "ReadRequest called when requestData buffer already existed.";
			FiddlerApplication.Log.LogString(exceptionMessage);
			return false;
		}
		if (pipeClient == null)
		{
			string exceptionMessage2 = "ReadRequest called after pipeClient was null'd.";
			FiddlerApplication.Log.LogString(exceptionMessage2);
			return false;
		}
		stateRead = new RequestReaderState();
		m_session.SetBitFlag(SessionFlags.ClientPipeReused, pipeClient.iUseCount != 0);
		pipeClient.IncrementUse(0);
		pipeClient.setReceiveTimeout(bFirstRead: true);
		bool bAbort = false;
		bool bDone = false;
		byte[] _arrReadFromPipe = new byte[s_cbClientReadBuffer];
		int cbLastReceive = 0;
		SessionTimers.NetTimestamps oNTS = new SessionTimers.NetTimestamps();
		Stopwatch oSW = Stopwatch.StartNew();
		do
		{
			try
			{
				cbLastReceive = pipeClient.Receive(_arrReadFromPipe);
				oNTS.AddRead(oSW.ElapsedMilliseconds, cbLastReceive);
			}
			catch (SocketException eeX)
			{
				bAbort = true;
				if (CONFIG.bDebugSpew)
				{
					FiddlerApplication.DebugSpew("ReadRequest {0} threw #{1} - {2}", (pipeClient == null) ? "Null pipeClient" : pipeClient.ToString(), eeX.ErrorCode, eeX.Message);
				}
				if (eeX.SocketErrorCode == SocketError.TimedOut)
				{
					m_session.oFlags["X-ClientPipeError"] = $"ReadRequest timed out; total of {stateRead.m_requestData.Length:N0} bytes read from client.";
					FailSession(408, "Request Timed Out", string.Format("The client failed to send a complete request on this {0} connection before the timeout period elapsed; {1} bytes were read from client.", (pipeClient.iUseCount < 2 || (pipeClient.bIsSecured && pipeClient.iUseCount < 3)) ? "NEW" : "REUSED", stateRead.m_requestData.Length));
				}
				continue;
			}
			catch (Exception ex)
			{
				bAbort = true;
				if (CONFIG.bDebugSpew)
				{
					FiddlerApplication.DebugSpew("ReadRequest {0} threw {1}", (pipeClient == null) ? "Null pipeClient" : pipeClient.ToString(), ex.Message);
				}
				continue;
			}
			if (cbLastReceive < 1)
			{
				bDone = true;
				FiddlerApplication.DoReadRequestBuffer(m_session, _arrReadFromPipe, 0);
				if (CONFIG.bDebugSpew)
				{
					FiddlerApplication.DebugSpew("ReadRequest {0} returned {1}", (pipeClient == null) ? "Null pipeClient" : pipeClient.ToString(), cbLastReceive);
				}
				continue;
			}
			if (CONFIG.bDebugSpew)
			{
				FiddlerApplication.DebugSpew("READ {0} FROM {1}:\n{2}", cbLastReceive, pipeClient, Utilities.ByteArrayToHexView(_arrReadFromPipe, 32, cbLastReceive));
			}
			if (!FiddlerApplication.DoReadRequestBuffer(m_session, _arrReadFromPipe, cbLastReceive))
			{
				FiddlerApplication.DebugSpew("ReadRequest() aborted by OnReadRequestBuffer");
				return false;
			}
			if (stateRead.m_requestData.Length == 0)
			{
				m_session.Timers.ClientBeginRequest = DateTime.Now;
				if (1 == pipeClient.iUseCount && cbLastReceive > 2 && (_arrReadFromPipe[0] == 4 || _arrReadFromPipe[0] == 5))
				{
					FiddlerApplication.Log.LogFormat("It looks like '{0}' is trying to send SOCKS traffic to us.\r\n{1}", m_session["X-ProcessInfo"], Utilities.ByteArrayToHexView(_arrReadFromPipe, 16, Math.Min(cbLastReceive, 256)));
					return false;
				}
				int iMsgStart;
				for (iMsgStart = 0; iMsgStart < cbLastReceive && (13 == _arrReadFromPipe[iMsgStart] || 10 == _arrReadFromPipe[iMsgStart]); iMsgStart++)
				{
				}
				stateRead.m_requestData.Write(_arrReadFromPipe, iMsgStart, cbLastReceive - iMsgStart);
				pipeClient.setReceiveTimeout(bFirstRead: false);
			}
			else
			{
				stateRead.m_requestData.Write(_arrReadFromPipe, 0, cbLastReceive);
			}
		}
		while (!bDone && !bAbort && !_isRequestComplete());
		_arrReadFromPipe = null;
		oSW = null;
		m_session.Timers.ClientReads = oNTS;
		if (bAbort || stateRead.m_requestData.Length == 0)
		{
			FiddlerApplication.DebugSpew("Reading from client set bAbort or m_requestData was empty");
			if (pipeClient != null && (pipeClient.iUseCount < 2 || (pipeClient.bIsSecured && pipeClient.iUseCount < 3)))
			{
				FiddlerApplication.Log.LogFormat("[Fiddler] No {0} request was received from ({1}) new client socket, port {2}.", pipeClient.bIsSecured ? "HTTPS" : "HTTP", m_session.oFlags["X-ProcessInfo"], m_session.oFlags["X-CLIENTPORT"]);
			}
			return false;
		}
		if (m_headers == null)
		{
			FiddlerApplication.DebugSpew("Reading from client set either bDone or bAbort without making any headers available");
			return false;
		}
		if (m_session.state >= SessionStates.Done)
		{
			FiddlerApplication.DebugSpew("SessionState >= Done while reading request");
			return false;
		}
		if ("CONNECT" == m_headers.HTTPMethod)
		{
			m_session.isTunnel = true;
			stateRead.m_sHostFromURI = m_session.PathAndQuery;
		}
		_ValidateHostDuringReadRequest();
		return m_headers.Exists("Host");
	}

	/// <summary>
	/// Verifies that the Hostname specified in the request line is compatible with the HOST header
	/// </summary>
	private void _ValidateHostDuringReadRequest()
	{
		if (stateRead.m_sHostFromURI == null)
		{
			return;
		}
		if (m_headers.Exists("Host"))
		{
			if (!Utilities.areOriginsEquivalent(stateRead.m_sHostFromURI, m_headers["Host"], m_session.isHTTPS ? 443 : (m_session.isFTP ? 21 : 80)) && (!m_session.isTunnel || !Utilities.areOriginsEquivalent(stateRead.m_sHostFromURI, m_headers["Host"], 443)))
			{
				m_session.oFlags["X-Original-Host"] = m_headers["Host"];
				m_session.oFlags["X-URI-Host"] = stateRead.m_sHostFromURI;
				if (FiddlerApplication.Prefs.GetBoolPref("fiddler.network.SetHostHeaderFromURL", bDefault: true))
				{
					m_headers["Host"] = stateRead.m_sHostFromURI;
				}
			}
		}
		else
		{
			if ("HTTP/1.1".OICEquals(m_headers.HTTPVersion))
			{
				m_session.oFlags["X-Original-Host"] = string.Empty;
			}
			m_headers["Host"] = stateRead.m_sHostFromURI;
		}
	}
}
