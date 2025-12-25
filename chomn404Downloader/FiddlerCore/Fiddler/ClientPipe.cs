using System;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using FiddlerCore.Utilities;

namespace Fiddler;

/// <summary>
/// A ClientPipe wraps a socket connection to a client application.
/// </summary>
public class ClientPipe : BasePipe
{
	/// <summary>
	/// By default, we now test for loopbackness before lookup of PID
	/// https://github.com/telerik/fiddler/issues/83
	/// </summary>
	internal static bool _ProcessLookupSkipsLoopbackCheck = FiddlerApplication.Prefs.GetBoolPref("fiddler.proxy.ProcessLookupSkipsLoopbackCheck", bDefault: false);

	/// <summary>
	/// Timeout to wait for the *first* data from the client
	/// </summary>
	internal static int _timeoutFirstReceive = FiddlerApplication.Prefs.GetInt32Pref("fiddler.network.timeouts.clientpipe.receive.initial", 45000);

	/// <summary>
	/// Timeout to wait for the ongoing reads from the client (as headers and body are read)
	/// </summary>
	internal static int _timeoutReceiveLoop = FiddlerApplication.Prefs.GetInt32Pref("fiddler.network.timeouts.clientpipe.receive.loop", 60000);

	/// <summary>
	/// Timeout before which an idle connection is closed (e.g. for HTTP Keep-Alive)
	/// </summary>
	internal static int _timeoutIdle = FiddlerApplication.Prefs.GetInt32Pref("fiddler.network.timeouts.clientpipe.idle", 115000);

	internal static int _cbLimitRequestHeaders = FiddlerApplication.Prefs.GetInt32Pref("fiddler.network.limit.maxrequestheaders", 1048576);

	private static bool _bWantClientCert = FiddlerApplication.Prefs.GetBoolPref("fiddler.network.https.requestclientcertificate", bDefault: false);

	/// <summary>
	/// Client process name (e.g. "iexplore")
	/// </summary>
	private string _sProcessName;

	/// <summary>
	/// Client process ProcessID
	/// </summary>
	private int _iProcessID;

	/// <summary>
	/// Data which was previously "over-read" from the client. Populated when HTTP-pipelining is attempted
	/// </summary>
	private byte[] _arrReceivedAndPutBack = null;

	/// <summary>
	/// ID of the process that opened this socket, assuming that Port Mapping is enabled, and the connection is from the local machine
	/// </summary>
	public int LocalProcessID => _iProcessID;

	/// <summary>
	/// Name of the Process referred to by LocalProcessID, or String.Empty if unknown
	/// </summary>
	public string LocalProcessName => _sProcessName ?? string.Empty;

	/// <summary>
	/// Timestamp of either 1&gt; The underlying socket's creation from a .Accept() call, or 2&gt; when this ClientPipe was created.
	/// </summary>
	internal DateTime dtAccepted { get; set; }

	/// <summary>
	/// Does this Pipe have data (or closure/errors) to read?
	/// </summary>
	/// <returns>TRUE if this Pipe requires attention</returns>
	public override bool HasDataAvailable()
	{
		try
		{
			if (_arrReceivedAndPutBack != null)
			{
				return true;
			}
			return base.HasDataAvailable();
		}
		catch
		{
			return true;
		}
	}

	/// <summary>
	/// If you previously read more bytes than you needed from this client socket, you can put some back.
	/// </summary>
	/// <param name="toPutback">Array of bytes to put back; now owned by this object</param>
	internal void putBackSomeBytes(byte[] toPutback)
	{
		_arrReceivedAndPutBack = toPutback;
	}

	internal new int Receive(byte[] arrBuffer)
	{
		if (_arrReceivedAndPutBack == null)
		{
			return base.Receive(arrBuffer);
		}
		int iRecoveredBufferLength = _arrReceivedAndPutBack.Length;
		Buffer.BlockCopy(_arrReceivedAndPutBack, 0, arrBuffer, 0, iRecoveredBufferLength);
		_arrReceivedAndPutBack = null;
		return iRecoveredBufferLength;
	}

	internal ClientPipe(Socket oSocket, DateTime dtCreationTime)
		: base(oSocket, "C")
	{
		try
		{
			dtAccepted = dtCreationTime;
			oSocket.NoDelay = true;
			if (ClientChatter.s_SO_RCVBUF_Option >= 0)
			{
				oSocket.ReceiveBufferSize = ClientChatter.s_SO_RCVBUF_Option;
			}
			if (ClientChatter.s_SO_SNDBUF_Option >= 0)
			{
				oSocket.SendBufferSize = ClientChatter.s_SO_SNDBUF_Option;
			}
			if (CONFIG.bDebugSpew)
			{
				FiddlerApplication.DebugSpew("[ClientPipe]\n SendBufferSize:\t{0}\n ReceiveBufferSize:\t{1}\n SendTimeout:\t{2}\n ReceiveTimeOut:\t{3}\n NoDelay:\t{4}", oSocket.SendBufferSize, oSocket.ReceiveBufferSize, oSocket.SendTimeout, oSocket.ReceiveTimeout, oSocket.NoDelay);
			}
			_setProcessName();
		}
		catch
		{
		}
	}

	private void _setProcessName()
	{
		if (CONFIG.bMapSocketToProcess && (!CONFIG.bAllowRemoteConnections || _ProcessLookupSkipsLoopbackCheck || (_baseSocket.LocalEndPoint as IPEndPoint).Address.Equals((_baseSocket.RemoteEndPoint as IPEndPoint).Address)))
		{
			_iProcessID = FiddlerSock.MapLocalPortToProcessId(base.Port);
			if (_iProcessID > 0)
			{
				_sProcessName = ProcessHelper.GetProcessName(_iProcessID);
			}
		}
	}

	/// <summary>
	/// Sets the socket's timeout based on whether we're waiting for our first read or for an ongoing read-loop
	/// </summary>
	internal void setReceiveTimeout(bool bFirstRead)
	{
		try
		{
			_baseSocket.ReceiveTimeout = (bFirstRead ? _timeoutFirstReceive : _timeoutReceiveLoop);
		}
		catch
		{
		}
	}

	/// <summary>
	/// Returns a semicolon-delimited string describing this ClientPipe
	/// </summary>
	/// <returns>A semicolon-delimited string</returns>
	public override string ToString()
	{
		return string.Format("[ClientPipe: {0}:{1}; UseCnt: {2}[{3}]; Port: {4}; {5} established {6}]", _sProcessName, _iProcessID, iUseCount, string.Empty, base.Port, base.bIsSecured ? "SECURE" : "PLAINTTEXT", dtAccepted);
	}

	/// <summary>
	/// Perform a HTTPS Server handshake to the client. Swallows exception and returns false on failure.
	/// </summary>
	/// <param name="certServer"></param>
	/// <returns></returns>
	internal bool SecureClientPipeDirect(X509Certificate2 certServer)
	{
		try
		{
			FiddlerApplication.DebugSpew("SecureClientPipeDirect({0})", certServer.Subject);
			if (_httpsStream != null)
			{
			}
			_httpsStream = new SslStream(new NetworkStream(_baseSocket, ownsSocket: false), leaveInnerStreamOpen: false);
			SslProtocols sslProtocols = CONFIG.oAcceptedClientHTTPSProtocols;
			sslProtocols = SslProtocolsFilter.RemoveNotAllowedSecurityProtocols(sslProtocols);
			sslProtocols = SslProtocolsFilter.EnsureConsecutiveProtocols(sslProtocols);
			_httpsStream.AuthenticateAsServer(certServer, _bWantClientCert, sslProtocols, checkCertificateRevocation: false);
			return true;
		}
		catch (AuthenticationException aEX)
		{
			FiddlerApplication.Log.LogFormat("!SecureClientPipeDirect failed: {1} for pipe ({0}).", certServer.Subject, FiddlerCore.Utilities.Utilities.DescribeException(aEX));
			End();
		}
		catch (Exception eX)
		{
			FiddlerApplication.Log.LogFormat("!SecureClientPipeDirect failed: {1} for pipe ({0})", certServer.Subject, FiddlerCore.Utilities.Utilities.DescribeException(eX));
			End();
		}
		return false;
	}

	/// <summary>
	/// This function sends the client socket a CONNECT ESTABLISHED, and then performs a HTTPS authentication
	/// handshake, with Fiddler acting as the server.
	/// </summary>
	/// <param name="sHostname">Hostname Fiddler is pretending to be (NO PORT!)</param>
	/// <param name="oHeaders">The set of headers to be returned to the client in response to the client's CONNECT tunneling request</param>
	/// <returns>true if the handshake succeeds</returns>
	internal bool SecureClientPipe(string sHostname, HTTPResponseHeaders oHeaders)
	{
		X509Certificate2 certServer;
		try
		{
			certServer = CertMaker.FindCert(sHostname);
		}
		catch (Exception eX2)
		{
			FiddlerApplication.Log.LogFormat("fiddler.https> Failed to obtain certificate for {0} due to {1}", sHostname, eX2.Message);
			certServer = null;
		}
		try
		{
			if (certServer == null)
			{
				FiddlerApplication.Log.LogFormat("!WARNING: Unable to find or create Certificate for {0}", sHostname);
				oHeaders.SetStatus(502, "Fiddler unable to find or create certificate");
			}
			if (CONFIG.bDebugSpew)
			{
				FiddlerApplication.DebugSpew("SecureClientPipe for: " + ToString() + " sending data to client:\n" + Utilities.ByteArrayToHexView(oHeaders.ToByteArray(prependStatusLine: true, appendEmptyLine: true), 32));
			}
			Send(oHeaders.ToByteArray(prependStatusLine: true, appendEmptyLine: true));
			if (oHeaders.HTTPResponseCode != 200)
			{
				FiddlerApplication.DebugSpew("SecureClientPipe returning FALSE because HTTPResponseCode != 200");
				return false;
			}
			_httpsStream = new SslStream(new NetworkStream(_baseSocket, ownsSocket: false), leaveInnerStreamOpen: false);
			SslProtocols sslProtocols = CONFIG.oAcceptedClientHTTPSProtocols;
			sslProtocols = SslProtocolsFilter.RemoveNotAllowedSecurityProtocols(sslProtocols);
			sslProtocols = SslProtocolsFilter.EnsureConsecutiveProtocols(sslProtocols);
			_httpsStream.AuthenticateAsServer(certServer, _bWantClientCert, sslProtocols, checkCertificateRevocation: false);
			return true;
		}
		catch (Exception eX)
		{
			FiddlerApplication.Log.LogFormat("SecureClientPipe ({0} failed: {1}.", sHostname, FiddlerCore.Utilities.Utilities.DescribeException(eX));
			try
			{
				End();
			}
			catch (Exception)
			{
			}
		}
		return false;
	}
}
