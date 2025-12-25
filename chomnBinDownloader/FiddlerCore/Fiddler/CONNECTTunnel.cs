using System;
using System.IO;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

namespace Fiddler;

/// <summary>
/// The CONNECTTunnel class represents a "blind tunnel" through which a CONNECT request is serviced to shuffle bytes between a client and the server.
/// </summary>
/// <remarks>
/// See pg 206 in HTTP: The Complete Reference for details on how Tunnels work.
/// When HTTPS Decryption is disabled, Fiddler accepts a CONNECT request from the client. Then, we open a connection to the remote server. 
/// We shuttle bytes back and forth between the client and the server in this tunnel, keeping Fiddler itself out of the loop
/// (no tampering, etc). 
/// </remarks>
internal class CONNECTTunnel : ITunnel
{
	private Socket socketRemote;

	private Socket socketClient;

	private ClientPipe pipeTunnelClient;

	private ServerPipe pipeTunnelRemote;

	private Session _mySession;

	private byte[] arrRequestBytes;

	private byte[] arrResponseBytes;

	private AutoResetEvent oKeepTunnelAlive;

	private bool bIsOpen = true;

	/// <summary>
	/// Number of bytes received from the client
	/// </summary>
	private long _lngEgressByteCount;

	/// <summary>
	/// Number of bytes received from the server
	/// </summary>
	private long _lngIngressByteCount;

	/// <summary>
	/// TRUE if this is a Blind tunnel, FALSE if decrypting
	/// </summary>
	private bool bIsBlind;

	public bool IsOpen => bIsOpen;

	/// <summary>
	/// Returns number of bytes sent from the Server to the Client
	/// </summary>
	public long IngressByteCount => _lngIngressByteCount;

	/// <summary>
	/// Returns number of bytes sent from the Client to the Server
	/// </summary>
	public long EgressByteCount => _lngEgressByteCount;

	/// <summary>
	/// This "Factory" method creates a new HTTPS Tunnel and executes it on a background (non-pooled) thread.
	/// </summary>
	/// <param name="oSession">The Session containing the HTTP CONNECT request</param>
	internal static void CreateTunnel(Session oSession)
	{
		if (oSession == null || oSession.oRequest == null || oSession.oRequest.headers == null || oSession.oRequest.pipeClient == null || oSession.oResponse == null)
		{
			return;
		}
		ClientPipe oPC = oSession.oRequest.pipeClient;
		if (oPC != null)
		{
			oSession.oRequest.pipeClient = null;
			ServerPipe oPS = oSession.oResponse.pipeServer;
			if (oPS != null)
			{
				oSession.oResponse.pipeServer = null;
				Thread oNewThread = new Thread(((CONNECTTunnel)(oSession.__oTunnel = new CONNECTTunnel(oSession, oPC, oPS))).RunTunnel);
				oNewThread.IsBackground = true;
				oNewThread.Start();
			}
		}
	}

	/// <summary>
	/// Creates a HTTPS tunnel. External callers instead use the CreateTunnel static method.
	/// </summary>
	/// <param name="oSess">The session for which this tunnel was initially created.</param>
	/// <param name="oFrom">Client Pipe</param>
	/// <param name="oTo">Server Pipe</param>
	private CONNECTTunnel(Session oSess, ClientPipe oFrom, ServerPipe oTo)
	{
		_mySession = oSess;
		pipeTunnelClient = oFrom;
		pipeTunnelRemote = oTo;
		_mySession.SetBitFlag(SessionFlags.IsBlindTunnel, b: true);
	}

	/// <summary>
	/// This function keeps the thread alive until it is signaled that the traffic is complete
	/// </summary>
	private void WaitForCompletion()
	{
		if (oKeepTunnelAlive != null)
		{
		}
		oKeepTunnelAlive = new AutoResetEvent(initialState: false);
		oKeepTunnelAlive.WaitOne();
		oKeepTunnelAlive.Close();
		oKeepTunnelAlive = null;
		bIsOpen = false;
		arrRequestBytes = (arrResponseBytes = null);
		pipeTunnelClient = null;
		pipeTunnelRemote = null;
		socketClient = (socketRemote = null);
		if (Utilities.HasHeaders(_mySession.oResponse))
		{
			_mySession.oResponse.headers["EndTime"] = DateTime.Now.ToString("HH:mm:ss.fff");
			_mySession.oResponse.headers["ClientToServerBytes"] = _lngEgressByteCount.ToString();
			_mySession.oResponse.headers["ServerToClientBytes"] = _lngIngressByteCount.ToString();
		}
		_mySession.Timers.ServerDoneResponse = (_mySession.Timers.ClientBeginResponse = (_mySession.Timers.ClientDoneResponse = DateTime.Now));
		_mySession = null;
	}

	/// <summary>
	/// Executes the HTTPS tunnel inside an All-it-can-eat exception handler.
	/// Call from a background thread.
	/// </summary>
	private void RunTunnel()
	{
		if (FiddlerApplication.oProxy == null)
		{
			return;
		}
		try
		{
			DoTunnel();
		}
		catch (Exception eX)
		{
			string title = "Uncaught Exception in Tunnel; Session #" + _mySession.id;
			FiddlerApplication.Log.LogFormat("{0}: {1}", title, eX.ToString());
		}
	}

	private void DoTunnel()
	{
		try
		{
			bIsBlind = !CONFIG.DecryptHTTPS || _mySession.oFlags.ContainsKey("x-no-decrypt");
			if (!bIsBlind)
			{
				bIsBlind = CONFIG.ShouldSkipDecryption(_mySession.PathAndQuery);
			}
			if (!bIsBlind && CONFIG.DecryptWhichProcesses != 0)
			{
				string sProc = _mySession.oFlags["x-ProcessInfo"];
				if (CONFIG.DecryptWhichProcesses == ProcessFilterCategories.HideAll)
				{
					if (!string.IsNullOrEmpty(sProc))
					{
						bIsBlind = true;
					}
				}
				else if (!string.IsNullOrEmpty(sProc))
				{
					bool bIsBrowser = Utilities.IsBrowserProcessName(sProc);
					if ((CONFIG.DecryptWhichProcesses == ProcessFilterCategories.Browsers && !bIsBrowser) || (CONFIG.DecryptWhichProcesses == ProcessFilterCategories.NonBrowsers && bIsBrowser))
					{
						bIsBlind = true;
					}
				}
			}
			bool bServerPipeSecured;
			string sCertCN;
			X509Certificate2 certServer;
			while (true)
			{
				_mySession.SetBitFlag(SessionFlags.IsDecryptingTunnel, !bIsBlind);
				_mySession.SetBitFlag(SessionFlags.IsBlindTunnel, bIsBlind);
				if (bIsBlind)
				{
					DoBlindTunnel();
					return;
				}
				bServerPipeSecured = false;
				if (!_mySession.oFlags.ContainsKey("x-OverrideCertCN"))
				{
					if (CONFIG.bUseSNIForCN)
					{
						string sSNI = _mySession.oFlags["https-Client-SNIHostname"];
						if (!string.IsNullOrEmpty(sSNI) && sSNI != _mySession.hostname)
						{
							_mySession.oFlags["x-OverrideCertCN"] = _mySession.oFlags["https-Client-SNIHostname"];
						}
					}
					if (_mySession.oFlags["x-OverrideCertCN"] == null && _mySession.oFlags.ContainsKey("x-UseCertCNFromServer"))
					{
						if (!pipeTunnelRemote.SecureExistingConnection(_mySession, _mySession.hostname, _mySession.oFlags["https-Client-Certificate"], SslProtocols.None, ref _mySession.Timers.HTTPSHandshakeTime))
						{
							throw new Exception("HTTPS Early-Handshaking to server did not succeed.");
						}
						bServerPipeSecured = true;
						string sServerCN = pipeTunnelRemote.GetServerCertCN();
						if (!string.IsNullOrEmpty(sServerCN))
						{
							_mySession.oFlags["x-OverrideCertCN"] = sServerCN;
						}
					}
				}
				sCertCN = _mySession.oFlags["x-OverrideCertCN"] ?? Utilities.StripIPv6LiteralBrackets(_mySession.hostname);
				try
				{
					certServer = CertMaker.FindCert(sCertCN);
					if (certServer == null)
					{
						throw new Exception("Certificate Maker returned null when asked for a certificate for " + sCertCN);
					}
				}
				catch (Exception eX2)
				{
					certServer = null;
					FiddlerApplication.Log.LogFormat("fiddler.https> Failed to obtain certificate for {0} due to {1}", sCertCN, eX2.Message);
					_mySession.oFlags["x-HTTPS-Decryption-Error"] = "Could not find or generate interception certificate.";
					if (!bServerPipeSecured && FiddlerApplication.Prefs.GetBoolPref("fiddler.network.https.blindtunnelifcertunobtainable", bDefault: true))
					{
						bIsBlind = true;
						continue;
					}
				}
				break;
			}
			if (!bServerPipeSecured)
			{
				SslProtocols sslprotClient = _PeekClientHelloVersion();
				if (!pipeTunnelRemote.SecureExistingConnection(_mySession, sCertCN, _mySession.oFlags["https-Client-Certificate"], sslprotClient, ref _mySession.Timers.HTTPSHandshakeTime))
				{
					throw new Exception("HTTPS Handshaking to server did not succeed.");
				}
			}
			if (!pipeTunnelClient.SecureClientPipeDirect(certServer))
			{
				throw new Exception("HTTPS Handshaking to client did not succeed.");
			}
			_mySession["https-Client-Version"] = pipeTunnelClient.SecureProtocol.ToString();
			string sConnectionDescriptionIntro = "Encrypted HTTPS traffic flows through this CONNECT tunnel. HTTPS Decryption is enabled in Fiddler, so decrypted sessions running in this tunnel will be shown in the Web Sessions list.\n\n";
			string sConnectionDescription = pipeTunnelRemote.DescribeConnectionSecurity();
			_mySession.responseBodyBytes = Encoding.UTF8.GetBytes(sConnectionDescriptionIntro + sConnectionDescription);
			_mySession["https-Server-Cipher"] = pipeTunnelRemote.GetConnectionCipherInfo();
			_mySession["https-Server-Version"] = pipeTunnelRemote.SecureProtocol.ToString();
			Session oSecuredSession = new Session(pipeTunnelClient, pipeTunnelRemote);
			oSecuredSession.oFlags["x-serversocket"] = _mySession.oFlags["x-securepipe"];
			if (pipeTunnelRemote != null && pipeTunnelRemote.Address != null)
			{
				oSecuredSession.m_hostIP = pipeTunnelRemote.Address.ToString();
				oSecuredSession.oFlags["x-hostIP"] = oSecuredSession.m_hostIP;
				oSecuredSession.oFlags["x-EgressPort"] = pipeTunnelRemote.LocalPort.ToString();
			}
			oSecuredSession.Execute(null);
		}
		catch (Exception)
		{
			try
			{
				pipeTunnelClient.End();
				pipeTunnelRemote.End();
			}
			catch (Exception)
			{
			}
		}
	}

	private SslProtocols _PeekClientHelloVersion()
	{
		SslProtocols sslprotClient = SslProtocols.None;
		if (pipeTunnelClient != null)
		{
			byte[] arrSniff = new byte[16];
			int iPeekCount = pipeTunnelClient.GetRawSocket().Receive(arrSniff, SocketFlags.Peek);
			if (iPeekCount > 3 && arrSniff[0] == 22)
			{
				if (iPeekCount > 10)
				{
					sslprotClient = _parseSslProt(arrSniff[9], arrSniff[10]);
				}
				else if (iPeekCount > 3)
				{
					sslprotClient = _parseSslProt(arrSniff[1], arrSniff[2]);
				}
			}
		}
		return sslprotClient;
	}

	private SslProtocols _parseSslProt(byte b1, byte b2)
	{
		if (b1 != 3)
		{
			return SslProtocols.None;
		}
		return b2 switch
		{
			0 => SslProtocols.Ssl3, 
			1 => SslProtocols.Tls, 
			2 => SslProtocols.Tls11, 
			3 => SslProtocols.Tls12, 
			_ => SslProtocols.None, 
		};
	}

	private void DoBlindTunnel()
	{
		arrRequestBytes = new byte[16384];
		arrResponseBytes = new byte[16384];
		socketClient = pipeTunnelClient.GetRawSocket();
		socketRemote = pipeTunnelRemote.GetRawSocket();
		socketClient.BeginReceive(arrRequestBytes, 0, arrRequestBytes.Length, SocketFlags.None, OnClientReceive, socketClient);
		socketRemote.BeginReceive(arrResponseBytes, 0, arrResponseBytes.Length, SocketFlags.None, OnRemoteReceive, socketRemote);
		WaitForCompletion();
	}

	/// <summary>
	/// Close the HTTPS tunnel and signal the event to let the service thread die.
	/// WARNING: This MUST not be allowed to throw any exceptions, because it will do so on threads that don't catch them, and this will kill the application.
	/// </summary>
	public void CloseTunnel()
	{
		try
		{
			if (pipeTunnelClient != null)
			{
				pipeTunnelClient.End();
			}
		}
		catch (Exception)
		{
		}
		try
		{
			if (pipeTunnelRemote != null)
			{
				pipeTunnelRemote.End();
			}
		}
		catch (Exception)
		{
		}
		try
		{
			if (oKeepTunnelAlive != null)
			{
				oKeepTunnelAlive.Set();
			}
		}
		catch (Exception)
		{
		}
	}

	/// <summary>
	/// 	Called when we have received data from the local client.
	/// 	Incoming data will immediately be forwarded to the remote host.
	/// </summary>
	/// <param name="ar">The result of the asynchronous operation.</param>
	protected void OnClientReceive(IAsyncResult ar)
	{
		try
		{
			if(socketClient==null)
			{
				return;
			}
			int Ret = socketClient.EndReceive(ar);
			if (Ret > 0)
			{
				_lngEgressByteCount += Ret;
				FiddlerApplication.DoReadRequestBuffer(_mySession, arrRequestBytes, Ret);
				if (_mySession.requestBodyBytes == null || _mySession.requestBodyBytes.LongLength == 0)
				{
					try
					{
						HTTPSClientHello oHello = new HTTPSClientHello();
						if (oHello.LoadFromStream(new MemoryStream(arrRequestBytes, 0, Ret, writable: false)))
						{
							_mySession.requestBodyBytes = Encoding.UTF8.GetBytes(oHello.ToString() + "\n");
							_mySession["https-Client-SessionID"] = oHello.SessionID;
							if (!string.IsNullOrEmpty(oHello.ServerNameIndicator))
							{
								_mySession["https-Client-SNIHostname"] = oHello.ServerNameIndicator;
							}
						}
					}
					catch (Exception eX2)
					{
						_mySession.requestBodyBytes = Encoding.UTF8.GetBytes("Request HTTPSParse failed: " + eX2.Message);
					}
				}
				socketRemote.BeginSend(arrRequestBytes, 0, Ret, SocketFlags.None, OnRemoteSent, socketRemote);
			}
			else
			{
				FiddlerApplication.DoReadRequestBuffer(_mySession, arrRequestBytes, 0);
				CloseTunnel();
			}
		}
		catch (Exception)
		{
			CloseTunnel();
		}
	}

	/// <summary>Called when we have sent data to the local client.<br>When all the data has been sent, we will start receiving again from the remote host.</br></summary>
	/// <param name="ar">The result of the asynchronous operation.</param>
	protected void OnClientSent(IAsyncResult ar)
	{
		try
		{
			if (socketClient == null)
				return;
			int Ret = socketClient.EndSend(ar);
			if (Ret > 0)
			{
				socketRemote.BeginReceive(arrResponseBytes, 0, arrResponseBytes.Length, SocketFlags.None, OnRemoteReceive, socketRemote);
			}
		}
		catch (Exception)
		{
		}
	}

	/// <summary>Called when we have sent data to the remote host.<br>When all the data has been sent, we will start receiving again from the local client.</br></summary>
	/// <param name="ar">The result of the asynchronous operation.</param>
	protected void OnRemoteSent(IAsyncResult ar)
	{
		try
		{
			int Ret = socketRemote.EndSend(ar);
			if (Ret > 0)
			{
				socketClient.BeginReceive(arrRequestBytes, 0, arrRequestBytes.Length, SocketFlags.None, OnClientReceive, socketClient);
			}
		}
		catch (Exception)
		{
		}
	}

	/// <summary>Called when we have received data from the remote host.<br>Incoming data will immediately be forwarded to the local client.</br></summary>
	/// <param name="ar">The result of the asynchronous operation.</param>
	protected void OnRemoteReceive(IAsyncResult ar)
	{
		try
		{
			if(socketRemote==null)
			{
				return;
			}
			int Ret = socketRemote.EndReceive(ar);
			if (Ret > 0)
			{
				_lngIngressByteCount += Ret;
				FiddlerApplication.DoReadResponseBuffer(_mySession, arrResponseBytes, Ret);
				if (Utilities.IsNullOrEmpty(_mySession.responseBodyBytes))
				{
					try
					{
						HTTPSServerHello oHello = new HTTPSServerHello();
						if (oHello.LoadFromStream(new MemoryStream(arrResponseBytes, 0, Ret, writable: false)))
						{
							string sDecryptTip = (CONFIG.DecryptHTTPS ? string.Format("Fiddler's HTTPS Decryption feature is enabled, but this specific tunnel was configured not to be decrypted. {0}", _mySession.oFlags.ContainsKey("X-No-Decrypt") ? (" Session Flag 'X-No-Decrypt' was set to: '" + _mySession.oFlags["X-No-Decrypt"] + "'.") : "Settings can be found inside Tools > Options > HTTPS.") : "To view the encrypted sessions inside this tunnel, enable the Tools > Options > HTTPS > Decrypt HTTPS traffic option.");
							string sMessage = $"This is a CONNECT tunnel, through which encrypted HTTPS traffic flows.\n{sDecryptTip}\n\n{oHello.ToString()}\n";
							_mySession.responseBodyBytes = Encoding.UTF8.GetBytes(sMessage);
							_mySession["https-Server-SessionID"] = oHello.SessionID;
							_mySession["https-Server-Cipher"] = oHello.CipherSuite;
						}
					}
					catch (Exception eX2)
					{
						_mySession.requestBodyBytes = Encoding.UTF8.GetBytes("Response HTTPSParse failed: " + eX2.Message);
					}
				}
				socketClient.BeginSend(arrResponseBytes, 0, Ret, SocketFlags.None, OnClientSent, socketClient);
			}
			else
			{
				FiddlerApplication.DoReadResponseBuffer(_mySession, arrResponseBytes, 0);
				CloseTunnel();
			}
		}
		catch (Exception)
		{
			CloseTunnel();
		}
	}
}
