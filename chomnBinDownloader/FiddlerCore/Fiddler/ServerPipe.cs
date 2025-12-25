using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using FiddlerCore.Utilities;

namespace Fiddler;

/// <summary>
/// A ServerPipe wraps a socket connection to a server.
/// </summary>
public class ServerPipe : BasePipe
{
	internal class TLSAlertEatingStream : Stream
	{
		private bool bFirstRead = true;

		private Stream _innerStream;

		private string _toHost;

		public override bool CanRead => _innerStream.CanRead;

		public override bool CanSeek => false;

		public override bool CanWrite => _innerStream.CanWrite;

		public override long Length
		{
			get
			{
				throw new NotSupportedException();
			}
		}

		public override long Position
		{
			get
			{
				throw new NotSupportedException();
			}
			set
			{
				throw new NotSupportedException();
			}
		}

		public override int ReadTimeout
		{
			get
			{
				return _innerStream.ReadTimeout;
			}
			set
			{
				_innerStream.ReadTimeout = value;
			}
		}

		public override int WriteTimeout
		{
			get
			{
				return _innerStream.WriteTimeout;
			}
			set
			{
				_innerStream.WriteTimeout = value;
			}
		}

		public TLSAlertEatingStream(Stream baseStream, string sHostname)
		{
			_innerStream = baseStream;
			_toHost = sHostname;
		}

		public override int Read(byte[] buffer, int offset, int count)
		{
			int iThisRead = _innerStream.Read(buffer, offset, count);
			if (bFirstRead && iThisRead > 1)
			{
				if (buffer[offset] == 21 && iThisRead == 5 && buffer[offset + 3] == 0 && 2 == buffer[offset + 4])
				{
					iThisRead = _innerStream.Read(buffer, offset, 2);
					if (iThisRead == 2 && 1 == buffer[offset] && 112 == buffer[offset + 1])
					{
						FiddlerApplication.Log.LogString("! Eating a TLS unrecognized_name alert (level: Warning) when connecting to '" + _toHost + "'");
						iThisRead = _innerStream.Read(buffer, offset, count);
					}
				}
				bFirstRead = false;
				_toHost = null;
			}
			return iThisRead;
		}

		public override void Write(byte[] buffer, int offset, int count)
		{
			_innerStream.Write(buffer, offset, count);
		}

		protected override void Dispose(bool disposing)
		{
			_innerStream.Close();
		}

		public override void Flush()
		{
			_innerStream.Flush();
		}

		public override long Seek(long offset, SeekOrigin origin)
		{
			throw new NotSupportedException();
		}

		public override void SetLength(long value)
		{
			throw new NotSupportedException();
		}
	}

	private static object thisLock = new object();

	internal static int _timeoutSendInitial = FiddlerApplication.Prefs.GetInt32Pref("fiddler.network.timeouts.serverpipe.send.initial", -1);

	internal static int _timeoutSendReused = FiddlerApplication.Prefs.GetInt32Pref("fiddler.network.timeouts.serverpipe.send.reuse", -1);

	internal static int _timeoutReceiveInitial = FiddlerApplication.Prefs.GetInt32Pref("fiddler.network.timeouts.serverpipe.receive.initial", -1);

	internal static int _timeoutReceiveReused = FiddlerApplication.Prefs.GetInt32Pref("fiddler.network.timeouts.serverpipe.receive.reuse", -1);

	internal static bool _bEatTLSAlerts = FiddlerApplication.Prefs.GetBoolPref("fiddler.network.https.DropSNIAlerts", bDefault: false);

	private PipeReusePolicy _reusePolicy;

	/// <summary>
	/// DateTime of the completion of the TCP/IP Connection
	/// </summary>
	internal DateTime dtConnected;

	/// <summary>
	/// TickCount when this Pipe was last placed in a PipePool
	/// </summary>
	internal ulong ulLastPooled;

	/// <summary>
	/// Returns TRUE if this ServerPipe is connected to a Gateway
	/// </summary>
	protected bool _bIsConnectedToGateway;

	/// <summary>
	/// Returns TRUE if this ServerPipe is connected to a SOCKS gateway
	/// </summary>
	private bool _bIsConnectedViaSOCKS;

	/// <summary>
	/// The Pooling key used for reusing a previously pooled ServerPipe. See sPoolKey property.
	/// </summary>
	protected string _sPoolKey;

	/// <summary>
	/// This field, if set, tracks the process ID to which this Pipe is permanently bound; set by MarkAsAuthenticated.
	/// NOTE: This isn't actually checked by anyone; instead the PID is added to the POOL Key
	/// </summary>
	private int _iMarriedToPID;

	/// <summary>
	/// Backing field for the isAuthenticated property
	/// </summary>
	private bool _isAuthenticated;

	/// <summary>
	/// String containing representation of the server's certificate chain
	/// </summary>
	private string _ServerCertChain = null;

	/// <summary>
	/// Server's certificate
	/// </summary>
	private X509Certificate2 _certServer = null;

	/// <summary>
	/// Policy for reuse of this pipe
	/// </summary>
	public PipeReusePolicy ReusePolicy
	{
		get
		{
			return _reusePolicy;
		}
		set
		{
			_reusePolicy = value;
		}
	}

	/// <summary>
	/// Returns TRUE if there is an underlying, mutually-authenticated HTTPS stream.
	///
	/// WARNING: Results are a bit of a lie. System.NET IsMutuallyAuthenticated == true if a client certificate is AVAILABLE even
	/// if that certificate was never SENT to the server.
	/// </summary>
	internal bool isClientCertAttached
	{
		get
		{
			if (_httpsStream != null)
			{
				return _httpsStream.IsMutuallyAuthenticated;
			}
			return false;
		}
	}

	/// <summary>
	/// Returns TRUE if this PIPE is marked as having been authenticated using a Connection-Oriented Auth protocol:
	/// NTLM, Kerberos, or HTTPS Client Certificate.
	/// </summary>
	internal bool isAuthenticated => _isAuthenticated;

	/// <summary>
	/// Indicates if this pipe is connected to an upstream (non-SOCKS) Proxy.
	/// </summary>
	public bool isConnectedToGateway => _bIsConnectedToGateway;

	/// <summary>
	/// Indicates if this pipe is connected to a SOCKS gateway
	/// </summary>
	public bool isConnectedViaSOCKS
	{
		get
		{
			return _bIsConnectedViaSOCKS;
		}
		set
		{
			_bIsConnectedViaSOCKS = value;
		}
	}

	/// <summary>
	/// Gets and sets the pooling key for this server pipe.
	/// </summary>
	/// <example>
	///   direct-&gt;{http|https}/{serverhostname}:{serverport}
	///   gw:{gatewayaddr:port}-&gt;*
	///   gw:{gatewayaddr:port}-&gt;{http|https}/{serverhostname}:{serverport}
	///   socks:{gatewayaddr:port}-&gt;{http|https}/{serverhostname}:{serverport}
	/// </example>
	public string sPoolKey
	{
		get
		{
			return _sPoolKey;
		}
		private set
		{
			if (CONFIG.bDebugSpew && !string.IsNullOrEmpty(_sPoolKey) && _sPoolKey != value)
			{
				FiddlerApplication.Log.LogFormat("fiddler.pipes>{0} pooling key changing from '{1}' to '{2}'", _sPipeName, _sPoolKey, value);
			}
			_sPoolKey = value.ToLower();
		}
	}

	public X509Certificate2 ServerCertificate => _certServer;

	/// <summary>
	/// Returns the IPEndPoint to which this socket is connected, or null
	/// </summary>
	public IPEndPoint RemoteEndPoint
	{
		get
		{
			if (_baseSocket == null)
			{
				return null;
			}
			try
			{
				return _baseSocket.RemoteEndPoint as IPEndPoint;
			}
			catch (Exception)
			{
				return null;
			}
		}
	}

	/// <summary>
	/// Wraps a socket in a Pipe
	/// </summary>
	/// <param name="oSocket">The Socket</param>
	/// <param name="sName">Pipe's human-readable name</param>
	/// <param name="bConnectedToGateway">True if the Pipe is attached to a gateway</param>
	/// <param name="sPoolingKey">The Pooling key used for socket reuse</param>
	internal ServerPipe(Socket oSocket, string sName, bool bConnectedToGateway, string sPoolingKey)
		: base(oSocket, sName)
	{
		dtConnected = DateTime.Now;
		_bIsConnectedToGateway = bConnectedToGateway;
		sPoolKey = sPoolingKey;
	}

	/// <summary>
	/// Marks this Pipe as having been authenticated. Depending on the preference "fiddler.network.auth.reusemode" this may impact the reuse policy for this pipe
	/// </summary>
	/// <param name="clientPID">The client's process ID, if known.</param>
	internal void MarkAsAuthenticated(int clientPID)
	{
		_isAuthenticated = true;
		int iMode = FiddlerApplication.Prefs.GetInt32Pref("fiddler.network.auth.reusemode", 0);
		if (iMode == 0 && clientPID == 0)
		{
			iMode = 1;
		}
		switch (iMode)
		{
		case 0:
			ReusePolicy = PipeReusePolicy.MarriedToClientProcess;
			_iMarriedToPID = clientPID;
			sPoolKey = $"pid{clientPID}*{sPoolKey}";
			break;
		case 1:
			ReusePolicy = PipeReusePolicy.MarriedToClientPipe;
			break;
		}
	}

	/// <summary>
	/// Sets the receiveTimeout based on whether this is a freshly opened server socket or a reused one.
	/// </summary>
	internal void setTimeouts()
	{
		try
		{
			int iReceiveTimeout = ((iUseCount < 2) ? _timeoutReceiveInitial : _timeoutReceiveReused);
			int iSendTimeout = ((iUseCount < 2) ? _timeoutSendInitial : _timeoutSendReused);
			if (iReceiveTimeout > 0)
			{
				_baseSocket.ReceiveTimeout = iReceiveTimeout;
			}
			if (iSendTimeout > 0)
			{
				_baseSocket.SendTimeout = iSendTimeout;
			}
		}
		catch
		{
		}
	}

	/// <summary>
	/// Returns a semicolon-delimited string describing this ServerPipe
	/// </summary>
	/// <returns>A semicolon-delimited string</returns>
	public override string ToString()
	{
		return string.Format("{0}[Key: {1}; UseCnt: {2} [{3}]; {4}; {5} (:{6} to {7}:{8} {9}) {10}]", _sPipeName, _sPoolKey, iUseCount, string.Empty, base.bIsSecured ? "Secure" : "PlainText", _isAuthenticated ? "Authenticated" : "Anonymous", base.LocalPort, base.Address, base.Port, isConnectedToGateway ? "Gateway" : "Direct", _reusePolicy);
	}

	private static string SummarizeCert(X509Certificate2 oCert)
	{
		if (!string.IsNullOrEmpty(oCert.FriendlyName))
		{
			return oCert.FriendlyName;
		}
		string sSubject = oCert.Subject;
		if (string.IsNullOrEmpty(sSubject))
		{
			return string.Empty;
		}
		if (sSubject.Contains("CN="))
		{
			return Utilities.TrimAfter(Utilities.TrimBefore(sSubject, "CN="), ",");
		}
		if (sSubject.Contains("O="))
		{
			return Utilities.TrimAfter(Utilities.TrimBefore(sSubject, "O="), ",");
		}
		return sSubject;
	}

	/// <summary>
	/// Returns the Server's certificate Subject CN (used by "x-UseCertCNFromServer")
	/// </summary>
	/// <returns>The *FIRST* CN field from the Subject of the certificate used to secure this HTTPS connection, or null if the connection is unsecure</returns>
	internal string GetServerCertCN()
	{
		if (_httpsStream == null)
		{
			return null;
		}
		if (_httpsStream.RemoteCertificate == null)
		{
			return null;
		}
		string sSubject = _httpsStream.RemoteCertificate.Subject;
		if (sSubject.Contains("CN="))
		{
			return Utilities.TrimAfter(Utilities.TrimBefore(sSubject, "CN="), ",");
		}
		return sSubject;
	}

	internal string GetServerCertChain()
	{
		if (_ServerCertChain != null)
		{
			return _ServerCertChain;
		}
		if (_httpsStream == null)
		{
			return string.Empty;
		}
		try
		{
			X509Certificate2 oEECert = new X509Certificate2(_httpsStream.RemoteCertificate);
			if (oEECert == null)
			{
				return string.Empty;
			}
			StringBuilder oSB = new StringBuilder();
			X509Chain oChain = new X509Chain();
			oChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
			oChain.Build(oEECert);
			for (int i = oChain.ChainElements.Count - 1; i >= 1; i--)
			{
				oSB.Append(SummarizeCert(oChain.ChainElements[i].Certificate));
				oSB.Append(" > ");
			}
			if (oChain.ChainElements.Count > 0)
			{
				oSB.AppendFormat("{0} [{1}]", SummarizeCert(oChain.ChainElements[0].Certificate), oChain.ChainElements[0].Certificate.SerialNumber);
			}
			_ServerCertChain = oSB.ToString();
			return oSB.ToString();
		}
		catch (Exception eX)
		{
			return eX.Message;
		}
	}

	/// <summary>
	/// Return a string describing the HTTPS connection security, if this socket is secured
	/// </summary>
	/// <returns>A string describing the HTTPS connection's security.</returns>
	public string DescribeConnectionSecurity()
	{
		if (_httpsStream != null)
		{
			string sClientCertificate = string.Empty;
			if (_httpsStream.IsMutuallyAuthenticated)
			{
				sClientCertificate = "== Client Certificate ==========\nUnknown.\n";
			}
			if (_httpsStream.LocalCertificate != null)
			{
				sClientCertificate = "\n== Client Certificate ==========\n" + _httpsStream.LocalCertificate.ToString(fVerbose: true) + "\n";
			}
			StringBuilder oSB = new StringBuilder(2048);
			oSB.AppendFormat("Secure Protocol: {0}\n", _httpsStream.SslProtocol.ToString());
			oSB.AppendFormat("Cipher: {0}\n", GetConnectionCipherInfo());
			oSB.AppendFormat("Hash Algorithm: {0}\n", GetConnectionHashInfo());
			oSB.AppendFormat("Key Exchange: {0}\n", GetConnectionKeyExchangeInfo());
			oSB.Append(sClientCertificate);
			oSB.AppendLine("\n== Server Certificate ==========");
			try
			{
				oSB.AppendLine(_httpsStream.RemoteCertificate.ToString(fVerbose: true));
				X509Certificate2 cert = new X509Certificate2(_httpsStream.RemoteCertificate);
				string subjectAltNamesHeader = "[SubjectAltNames]\n";
				string altNames = CertInfo.GetSubjectAltNames(cert);
				if (!string.IsNullOrEmpty(altNames))
				{
					oSB.AppendLine(subjectAltNamesHeader + altNames);
				}
			}
			catch
			{
			}
			if (FiddlerApplication.Prefs.GetBoolPref("fiddler.network.https.storeservercertchain", bDefault: false))
			{
				oSB.AppendFormat("[Chain]\n {0}\n", GetServerCertChain());
			}
			return oSB.ToString();
		}
		return "No connection security";
	}

	/// <summary>
	/// Returns a string describing how this connection is secured.
	/// </summary>
	/// <returns></returns>
	internal string GetConnectionCipherInfo()
	{
		return GetConnectionInfo(() => _httpsStream.CipherAlgorithm.ToString(), () => _httpsStream.CipherStrength.ToString());
	}

	private string GetConnectionHashInfo()
	{
		return GetConnectionInfo(delegate
		{
			string text2 = _httpsStream.HashAlgorithm.ToString();
			if (text2 == "32780")
			{
				text2 = "Sha256";
			}
			else if (text2 == "32781")
			{
				text2 = "Sha384";
			}
			return text2;
		}, delegate
		{
			string text = _httpsStream.HashStrength.ToString();
			if ("0" == text)
			{
				text = "?";
			}
			return text;
		});
	}

	private string GetConnectionKeyExchangeInfo()
	{
		return GetConnectionInfo(delegate
		{
			string text = _httpsStream.KeyExchangeAlgorithm.ToString();
			if (text == "44550")
			{
				text = "ECDHE_RSA (0xae06)";
			}
			return text;
		}, () => _httpsStream.KeyExchangeStrength.ToString());
	}

	private string GetConnectionInfo(Func<string> getAlgorithm, Func<string> getStrength)
	{
		if (_httpsStream == null)
		{
			return "<none>";
		}
		string algorithm;
		try
		{
			algorithm = getAlgorithm();
		}
		catch (NotImplementedException)
		{
			return "Your tls implementation does not provide this information";
		}
		catch (Exception ex3)
		{
			if (ex3 == null)
			{
				return "Error";
			}
			return ex3.ToString();
		}
		string strength;
		try
		{
			strength = getStrength();
		}
		catch (Exception)
		{
			strength = "?";
		}
		return $"{algorithm} {strength}bits";
	}

	/// <summary>
	/// Get the Transport Context for the underlying HTTPS connection so that Channel-Binding Tokens work correctly
	/// </summary>
	/// <returns></returns>
	internal TransportContext _GetTransportContext()
	{
		if (_httpsStream != null)
		{
			return _httpsStream.TransportContext;
		}
		return null;
	}

	private static bool ConfirmServerCertificate(Session oS, string sExpectedCN, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
	{
		CertificateValidity oCV = CertificateValidity.Default;
		FiddlerApplication.CheckOverrideCertificatePolicy(oS, sExpectedCN, certificate, chain, sslPolicyErrors, ref oCV);
		if (oCV == CertificateValidity.ForceInvalid)
		{
			return false;
		}
		if (oCV == CertificateValidity.ForceValid)
		{
			return true;
		}
		if ((oCV != CertificateValidity.ConfirmWithUser && (sslPolicyErrors == SslPolicyErrors.None || CONFIG.IgnoreServerCertErrors)) || oS.oFlags.ContainsKey("X-IgnoreCertErrors"))
		{
			return true;
		}
		if ((sslPolicyErrors & SslPolicyErrors.RemoteCertificateNameMismatch) == SslPolicyErrors.RemoteCertificateNameMismatch && oS.oFlags.ContainsKey("X-IgnoreCertCNMismatch"))
		{
			sslPolicyErrors &= ~SslPolicyErrors.RemoteCertificateNameMismatch;
			if (sslPolicyErrors == SslPolicyErrors.None)
			{
				return true;
			}
		}
		return false;
	}

	/// <summary>
	/// Get the user's default client cert for authentication; caching if if possible and permitted.
	/// </summary>
	/// <returns></returns>
	private static X509Certificate _GetDefaultCertificate()
	{
		if (FiddlerApplication.oDefaultClientCertificate != null)
		{
			return FiddlerApplication.oDefaultClientCertificate;
		}
		X509Certificate oCert = null;
		if (File.Exists(CONFIG.GetPath("DefaultClientCertificate")))
		{
			oCert = X509Certificate.CreateFromCertFile(CONFIG.GetPath("DefaultClientCertificate"));
			if (oCert == null)
			{
				return null;
			}
			if (FiddlerApplication.Prefs.GetBoolPref("fiddler.network.https.cacheclientcert", bDefault: true))
			{
				FiddlerApplication.oDefaultClientCertificate = oCert;
			}
		}
		return oCert;
	}

	/// <summary>
	/// This method is called by the HTTPS Connection establishment to optionally attach a client certificate to the request.
	/// Test Page: https://tower.dartmouth.edu/doip/OracleDatabases.jspx or ClientCertificate.ms in Test folder should request on initial connection
	/// In contrast, this one: https://roaming.officeapps.live.com/rs/roamingsoapservice.svc appears to try twice (renego)
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="targetHost"></param>
	/// <param name="localCertificates"></param>
	/// <param name="remoteCertificate"></param>
	/// <param name="acceptableIssuers"></param>
	/// <returns></returns>
	private X509Certificate AttachClientCertificate(Session oS, object sender, string targetHost, X509CertificateCollection localCertificates, X509Certificate remoteCertificate, string[] acceptableIssuers)
	{
		if (CONFIG.bDebugSpew)
		{
			FiddlerApplication.Log.LogFormat("fiddler.network.https.clientcertificate>AttachClientCertificate {0} - {1}, {2} local certs, {3} acceptable issuers.", targetHost, (remoteCertificate != null) ? remoteCertificate.Subject.ToString() : "NoRemoteCert", (localCertificates != null) ? localCertificates.Count.ToString() : "(null)", (acceptableIssuers != null) ? acceptableIssuers.Length.ToString() : "(null)");
		}
		if (localCertificates.Count > 0)
		{
			MarkAsAuthenticated(oS.LocalProcessID);
			oS.oFlags["x-client-cert"] = localCertificates[0].Subject + " Serial#" + localCertificates[0].GetSerialNumberString();
			return localCertificates[0];
		}
		if (FiddlerApplication.ClientCertificateProvider != null)
		{
			X509Certificate oCert = FiddlerApplication.ClientCertificateProvider(oS, targetHost, localCertificates, remoteCertificate, acceptableIssuers);
			if (oCert == null)
			{
				return null;
			}
			if (CONFIG.bDebugSpew)
			{
				FiddlerApplication.DebugSpew("Session #{0} Attaching client certificate '{1}' when connecting to host '{2}'", oS.id, oCert.Subject, targetHost);
			}
			MarkAsAuthenticated(oS.LocalProcessID);
			oS.oFlags["x-client-cert"] = oCert.Subject + " Serial#" + oCert.GetSerialNumberString();
			return oCert;
		}
		bool bSawHintsServerSentCertRequest = remoteCertificate != null || acceptableIssuers.Length != 0;
		X509Certificate oDefaultCert = _GetDefaultCertificate();
		if (oDefaultCert != null)
		{
			if (bSawHintsServerSentCertRequest)
			{
				MarkAsAuthenticated(oS.LocalProcessID);
			}
			oS.oFlags["x-client-cert"] = oDefaultCert.Subject + " Serial#" + oDefaultCert.GetSerialNumberString();
			return oDefaultCert;
		}
		if (bSawHintsServerSentCertRequest)
		{
			FiddlerApplication.Log.LogFormat("The server [{0}] requested a client certificate, but no client certificate was available.", targetHost);
			if (CONFIG.bShowDefaultClientCertificateNeededPrompt && FiddlerApplication.Prefs.GetBoolPref("fiddler.network.https.clientcertificate.ephemeral.prompt-for-missing", bDefault: true))
			{
				FiddlerApplication.Prefs.SetBoolPref("fiddler.network.https.clientcertificate.ephemeral.prompt-for-missing", bValue: false);
				string messageTitle = "Client Certificate Requested";
				string messageContent = "The server [" + targetHost + "] requests a client certificate.\nPlease save a client certificate using the filename:\n\n" + CONFIG.GetPath("DefaultClientCertificate");
				FiddlerApplication.Log.LogFormat("{0}: {1}", messageTitle, messageContent);
			}
		}
		return null;
	}

	/// <summary>
	/// This function secures an existing connection and authenticates as client. This is primarily useful when
	/// the socket is connected to a Gateway/Proxy and we had to send a CONNECT and get a HTTP/200 Connected back before
	/// we actually secure the socket.
	///  http://msdn.microsoft.com/en-us/library/system.net.security.sslstream.aspx
	/// </summary>
	/// <param name="oS">The Session (a CONNECT) this tunnel wraps</param>
	/// <param name="sCertCN">The CN to use in the certificate</param>
	/// <param name="sClientCertificateFilename">Path to client certificate file</param>
	/// <param name="sslprotClient">The HTTPS protocol version of the Client Pipe; can influence which SslProtocols we offer the server</param>
	/// <param name="iHandshakeTime">Reference-passed integer which returns the time spent securing the connection</param>
	/// <returns>TRUE if the connection can be secued</returns>
	internal bool SecureExistingConnection(Session oS, string sCertCN, string sClientCertificateFilename, SslProtocols sslprotClient, ref int iHandshakeTime)
	{
		sPoolKey = sPoolKey.Replace("->http/", "->https/");
		if (sPoolKey.EndsWith("->*"))
		{
			sPoolKey = sPoolKey.Replace("->*", $"->https/{oS.hostname}:{oS.port}");
		}
		X509CertificateCollection oClientCerts = GetCertificateCollectionFromFile(sClientCertificateFilename);
		Stopwatch oSW = Stopwatch.StartNew();
		try
		{
			Stream strmNet = new NetworkStream(_baseSocket, ownsSocket: false);
			if (_bEatTLSAlerts || oS.oFlags.ContainsKey("https-DropSNIAlerts"))
			{
				strmNet = new TLSAlertEatingStream(strmNet, oS.host);
			}
			_httpsStream = new SslStream(strmNet, leaveInnerStreamOpen: false, delegate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
			{
				try
				{
					_certServer = new X509Certificate2(certificate);
				}
				catch (Exception)
				{
				}
				return ConfirmServerCertificate(oS, sCertCN, certificate, chain, sslPolicyErrors);
			}, (object sender, string targetHost, X509CertificateCollection localCertificates, X509Certificate remoteCertificate, string[] acceptableIssuers) => AttachClientCertificate(oS, sender, targetHost, localCertificates, remoteCertificate, acceptableIssuers));
			SslProtocols oAcceptedProtocols = CONFIG.oAcceptedServerHTTPSProtocols;
			if (oS.oFlags.ContainsKey("x-OverrideSslProtocols"))
			{
				oAcceptedProtocols = Utilities.ParseSSLProtocolString(oS.oFlags["x-OverrideSslProtocols"]);
			}
			else if (CONFIG.bMimicClientHTTPSProtocols && sslprotClient != 0)
			{
				oAcceptedProtocols |= sslprotClient;
			}
			oAcceptedProtocols = SslProtocolsFilter.RemoveNotAllowedSecurityProtocols(oAcceptedProtocols);
			oAcceptedProtocols = SslProtocolsFilter.EnsureConsecutiveProtocols(oAcceptedProtocols);
			_httpsStream.AuthenticateAsClient(sCertCN, oClientCerts, oAcceptedProtocols, FiddlerApplication.Prefs.GetBoolPref("fiddler.network.https.checkcertificaterevocation", bDefault: false));
			iHandshakeTime = (int)oSW.ElapsedMilliseconds;
		}
		catch (Exception eX)
		{
			iHandshakeTime = (int)oSW.ElapsedMilliseconds;
			FiddlerApplication.DebugSpew("SecureExistingConnection failed: {0}\n{1}", FiddlerCore.Utilities.Utilities.DescribeException(eX), eX.StackTrace);
			string sError = $"fiddler.network.https> HTTPS handshake to {sCertCN} (for #{oS.id}) failed. {FiddlerCore.Utilities.Utilities.DescribeException(eX)}\n\n";
			if (eX is CryptographicException && FiddlerApplication.oDefaultClientCertificate != null)
			{
				sError += "NOTE: A ClientCertificate was supplied. Make certain that the certificate is valid and its public key is accessible in the current user account.\n";
			}
			if (eX is AuthenticationException && eX.InnerException != null && eX.InnerException is Win32Exception)
			{
				Win32Exception exWin32 = (Win32Exception)eX.InnerException;
				if (exWin32.NativeErrorCode == -2146893007)
				{
					sError = sError + "HTTPS handshake returned error SEC_E_ALGORITHM_MISMATCH.\nFiddler's Enabled HTTPS Protocols: [" + CONFIG.oAcceptedServerHTTPSProtocols.ToString() + "] are controlled inside Tools > Options > HTTPS.";
					if (oS.oFlags.ContainsKey("x-OverrideSslProtocols"))
					{
						sError = sError + "\nThis connection specified X-OverrideSslProtocols: " + oS.oFlags["x-OverrideSslProtocols"];
					}
				}
				else
				{
					sError = sError + "Win32 (SChannel) Native Error Code: 0x" + exWin32.NativeErrorCode.ToString("x");
				}
			}
			if (Utilities.IsNullOrEmpty(oS.responseBodyBytes))
			{
				oS.responseBodyBytes = Encoding.UTF8.GetBytes(sError);
			}
			FiddlerApplication.Log.LogString(sError);
			return false;
		}
		return true;
	}

	/// <summary>
	/// Return a Certificate Collection containing certificate from the specified file. 
	/// </summary>
	/// <param name="sClientCertificateFilename">Path to the certificate. Relative Paths will be absolutified automatically</param>
	/// <returns>The Certificate collection, or null</returns>
	private static X509CertificateCollection GetCertificateCollectionFromFile(string sClientCertificateFilename)
	{
		if (string.IsNullOrEmpty(sClientCertificateFilename))
		{
			return null;
		}
		X509CertificateCollection oReturnCollection = null;
		try
		{
			sClientCertificateFilename = Utilities.EnsurePathIsAbsolute(CONFIG.GetPath("Root"), sClientCertificateFilename);
			if (File.Exists(sClientCertificateFilename))
			{
				oReturnCollection = new X509CertificateCollection();
				oReturnCollection.Add(X509Certificate.CreateFromCertFile(sClientCertificateFilename));
			}
			else
			{
				FiddlerApplication.Log.LogFormat("!! ERROR: Specified client certificate file '{0}' does not exist.", sClientCertificateFilename);
			}
		}
		catch (Exception eX)
		{
			string title = "Failed to GetCertificateCollection from " + sClientCertificateFilename;
			FiddlerApplication.Log.LogFormat("{0}: {1}", title, eX.ToString());
		}
		return oReturnCollection;
	}
}
