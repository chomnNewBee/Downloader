using System;
using System.Net.Sockets;
using System.Threading;

namespace Fiddler;

/// <summary>
/// The GenericTunnel class represents a "blind tunnel" to shuffle bytes between a client and the server.
/// </summary>
internal class GenericTunnel : ITunnel
{
	private ClientPipe pipeToClient;

	private ServerPipe pipeToRemote;

	/// <summary>
	/// Is streaming started in the downstream direction?
	/// </summary>
	private bool bResponseStreamStarted = false;

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
	internal static void CreateTunnel(Session oSession, bool bStreamResponse)
	{
		if (oSession == null || oSession.oRequest == null || oSession.oRequest.headers == null || oSession.oRequest.pipeClient == null || oSession.oResponse == null)
		{
			return;
		}
		ClientPipe oPC = oSession.oRequest.pipeClient;
		if (oPC == null)
		{
			return;
		}
		if (bStreamResponse)
		{
			oSession.oRequest.pipeClient = null;
		}
		ServerPipe oPS = oSession.oResponse.pipeServer;
		if (oPS != null)
		{
			if (bStreamResponse)
			{
				oSession.oResponse.pipeServer = null;
			}
			Thread oNewThread = new Thread(((GenericTunnel)(oSession.__oTunnel = new GenericTunnel(oSession, oPC, oPS, bStreamResponse))).RunTunnel);
			oNewThread.IsBackground = true;
			oNewThread.Start();
		}
	}

	/// <summary>
	/// Creates a tunnel. External callers instead use the CreateTunnel static method.
	/// </summary>
	/// <param name="oSess">The session for which this tunnel was initially created.</param>
	/// <param name="oFrom">Client Pipe</param>
	/// <param name="oTo">Server Pipe</param>
	private GenericTunnel(Session oSess, ClientPipe oFrom, ServerPipe oTo, bool bStreamResponse)
	{
		_mySession = oSess;
		pipeToClient = oFrom;
		pipeToRemote = oTo;
		bResponseStreamStarted = bStreamResponse;
		_mySession.SetBitFlag(SessionFlags.IsBlindTunnel, b: true);
		FiddlerApplication.DebugSpew("[GenericTunnel] For session #" + _mySession.id + " created...");
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
		FiddlerApplication.DebugSpew("[GenericTunnel] Blocking thread...");
		oKeepTunnelAlive.WaitOne();
		FiddlerApplication.DebugSpew("[GenericTunnel] Unblocking thread...");
		oKeepTunnelAlive.Close();
		oKeepTunnelAlive = null;
		bIsOpen = false;
		arrRequestBytes = (arrResponseBytes = null);
		pipeToClient = null;
		pipeToRemote = null;
		FiddlerApplication.DebugSpew("[GenericTunnel] Thread for session #" + _mySession.id + " has died...");
		if (_mySession.oResponse != null && _mySession.oResponse.headers != null)
		{
			_mySession.oResponse.headers["EndTime"] = DateTime.Now.ToString("HH:mm:ss.fff");
			_mySession.oResponse.headers["ClientToServerBytes"] = _lngEgressByteCount.ToString();
			_mySession.oResponse.headers["ServerToClientBytes"] = _lngIngressByteCount.ToString();
		}
		_mySession.Timers.ServerDoneResponse = (_mySession.Timers.ClientBeginResponse = (_mySession.Timers.ClientDoneResponse = DateTime.Now));
		_mySession.state = SessionStates.Done;
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

	/// <summary>
	/// Executes the WebSocket tunnel on a background thread
	/// </summary>
	private void DoTunnel()
	{
		if (FiddlerApplication.oProxy == null)
		{
			return;
		}
		arrRequestBytes = new byte[16384];
		arrResponseBytes = new byte[16384];
		bIsOpen = true;
		if (CONFIG.bDebugSpew)
		{
			FiddlerApplication.DebugSpew(string.Format("Generic Tunnel for Session #{0}, Response State: {1}, created between\n\t{2}\nand\n\t{3}", _mySession.id, bResponseStreamStarted ? "Streaming" : "Blocked", pipeToClient, pipeToRemote));
		}
		try
		{
			pipeToClient.BeginReceive(arrRequestBytes, 0, arrRequestBytes.Length, SocketFlags.None, OnClientReceive, null);
			if (bResponseStreamStarted)
			{
				pipeToRemote.BeginReceive(arrResponseBytes, 0, arrResponseBytes.Length, SocketFlags.None, OnRemoteReceive, null);
			}
			WaitForCompletion();
		}
		catch (Exception)
		{
		}
		CloseTunnel();
	}

	/// <summary>
	/// Instructs the tunnel to take over the server pipe and begin streaming responses to the client
	/// </summary>
	internal void BeginResponseStreaming()
	{
		FiddlerApplication.DebugSpew(">>> Begin response streaming in GenericTunnel for Session #" + _mySession.id);
		bResponseStreamStarted = true;
		_mySession.oResponse.pipeServer = null;
		_mySession.oRequest.pipeClient = null;
		pipeToRemote.BeginReceive(arrResponseBytes, 0, arrResponseBytes.Length, SocketFlags.None, OnRemoteReceive, null);
	}

	/// <summary>
	/// Close the HTTPS tunnel and signal the event to let the service thread die.
	/// WARNING: This MUST not be allowed to throw any exceptions, because it will do so on threads that don't catch them, and this will kill the application.
	/// </summary>
	public void CloseTunnel()
	{
		FiddlerApplication.DebugSpew("Close Generic Tunnel for Session #" + ((_mySession != null) ? _mySession.id.ToString() : "<unassigned>"));
		try
		{
			if (pipeToClient != null)
			{
				pipeToClient.End();
			}
		}
		catch (Exception eX2)
		{
			FiddlerApplication.DebugSpew("Error closing gatewayFrom tunnel. " + eX2.Message + "\n" + eX2.StackTrace);
		}
		try
		{
			if (pipeToRemote != null)
			{
				pipeToRemote.End();
			}
		}
		catch (Exception eX3)
		{
			FiddlerApplication.DebugSpew("Error closing gatewayTo tunnel. " + eX3.Message + "\n" + eX3.StackTrace);
		}
		try
		{
			if (oKeepTunnelAlive != null)
			{
				oKeepTunnelAlive.Set();
			}
		}
		catch (Exception eX)
		{
			FiddlerApplication.DebugSpew("Error closing oKeepTunnelAlive. " + eX.Message + "\n" + eX.StackTrace);
		}
	}

	/// <summary>
	///  Called when we have received data from the local client.
	///  Incoming data will immediately be forwarded to the remote host.
	/// </summary>
	/// <param name="ar">The result of the asynchronous operation.</param>
	protected void OnClientReceive(IAsyncResult ar)
	{
		try
		{
			int Ret = pipeToClient.EndReceive(ar);
			if (Ret > 0)
			{
				_lngEgressByteCount += Ret;
				if (CONFIG.bDebugSpew)
				{
					FiddlerApplication.DebugSpew("[GenericTunnel] Received from client: " + Ret + " bytes. Sending to server...");
					FiddlerApplication.DebugSpew(Utilities.ByteArrayToHexView(arrRequestBytes, 16, Ret));
				}
				FiddlerApplication.DoReadRequestBuffer(_mySession, arrRequestBytes, Ret);
				pipeToRemote.Send(arrRequestBytes, 0, Ret);
				pipeToClient.BeginReceive(arrRequestBytes, 0, arrRequestBytes.Length, SocketFlags.None, OnClientReceive, null);
			}
			else
			{
				FiddlerApplication.DoReadRequestBuffer(_mySession, arrRequestBytes, 0);
				CloseTunnel();
			}
		}
		catch (Exception eX)
		{
			FiddlerApplication.DebugSpew("[GenericTunnel] OnClientReceive threw... " + eX.Message);
			CloseTunnel();
		}
	}

	/// <summary>Called when we have sent data to the local client.<br>When all the data has been sent, we will start receiving again from the remote host.</br></summary>
	/// <param name="ar">The result of the asynchronous operation.</param>
	protected void OnClientSent(IAsyncResult ar)
	{
		try
		{
			FiddlerApplication.DebugSpew("OnClientSent...");
			pipeToClient.EndSend(ar);
		}
		catch (Exception eX)
		{
			FiddlerApplication.DebugSpew("[GenericTunnel] OnClientSent failed... " + eX.Message);
			CloseTunnel();
		}
	}

	/// <summary>Called when we have sent data to the remote host.<br>When all the data has been sent, we will start receiving again from the local client.</br></summary>
	/// <param name="ar">The result of the asynchronous operation.</param>
	protected void OnRemoteSent(IAsyncResult ar)
	{
		try
		{
			FiddlerApplication.DebugSpew("OnRemoteSent...");
			pipeToRemote.EndSend(ar);
		}
		catch (Exception eX)
		{
			FiddlerApplication.DebugSpew("[GenericTunnel] OnRemoteSent failed... " + eX.Message);
			CloseTunnel();
		}
	}

	/// <summary>Called when we have received data from the remote host.<br>Incoming data will immediately be forwarded to the local client.</br></summary>
	/// <param name="ar">The result of the asynchronous operation.</param>
	protected void OnRemoteReceive(IAsyncResult ar)
	{
		try
		{
			int Ret = pipeToRemote.EndReceive(ar);
			if (Ret > 0)
			{
				_lngIngressByteCount += Ret;
				if (CONFIG.bDebugSpew)
				{
					FiddlerApplication.DebugSpew("[GenericTunnel] Received from server: " + Ret + " bytes. Sending to client...");
					FiddlerApplication.DebugSpew(Utilities.ByteArrayToHexView(arrResponseBytes, 16, Ret));
				}
				FiddlerApplication.DoReadResponseBuffer(_mySession, arrResponseBytes, Ret);
				pipeToClient.Send(arrResponseBytes, 0, Ret);
				pipeToRemote.BeginReceive(arrResponseBytes, 0, arrResponseBytes.Length, SocketFlags.None, OnRemoteReceive, null);
			}
			else
			{
				FiddlerApplication.DebugSpew("[GenericTunnel] ReadFromRemote failed, ret=" + Ret);
				FiddlerApplication.DoReadResponseBuffer(_mySession, arrResponseBytes, 0);
				CloseTunnel();
			}
		}
		catch (Exception eX)
		{
			FiddlerApplication.DebugSpew("[GenericTunnel] OnRemoteReceive failed... " + eX.Message);
			CloseTunnel();
		}
	}
}
