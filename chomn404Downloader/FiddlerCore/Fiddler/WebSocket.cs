using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace Fiddler;

/// <summary>
/// The WebSocket class represents a "tunnel" through which WebSocket messages flow.
/// The class' messages may be deserialized from a SAZ file.
/// </summary>
public class WebSocket : ITunnel
{
	private ClientPipe oCP;

	private ServerPipe oSP;

	private Session _mySession;

	private string sName = "Unknown";

	private byte[] arrRequestBytes;

	private byte[] arrResponseBytes;

	private int _iMsgCount;

	private MemoryStream strmClientBytes;

	private MemoryStream strmServerBytes;

	public List<WebSocketMessage> listMessages;

	private AutoResetEvent oKeepTunnelAlive;

	/// <summary>
	/// Should this WebSocket Tunnel parse the WS traffic within into individual messages?
	/// </summary>
	private bool bParseMessages = FiddlerApplication.Prefs.GetBoolPref("fiddler.websocket.ParseMessages", bDefault: true);

	private bool bIsOpen;

	/// <summary>
	/// Number of bytes received from the client
	/// </summary>
	private long _lngEgressByteCount;

	/// <summary>
	/// Number of bytes received from the server
	/// </summary>
	private long _lngIngressByteCount;

	public int MessageCount
	{
		get
		{
			if (listMessages == null)
			{
				return 0;
			}
			return listMessages.Count;
		}
	}

	/// <summary>
	/// Is this WebSocket open/connected?
	/// </summary>
	public bool IsOpen => bIsOpen;

	/// <summary>
	/// Boolean that determines whether the WebSocket tunnel tracks messages.
	/// </summary>
	internal bool IsBlind
	{
		get
		{
			return !bParseMessages;
		}
		set
		{
			bParseMessages = !value;
		}
	}

	/// <summary>
	/// Returns number of bytes sent from the Server to the Client on this WebSocket
	/// </summary>
	public long IngressByteCount => _lngIngressByteCount;

	/// <summary>
	/// Returns number of bytes sent from the Client to the Server on this WebSocket
	/// </summary>
	public long EgressByteCount => _lngEgressByteCount;

	internal void UnfragmentMessages()
	{
		if (listMessages == null)
		{
			return;
		}
		List<WebSocketMessage> listFinal = new List<WebSocketMessage>();
		WebSocketMessage wsmPriorInbound = null;
		WebSocketMessage wsmPriorOutbound = null;
		lock (listMessages)
		{
			foreach (WebSocketMessage oWSM in listMessages)
			{
				if (oWSM.FrameType != 0)
				{
					if (oWSM.IsOutbound)
					{
						wsmPriorOutbound = oWSM;
					}
					else
					{
						wsmPriorInbound = oWSM;
					}
					listFinal.Add(oWSM);
				}
				else if (oWSM.IsOutbound)
				{
					if (wsmPriorOutbound == null)
					{
						listFinal.Add(oWSM);
						wsmPriorOutbound = oWSM;
					}
					else
					{
						wsmPriorOutbound.Assemble(oWSM);
					}
				}
				else if (wsmPriorInbound == null)
				{
					listFinal.Add(oWSM);
					wsmPriorInbound = oWSM;
				}
				else
				{
					wsmPriorInbound.Assemble(oWSM);
				}
			}
		}
		listMessages = listFinal;
	}

	/// <summary>
	/// Writes all of the messages stored in this WebSocket to a stream.
	/// </summary>
	/// <param name="oFS"></param>
	/// <returns></returns>
	internal bool WriteWebSocketMessageListToStream(Stream oFS)
	{
		oFS.WriteByte(13);
		oFS.WriteByte(10);
		if (listMessages != null)
		{
			lock (listMessages)
			{
				foreach (WebSocketMessage oWSM in listMessages)
				{
					oWSM.SerializeToStream(oFS);
				}
			}
		}
		return true;
	}

	/// <summary>
	/// Approximate size of the data of the stored messages, used for memory tracking
	/// </summary>
	/// <returns></returns>
	internal int MemoryUsage()
	{
		int i = 0;
		if (listMessages != null)
		{
			lock (listMessages)
			{
				foreach (WebSocketMessage oWSM in listMessages)
				{
					i += 12 + oWSM.PayloadLength;
				}
			}
		}
		return i;
	}

	/// <summary>
	/// Read headers from the stream.
	/// </summary>
	/// <param name="oFS">The Stream from which WebSocketSerializationHeaders should be read</param>
	/// <returns>The Array of headers, or String[0]</returns>
	private static string[] _ReadHeadersFromStream(Stream oFS)
	{
		List<byte> oHeaderBytes = new List<byte>();
		bool bAtCR = false;
		bool bAtCRLF = true;
		int iByte = oFS.ReadByte();
		while (-1 != iByte)
		{
			if (iByte == 13)
			{
				bAtCR = true;
			}
			else if (bAtCR && iByte == 10)
			{
				if (bAtCRLF)
				{
					break;
				}
				bAtCRLF = true;
				oHeaderBytes.Add(13);
				oHeaderBytes.Add(10);
			}
			else
			{
				bAtCR = (bAtCRLF = false);
				oHeaderBytes.Add((byte)iByte);
			}
			iByte = oFS.ReadByte();
		}
		string sHeaders = Encoding.ASCII.GetString(oHeaderBytes.ToArray());
		return sHeaders.Split(new string[1] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries);
	}

	private static DateTime _GetDateTime(string sDateTimeStr)
	{
		if (!DateTime.TryParseExact(sDateTimeStr, "o", CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var dtResult))
		{
			dtResult = new DateTime(0L);
		}
		return dtResult;
	}

	internal bool ReadWebSocketMessageListFromStream(Stream oFS)
	{
		try
		{
			string[] slHeaders = _ReadHeadersFromStream(oFS);
			List<WebSocketMessage> oMsgs = new List<WebSocketMessage>();
			slHeaders = _ReadHeadersFromStream(oFS);
			while (slHeaders != null && slHeaders.Length != 0)
			{
				int iSize = 0;
				bool bIsRequest = false;
				DateTime dtDoneRead = new DateTime(0L);
				DateTime dtBeginSend = new DateTime(0L);
				DateTime dtDoneSend = new DateTime(0L);
				WSMFlags wsmfBitFlags = WSMFlags.None;
				string[] array = slHeaders;
				foreach (string sHeader in array)
				{
					if (sHeader.StartsWith("Request-Length:"))
					{
						bIsRequest = true;
						iSize = int.Parse(sHeader.Substring(16));
					}
					else if (sHeader.StartsWith("Response-Length:"))
					{
						bIsRequest = false;
						iSize = int.Parse(sHeader.Substring(17));
					}
					else if (sHeader.StartsWith("DoneRead:"))
					{
						dtDoneRead = _GetDateTime(sHeader.Substring(10));
					}
					else if (sHeader.StartsWith("BeginSend:"))
					{
						dtBeginSend = _GetDateTime(sHeader.Substring(11));
					}
					else if (sHeader.StartsWith("DoneSend:"))
					{
						dtDoneSend = _GetDateTime(sHeader.Substring(10));
					}
					else if (sHeader.StartsWith("BitFlags:"))
					{
						wsmfBitFlags = (WSMFlags)int.Parse(sHeader.Substring(9));
					}
				}
				if (iSize < 1)
				{
					throw new InvalidDataException("Missing size indication.");
				}
				byte[] arrData = new byte[iSize];
				oFS.Read(arrData, 0, iSize);
				MemoryStream oMS = new MemoryStream(arrData);
				WebSocketMessage[] arrWSM = _ParseMessagesFromStream(this, ref oMS, bIsRequest, bTrimAfterParsing: false);
				if (arrWSM.Length == 1)
				{
					if (dtDoneRead.Ticks > 0)
					{
						arrWSM[0].Timers.dtDoneRead = dtDoneRead;
					}
					if (dtBeginSend.Ticks > 0)
					{
						arrWSM[0].Timers.dtBeginSend = dtBeginSend;
					}
					if (dtDoneSend.Ticks > 0)
					{
						arrWSM[0].Timers.dtDoneSend = dtDoneSend;
					}
					arrWSM[0].SetBitFlags(wsmfBitFlags);
					oMsgs.Add(arrWSM[0]);
				}
				slHeaders = ((-1 != oFS.ReadByte() && -1 != oFS.ReadByte()) ? _ReadHeadersFromStream(oFS) : null);
			}
			listMessages = oMsgs;
			return true;
		}
		catch (Exception)
		{
			return false;
		}
	}

	public override string ToString()
	{
		return $"Session{((_mySession == null) ? (-1) : _mySession.id)}.WebSocket'{sName}'";
	}

	/// <summary>
	/// Creates a "detached" WebSocket which contains messages loaded from the specified stream
	/// </summary>
	/// <param name="oS">Session to which the WebSocket messages belong</param>
	/// <param name="strmWSMessages">The Stream containing messages, which will be closed upon completion</param>
	internal static void LoadWebSocketMessagesFromStream(Session oS, Stream strmWSMessages)
	{
		try
		{
			WebSocket oNewTunnel = new WebSocket(oS, null, null);
			oNewTunnel.sName = $"SAZ-Session#{oS.id}";
			oS.__oTunnel = oNewTunnel;
			oNewTunnel.ReadWebSocketMessageListFromStream(strmWSMessages);
		}
		finally
		{
			strmWSMessages.Dispose();
		}
	}

	/// <summary>
	/// This factory method creates a new WebSocket Tunnel and executes it on a background (non-pooled) thread.
	/// </summary>
	/// <param name="oSession">The Session containing the HTTP CONNECT request</param>
	internal static void CreateTunnel(Session oSession)
	{
		if (oSession != null && oSession.oRequest != null && oSession.oRequest.headers != null && oSession.oRequest.pipeClient != null && oSession.oResponse != null && oSession.oResponse.pipeServer != null)
		{
			ClientPipe oFrom = oSession.oRequest.pipeClient;
			oSession.oRequest.pipeClient = null;
			ServerPipe oTo = oSession.oResponse.pipeServer;
			oSession.oResponse.pipeServer = null;
			Thread oNewThread = new Thread(((WebSocket)(oSession.__oTunnel = new WebSocket(oSession, oFrom, oTo))).RunTunnel);
			oNewThread.IsBackground = true;
			oNewThread.Start();
		}
	}

	/// <summary>
	/// Creates a WebSocket tunnel. External callers instead use the CreateTunnel static method.
	/// </summary>
	/// <param name="oSess">The session for which this tunnel was initially created.</param>
	/// <param name="oFrom">The client pipe</param>
	/// <param name="oTo">The server pipe</param>
	private WebSocket(Session oSess, ClientPipe oFrom, ServerPipe oTo)
	{
		sName = "WebSocket #" + oSess.id;
		_mySession = oSess;
		oCP = oFrom;
		oSP = oTo;
		_mySession.SetBitFlag(SessionFlags.IsWebSocketTunnel, b: true);
		if (_mySession.isAnyFlagSet(SessionFlags.Ignored) || oSess.oFlags.ContainsKey("x-no-parse"))
		{
			bParseMessages = false;
		}
		else if (oSess.oFlags.ContainsKey("x-Parse-WebSocketMessages"))
		{
			bParseMessages = true;
		}
	}

	/// <summary>
	/// This function keeps the Tunnel/Thread alive until it is signaled that the traffic is complete
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
	}

	/// <summary>
	/// Performs cleanup of the WebSocket instance. Call this after the WebSocket closes normally or after abort/exceptions.
	/// </summary>
	private void _CleanupWebSocket()
	{
		bIsOpen = false;
		arrRequestBytes = (arrResponseBytes = null);
		strmServerBytes = null;
		strmClientBytes = null;
		if (oCP != null)
		{
			oCP.End();
		}
		if (oSP != null)
		{
			oSP.End();
		}
		oCP = null;
		oSP = null;
		if (_mySession != null)
		{
			if (Utilities.HasHeaders(_mySession.oResponse))
			{
				_mySession.oResponse.headers["EndTime"] = DateTime.Now.ToString("HH:mm:ss.fff");
				_mySession.oResponse.headers["ReceivedBytes"] = _lngIngressByteCount.ToString();
				_mySession.oResponse.headers["SentBytes"] = _lngEgressByteCount.ToString();
			}
			_mySession.Timers.ServerDoneResponse = (_mySession.Timers.ClientBeginResponse = (_mySession.Timers.ClientDoneResponse = DateTime.Now));
			_mySession = null;
		}
	}

	/// <summary>
	/// Executes the WebSocket tunnel on a background thread
	/// </summary>
	private void RunTunnel()
	{
		if (FiddlerApplication.oProxy != null)
		{
			arrRequestBytes = new byte[16384];
			arrResponseBytes = new byte[16384];
			if (bParseMessages)
			{
				strmClientBytes = new MemoryStream();
				strmServerBytes = new MemoryStream();
				listMessages = new List<WebSocketMessage>();
			}
			bIsOpen = true;
			try
			{
				oCP.BeginReceive(arrRequestBytes, 0, arrRequestBytes.Length, SocketFlags.None, OnReceiveFromClient, oCP);
				oSP.BeginReceive(arrResponseBytes, 0, arrResponseBytes.Length, SocketFlags.None, OnReceiveFromServer, oSP);
				WaitForCompletion();
			}
			catch (Exception)
			{
			}
			CloseTunnel();
		}
	}

	/// <summary>
	/// Interface Method
	/// Close the WebSocket and signal the event to let its service thread die. Also called by oSession.Abort()
	/// WARNING: This should not be allowed to throw any exceptions, because it will do so on threads that don't 
	/// catch them, and this will kill the application.
	/// </summary>
	public void CloseTunnel()
	{
		if (CONFIG.bDebugSpew)
		{
			FiddlerApplication.Log.LogString("Close WebSocket Tunnel: " + Environment.StackTrace);
		}
		try
		{
			if (oKeepTunnelAlive != null)
			{
				oKeepTunnelAlive.Set();
			}
			else
			{
				_CleanupWebSocket();
			}
		}
		catch (Exception eX)
		{
			FiddlerApplication.Log.LogString("Error closing oKeepTunnelAlive. " + eX.Message + "\n" + eX.StackTrace);
		}
	}

	/// <summary>
	/// When we get a buffer from the client, we push it into the memory stream
	/// </summary>
	private void _PushClientBuffer(int iReadCount)
	{
		strmClientBytes.Write(arrRequestBytes, 0, iReadCount);
		_ParseAndSendClientMessages();
	}

	/// <summary>
	/// When we get a buffer from the server, we push it into the memory stream
	/// </summary>
	private void _PushServerBuffer(int iReadCount)
	{
		strmServerBytes.Write(arrResponseBytes, 0, iReadCount);
		_ParseAndSendServerMessages();
	}

	private static WebSocketMessage[] _ParseMessagesFromStream(WebSocket wsOwner, ref MemoryStream strmData, bool bIsOutbound, bool bTrimAfterParsing)
	{
		List<WebSocketMessage> oMsgList = new List<WebSocketMessage>();
		strmData.Position = 0L;
		long iEndOfLastFullMessage = 0L;
		while (strmData.Length - strmData.Position >= 2)
		{
			byte[] arrHeader = new byte[2];
			strmData.Read(arrHeader, 0, arrHeader.Length);
			ulong iSize = (ulong)(int)(arrHeader[1] & 0x7Fu);
			if (iSize == 126)
			{
				if (strmData.Length < strmData.Position + 2)
				{
					break;
				}
				byte[] arrSize2 = new byte[2];
				strmData.Read(arrSize2, 0, arrSize2.Length);
				iSize = (ulong)(arrSize2[0] << 8) + (ulong)arrSize2[1];
			}
			else if (iSize == 127)
			{
				if (strmData.Length < strmData.Position + 8)
				{
					break;
				}
				byte[] arrSize = new byte[8];
				strmData.Read(arrSize, 0, arrSize.Length);
				iSize = (ulong)((arrSize[0] << 24) + (arrSize[1] << 16) + (arrSize[2] << 8) + arrSize[3] + (arrSize[4] << 24) + (arrSize[5] << 16) + (arrSize[6] << 8) + arrSize[7]);
			}
			bool bMasked = 128 == (arrHeader[1] & 0x80);
			if ((ulong)strmData.Length < (ulong)(strmData.Position + (long)iSize + (bMasked ? 4 : 0)))
			{
				break;
			}
			WebSocketMessage oMessage = new WebSocketMessage(wsOwner, Interlocked.Increment(ref wsOwner._iMsgCount), bIsOutbound);
			oMessage.AssignHeader(arrHeader[0]);
			if (bMasked)
			{
				byte[] arrKey = new byte[4];
				strmData.Read(arrKey, 0, arrKey.Length);
				oMessage.MaskingKey = arrKey;
			}
			byte[] arrPayload = new byte[iSize];
			strmData.Read(arrPayload, 0, arrPayload.Length);
			oMessage.PayloadData = arrPayload;
			oMsgList.Add(oMessage);
			iEndOfLastFullMessage = strmData.Position;
		}
		strmData.Position = iEndOfLastFullMessage;
		if (bTrimAfterParsing)
		{
			byte[] arrLeftovers = new byte[strmData.Length - iEndOfLastFullMessage];
			strmData.Read(arrLeftovers, 0, arrLeftovers.Length);
			strmData.Dispose();
			strmData = new MemoryStream();
			strmData.Write(arrLeftovers, 0, arrLeftovers.Length);
		}
		return oMsgList.ToArray();
	}

	/// <summary>
	/// This method parses the data in strmClientBytes to extact one or more WebSocket messages. It then sends each message
	/// through the pipeline.
	/// </summary>
	private void _ParseAndSendClientMessages()
	{
		WebSocketMessage[] arrMessages = _ParseMessagesFromStream(this, ref strmClientBytes, bIsOutbound: true, bTrimAfterParsing: true);
		WebSocketMessage[] array = arrMessages;
		foreach (WebSocketMessage oWSM in array)
		{
			oWSM.Timers.dtDoneRead = DateTime.Now;
			lock (listMessages)
			{
				listMessages.Add(oWSM);
			}
			FiddlerApplication.DoOnWebSocketMessage(_mySession, oWSM);
			if (!oWSM.WasAborted)
			{
				oWSM.Timers.dtBeginSend = DateTime.Now;
				oSP.Send(oWSM.ToByteArray());
				oWSM.Timers.dtDoneSend = DateTime.Now;
			}
		}
	}

	/// This method parses the data in strmServerBytes to extact one or more WebSocket messages. It then sends each message
	/// through the pipeline to the client.
	private void _ParseAndSendServerMessages()
	{
		WebSocketMessage[] arrMessages = _ParseMessagesFromStream(this, ref strmServerBytes, bIsOutbound: false, bTrimAfterParsing: true);
		WebSocketMessage[] array = arrMessages;
		foreach (WebSocketMessage oWSM in array)
		{
			oWSM.Timers.dtDoneRead = DateTime.Now;
			lock (listMessages)
			{
				listMessages.Add(oWSM);
			}
			FiddlerApplication.DoOnWebSocketMessage(_mySession, oWSM);
			if (!oWSM.WasAborted)
			{
				oWSM.Timers.dtBeginSend = DateTime.Now;
				oCP.Send(oWSM.ToByteArray());
				oWSM.Timers.dtDoneSend = DateTime.Now;
			}
		}
	}

	/// <summary>
	///  Called when we have received data from the local client.
	/// </summary>
	/// <param name="ar">The result of the asynchronous operation.</param>
	protected void OnReceiveFromClient(IAsyncResult ar)
	{
		try
		{
			int iReadCount = oCP.EndReceive(ar);
			if (iReadCount > 0)
			{
				_lngEgressByteCount += iReadCount;
				if (bParseMessages)
				{
					_PushClientBuffer(iReadCount);
				}
				else
				{
					oSP.Send(arrRequestBytes, 0, iReadCount);
				}
				oCP.BeginReceive(arrRequestBytes, 0, arrRequestBytes.Length, SocketFlags.None, OnReceiveFromClient, oCP);
				return;
			}
			if (bParseMessages)
			{
				FiddlerApplication.Log.LogFormat("[{0}] Read from Client returned error: {1}", sName, iReadCount);
			}
			CloseTunnel();
		}
		catch (Exception eX)
		{
			if (bParseMessages)
			{
				FiddlerApplication.Log.LogFormat("[{0}] Read from Client failed... {1}", sName, eX.Message);
			}
			CloseTunnel();
		}
	}

	/// <summary>Called when we have received data from the remote host. Incoming data will immediately be forwarded to the local client.</summary>
	/// <param name="ar">The result of the asynchronous operation.</param>
	protected void OnReceiveFromServer(IAsyncResult ar)
	{
		try
		{
			int iReadCount = oSP.EndReceive(ar);
			if (iReadCount > 0)
			{
				_lngIngressByteCount += iReadCount;
				if (bParseMessages)
				{
					_PushServerBuffer(iReadCount);
				}
				else
				{
					oCP.Send(arrResponseBytes, 0, iReadCount);
				}
				oSP.BeginReceive(arrResponseBytes, 0, arrResponseBytes.Length, SocketFlags.None, OnReceiveFromServer, oSP);
				return;
			}
			if (bParseMessages)
			{
				FiddlerApplication.Log.LogFormat("[{0}] Read from Server returned error: {1}", sName, iReadCount);
			}
			CloseTunnel();
		}
		catch (Exception eX)
		{
			if (bParseMessages)
			{
				FiddlerApplication.Log.LogFormat("[{0}] Read from Server failed... {1}", sName, eX.Message);
			}
			CloseTunnel();
		}
	}
}
