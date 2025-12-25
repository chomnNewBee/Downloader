using System;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Threading;

namespace Fiddler;

/// <summary>
/// Abstract base class for the ClientPipe and ServerPipe classes. A Pipe represents a connection to either the client or the server, optionally encrypted using SSL/TLS.
/// </summary>
public abstract class BasePipe
{
	/// <summary>
	/// The base socket wrapped in this pipe
	/// </summary>
	protected Socket _baseSocket;

	/// <summary>
	/// The number of times that this Pipe has been used
	/// </summary>
	protected internal uint iUseCount;

	/// <summary>
	/// The HTTPS stream wrapped around the base socket
	/// </summary>
	protected SslStream _httpsStream;

	/// <summary>
	/// The display name of this Pipe
	/// </summary>
	protected internal string _sPipeName;

	/// <summary>
	/// Number of milliseconds to delay each 1024 bytes transmitted
	/// </summary>
	private int _iTransmitDelayMS;

	/// <summary>
	/// Return the Connected status of the base socket. 
	/// WARNING: This doesn't work as you might expect; you can see Connected == false when a READ timed out but a WRITE will succeed.
	/// </summary>
	public bool Connected => _baseSocket != null && _baseSocket.Connected;

	/// <summary>
	/// Returns a bool indicating if the socket in this Pipe is CURRENTLY connected and wrapped in a SecureStream
	/// </summary>
	public bool bIsSecured => _httpsStream != null;

	/// <summary>
	/// Returns the SSL/TLS protocol securing this connection
	/// </summary>
	public SslProtocols SecureProtocol
	{
		get
		{
			if (_httpsStream == null)
			{
				return SslProtocols.None;
			}
			return _httpsStream.SslProtocol;
		}
	}

	/// <summary>
	/// Return the Remote Port to which this socket is attached.
	/// </summary>
	public int Port
	{
		get
		{
			try
			{
				if (_baseSocket != null && _baseSocket.RemoteEndPoint != null)
				{
					return (_baseSocket.RemoteEndPoint as IPEndPoint).Port;
				}
				return 0;
			}
			catch
			{
				return 0;
			}
		}
	}

	/// <summary>
	/// Return the Local Port to which the base socket is attached. Note: May return a misleading port if the ISA Firewall Client is in use.
	/// </summary>
	public int LocalPort
	{
		get
		{
			try
			{
				if (_baseSocket != null && _baseSocket.LocalEndPoint != null)
				{
					return (_baseSocket.LocalEndPoint as IPEndPoint).Port;
				}
				return 0;
			}
			catch
			{
				return 0;
			}
		}
	}

	/// <summary>
	/// Returns the remote address to which this Pipe is connected, or 0.0.0.0 on error.
	/// </summary>
	public IPAddress Address
	{
		get
		{
			try
			{
				if (_baseSocket == null || _baseSocket.RemoteEndPoint == null)
				{
					return new IPAddress(0L);
				}
				return (_baseSocket.RemoteEndPoint as IPEndPoint).Address;
			}
			catch
			{
				return new IPAddress(0L);
			}
		}
	}

	/// <summary>
	/// Gets or sets the transmission delay on this Pipe, used for performance simulation purposes.
	/// </summary>
	public int TransmitDelay
	{
		get
		{
			return _iTransmitDelayMS;
		}
		set
		{
			_iTransmitDelayMS = value;
		}
	}

	/// <summary>
	/// Create a new pipe, an enhanced wrapper around a socket
	/// </summary>
	/// <param name="oSocket">Socket which this pipe wraps</param>
	/// <param name="sName">Identification string used for debugging purposes</param>
	public BasePipe(Socket oSocket, string sName)
	{
		_sPipeName = sName;
		_baseSocket = oSocket;
	}

	/// <summary>
	/// Poll the underlying socket for readable data (or closure/errors)
	/// </summary>
	/// <returns>TRUE if this Pipe requires attention</returns>
	public virtual bool HasDataAvailable()
	{
		if (!Connected)
		{
			return false;
		}
		return _baseSocket.Poll(0, SelectMode.SelectRead);
	}

	/// <summary>
	/// Call this method when about to reuse a socket. Currently, increments the socket's UseCount and resets its transmit delay to 0.
	/// </summary>
	/// <param name="iSession">The session identifier of the new session, or zero</param>
	internal void IncrementUse(int iSession)
	{
		_iTransmitDelayMS = 0;
		iUseCount++;
	}

	/// <summary>
	/// Sends a byte array through this pipe
	/// </summary>
	/// <param name="oBytes">The bytes</param>
	public void Send(byte[] oBytes)
	{
		Send(oBytes, 0, oBytes.Length);
	}

	/// <summary>
	/// Sends the data specified in oBytes (between iOffset and iOffset+iCount-1 inclusive) down the pipe.
	/// </summary>
	/// <param name="oBytes"></param>
	/// <param name="iOffset"></param>
	/// <param name="iCount"></param>
	internal void Send(byte[] oBytes, int iOffset, int iCount)
	{
		if (oBytes == null)
		{
			return;
		}
		if (iOffset + iCount > oBytes.LongLength)
		{
			iCount = oBytes.Length - iOffset;
		}
		if (iCount < 1)
		{
			return;
		}
		if (_iTransmitDelayMS < 1)
		{
			if (bIsSecured)
			{
				_httpsStream.Write(oBytes, iOffset, iCount);
			}
			else
			{
				_baseSocket.Send(oBytes, iOffset, iCount, SocketFlags.None);
			}
			return;
		}
		int iBlockSize = 1024;
		for (int iWroteSoFar = iOffset; iWroteSoFar < iOffset + iCount; iWroteSoFar += iBlockSize)
		{
			if (iWroteSoFar + iBlockSize > iOffset + iCount)
			{
				iBlockSize = iOffset + iCount - iWroteSoFar;
			}
			Thread.Sleep(_iTransmitDelayMS / 2);
			if (bIsSecured)
			{
				_httpsStream.Write(oBytes, iWroteSoFar, iBlockSize);
			}
			else
			{
				_baseSocket.Send(oBytes, iWroteSoFar, iBlockSize, SocketFlags.None);
			}
			Thread.Sleep(_iTransmitDelayMS / 2);
		}
	}

	internal IAsyncResult BeginSend(byte[] arrData, int iOffset, int iSize, SocketFlags oSF, AsyncCallback oCB, object oContext)
	{
		if (bIsSecured)
		{
			return _httpsStream.BeginWrite(arrData, iOffset, iSize, oCB, oContext);
		}
		return _baseSocket.BeginSend(arrData, iOffset, iSize, oSF, oCB, oContext);
	}

	internal void EndSend(IAsyncResult oAR)
	{
		if (bIsSecured)
		{
			_httpsStream.EndWrite(oAR);
		}
		else
		{
			_baseSocket.EndSend(oAR);
		}
	}

	internal IAsyncResult BeginReceive(byte[] arrData, int iOffset, int iSize, SocketFlags oSF, AsyncCallback oCB, object oContext)
	{
		if (bIsSecured)
		{
			return _httpsStream.BeginRead(arrData, iOffset, iSize, oCB, oContext);
		}
		return _baseSocket.BeginReceive(arrData, iOffset, iSize, oSF, oCB, oContext);
	}

	internal int EndReceive(IAsyncResult oAR)
	{
		if (bIsSecured)
		{
			return _httpsStream.EndRead(oAR);
		}
		return _baseSocket.EndReceive(oAR);
	}

	/// <summary>
	/// Receive bytes from the pipe into the DATA buffer.
	/// </summary>
	/// <exception cref="T:System.IO.IOException">Throws IO exceptions from the socket/stream</exception>
	/// <param name="arrBuffer">Array of data read</param>
	/// <returns>Bytes read</returns>
	internal int Receive(byte[] arrBuffer)
	{
		int cBytes = -1;
		if (bIsSecured)
		{
			return _httpsStream.Read(arrBuffer, 0, arrBuffer.Length);
		}
		return _baseSocket.Receive(arrBuffer);
	}

	/// <summary>
	/// Return the raw socket this pipe wraps. Avoid calling this method if at all possible.
	/// </summary>
	/// <returns>The Socket object this Pipe wraps.</returns>
	public Socket GetRawSocket()
	{
		return _baseSocket;
	}

	/// <summary>
	/// Shutdown and close the socket inside this pipe. Eats exceptions.
	/// </summary>
	public void End()
	{
		if (CONFIG.bDebugSpew)
		{
			FiddlerApplication.DebugSpew("Pipe::End() for {0}", _sPipeName);
		}
		try
		{
			if (_httpsStream != null)
			{
				_httpsStream.Close();
			}
			if (_baseSocket != null)
			{
				_baseSocket.Shutdown(SocketShutdown.Both);
				_baseSocket.Close();
			}
		}
		catch (Exception)
		{
		}
		_baseSocket = null;
		_httpsStream = null;
	}

	/// <summary>
	/// Abruptly closes the socket by sending a RST packet
	/// </summary>
	public void EndWithRST()
	{
		try
		{
			if (_baseSocket != null)
			{
				_baseSocket.LingerState = new LingerOption(enable: true, 0);
				_baseSocket.Close();
			}
		}
		catch (Exception)
		{
		}
		_baseSocket = null;
		_httpsStream = null;
	}
}
