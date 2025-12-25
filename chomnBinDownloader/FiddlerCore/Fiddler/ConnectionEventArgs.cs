using System;
using System.Net.Sockets;

namespace Fiddler;

public class ConnectionEventArgs : EventArgs
{
	private readonly Socket _oSocket;

	private readonly Session _oSession;

	/// <summary>
	/// The Socket which was just Connected or Accepted
	/// </summary>
	public Socket Connection => _oSocket;

	/// <summary>
	/// The Session which owns the this new connection
	/// </summary>
	public Session OwnerSession => _oSession;

	internal ConnectionEventArgs(Session oSession, Socket oSocket)
	{
		_oSession = oSession;
		_oSocket = oSocket;
	}
}
