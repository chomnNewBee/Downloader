using System;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

namespace Fiddler;

/// <summary>
/// Parameters passed into the AcceptConnection method.
/// </summary>
internal class ProxyExecuteParams
{
	/// <summary>
	/// The Socket which represents the newly-accepted Connection
	/// </summary>
	public Socket oSocket;

	/// <summary>
	/// The Certificate to pass to SecureClientPipeDirect immediately after accepting the connection.
	/// Normally null, this will be set if the proxy endpoint is configured as a "Secure" endpoint
	/// by AssignEndpointCertificate / ActAsHTTPSEndpointForHostname.
	/// </summary>
	public X509Certificate2 oServerCert;

	/// <summary>
	/// The DateTime of Creation of this connection
	/// </summary>
	public DateTime dtConnectionAccepted;

	public ProxyExecuteParams(Socket oS, X509Certificate2 oC)
	{
		dtConnectionAccepted = DateTime.Now;
		oSocket = oS;
		oServerCert = oC;
	}
}
