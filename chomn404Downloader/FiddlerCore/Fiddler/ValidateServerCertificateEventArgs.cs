using System;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace Fiddler;

/// <summary>
/// These EventArgs are passed to the FiddlerApplication.OnValidateServerCertificate event handler when a server-provided HTTPS certificate is evaluated
/// </summary>
public class ValidateServerCertificateEventArgs : EventArgs
{
	private readonly X509Certificate _oServerCertificate;

	private readonly string _sExpectedCN;

	private readonly Session _oSession;

	private readonly X509Chain _ServerCertificateChain;

	private readonly SslPolicyErrors _sslPolicyErrors;

	/// <summary>
	/// The port to which this request was targeted
	/// </summary>
	public int TargetPort => _oSession.port;

	/// <summary>
	/// The SubjectCN (e.g. Hostname) that should be expected on this HTTPS connection, based on the request's Host property.
	/// </summary>
	public string ExpectedCN => _sExpectedCN;

	/// <summary>
	/// The Session for which a HTTPS certificate was received.
	/// </summary>
	public Session Session => _oSession;

	/// <summary>
	/// The server's certificate chain.
	/// </summary>
	public X509Chain ServerCertificateChain => _ServerCertificateChain;

	/// <summary>
	/// The SslPolicyErrors found during default certificate evaluation.
	/// </summary>
	public SslPolicyErrors CertificatePolicyErrors => _sslPolicyErrors;

	/// <summary>
	/// Set this property to override the certificate validity
	/// </summary>
	public CertificateValidity ValidityState { get; set; }

	/// <summary>
	/// The X509Certificate provided by the server to vouch for its authenticity
	/// </summary>
	public X509Certificate ServerCertificate => _oServerCertificate;

	/// <summary>
	/// EventArgs for the ValidateServerCertificateEvent that allows host to override default certificate handling policy
	/// </summary>
	/// <param name="inSession">The session</param>
	/// <param name="inExpectedCN">The CN expected for this session</param>
	/// <param name="inServerCertificate">The certificate provided by the server</param>
	/// <param name="inServerCertificateChain">The certificate chain of that certificate</param>
	/// <param name="inSslPolicyErrors">Errors from default validation</param>
	internal ValidateServerCertificateEventArgs(Session inSession, string inExpectedCN, X509Certificate inServerCertificate, X509Chain inServerCertificateChain, SslPolicyErrors inSslPolicyErrors)
	{
		_oSession = inSession;
		_sExpectedCN = inExpectedCN;
		_oServerCertificate = inServerCertificate;
		_ServerCertificateChain = inServerCertificateChain;
		_sslPolicyErrors = inSslPolicyErrors;
	}
}
