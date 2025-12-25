using System.Security.Cryptography.X509Certificates;

namespace Fiddler;

/// <summary>
/// Implement ICertificateProvider2 instead
/// </summary>
public interface ICertificateProvider
{
	/// <summary>
	/// Return a certificate to secure this traffic. Generally, it's expected that this method WILL create a new certificate if needed. 
	/// </summary>
	/// <param name="sHostname">Hostname (e.g. "www.example.com")</param>
	/// <returns>An X509Certificate, or null on error</returns>
	X509Certificate2 GetCertificateForHost(string sHostname);

	/// <summary>
	/// Return the root certificate to which Host Certificates are chained. Generally, it's expected that this method will NOT create a root certificate.
	/// </summary>
	/// <returns>An X509Certificate, or null on error</returns>
	X509Certificate2 GetRootCertificate();

	/// <summary>
	/// When this method is called, your extension should create a Root certificate.
	/// </summary>
	/// <returns>TRUE if the operation was successful</returns>
	bool CreateRootCertificate();

	/// <summary>
	/// When this method is called, your extension should copy the your Root certificate into
	/// the user's (or machines's) Root certificate store.
	/// </summary>
	/// <returns>TRUE if the operation was successful</returns>
	bool TrustRootCertificate();

	/// <summary>
	/// When this method is called, your extension should discard all certificates and 
	/// clear any certificates that have been added to the user's certificate store.
	/// </summary>
	/// <returns>TRUE, if all certificates were removed; FALSE if any certificates were preserved</returns>
	bool ClearCertificateCache();

	/// <summary>
	/// When this method is called, your extension should check to see if the User or Machine Root 
	/// certificate store contains your Root certificate.
	/// </summary>
	/// <param name="bUserTrusted">Set to TRUE if StoreLocation.CurrentUser StoreName.Root has the certificate</param>
	/// <param name="bMachineTrusted">Set to TRUE if StoreLocation.LocalMachine StoreName.Root has the certificate</param>
	/// <returns>TRUE if either bUserTrusted or bMachineTrusted</returns>
	bool rootCertIsTrusted(out bool bUserTrusted, out bool bMachineTrusted);
}
