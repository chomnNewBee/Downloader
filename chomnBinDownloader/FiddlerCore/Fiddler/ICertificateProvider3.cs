using System.Security.Cryptography.X509Certificates;

namespace Fiddler;

public interface ICertificateProvider3 : ICertificateProvider2, ICertificateProvider
{
	/// <summary>
	/// Call this function to cache a certificate in the Certificate Provider
	/// </summary>
	/// <param name="sHost">The hostname to match</param>
	/// <param name="oCert">The certificate that the Provider should later provide when GetCertificateForHost is called</param>
	/// <returns>True if the request was successful</returns>
	bool CacheCertificateForHost(string sHost, X509Certificate2 oCert);
}
