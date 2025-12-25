using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using FiddlerCore.Utilities.SmartAssembly.Attributes;

namespace Fiddler;

[DoNotObfuscateType]
public interface ICertificateProvider4 : ICertificateProvider3, ICertificateProvider2, ICertificateProvider
{
	/// <summary>
	/// Copy of the cache of the EndEntity certificates that have been generated in this session.
	/// </summary>
	IDictionary<string, X509Certificate2> CertCache { get; }
}
