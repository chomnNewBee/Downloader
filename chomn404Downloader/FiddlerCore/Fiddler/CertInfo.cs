using System.Security.Cryptography.X509Certificates;

namespace Fiddler;

internal static class CertInfo
{
	private const string szOID_SUBJECT_ALT_NAME2 = "2.5.29.17";

	internal static string GetSubjectAltNames(X509Certificate2 cert)
	{
		if (cert.Extensions["2.5.29.17"] != null)
		{
			return cert.Extensions["2.5.29.17"].Format(multiLine: true);
		}
		return null;
	}
}
