namespace Fiddler;

/// <summary>
/// Enumeration of possible responses specified by the ValidateServerCertificateEventArgs as modified by FiddlerApplication's <see cref="E:Fiddler.FiddlerApplication.OnValidateServerCertificate">OnValidateServerCertificate event</see>  
/// </summary>
public enum CertificateValidity
{
	/// <summary>
	/// The certificate will be considered valid if CertificatePolicyErrors == SslPolicyErrors.None, otherwise the certificate will be invalid unless the user manually allows the certificate.
	/// </summary>
	Default,
	/// <summary>
	/// The certificate will be confirmed with the user even if CertificatePolicyErrors == SslPolicyErrors.None.
	/// Note: FiddlerCore does not support user-prompting and will always treat this status as ForceInvalid.
	/// </summary>
	ConfirmWithUser,
	/// <summary>
	/// Force the certificate to be considered Invalid, regardless of the value of CertificatePolicyErrors.
	/// </summary>
	ForceInvalid,
	/// <summary>
	/// Force the certificate to be considered Valid, regardless of the value of CertificatePolicyErrors.
	/// </summary>
	ForceValid
}
