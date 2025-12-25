namespace Fiddler;

public interface ICertificateProviderInfo
{
	/// <summary>
	/// Return a string describing the current configuration of the Certificate Provider. For instance, list
	/// the configured key size, hash algorithms, etc.
	/// </summary>
	string GetConfigurationString();
}
