namespace Fiddler;

/// <summary>
/// To override default certificate handling, your class should implement this interface in an assembly 
/// referenced by the fiddler.certmaker.assembly preference; by default, "certmaker.dll" in the application
/// folder is loaded
/// </summary>
public interface ICertificateProvider2 : ICertificateProvider
{
	/// <summary>
	/// When this method is called, your extension should discard all certificates and 
	/// clear any certificates that have been added to the user's certificate store
	/// </summary>
	/// <param name="bClearRoot">TRUE if the root certificate should also be cleared</param>
	/// <returns>TRUE, if all certificates were removed; FALSE if any certificates were preserved</returns>
	bool ClearCertificateCache(bool bClearRoot);
}
