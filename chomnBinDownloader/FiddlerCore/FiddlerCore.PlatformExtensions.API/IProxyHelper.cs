namespace FiddlerCore.PlatformExtensions.API;

/// <summary>
/// Implement this interface, in order to provide FiddlerCore with platform-specific proxy helper.
/// This interface contains members used to manipulate proxy settings.
/// </summary>
internal interface IProxyHelper
{
	/// <summary>
	/// Configures the current process to use no proxy.
	/// </summary>
	void DisableProxyForCurrentProcess();

	/// <summary>
	/// Returns the current process' proxy settings.
	/// </summary>
	/// <returns>String containing a HEX view of the current process' proxy settings.</returns>
	string GetProxyForCurrentProcessAsHexView();

	/// <summary>
	/// Configures current process' proxy settings to default.
	/// </summary>
	void ResetProxyForCurrentProcess();

	/// <summary>
	/// Configures current process' proxy settings.
	/// </summary>
	/// <param name="proxy">The proxy information (IP and port). It can be per connection type
	/// (e.g. http=127.0.0.1:8080;https=127.0.0.1:444) or global (e.g. 127.0.0.1:8888).</param>
	/// <param name="bypassList">Semi-colon delimted list of hosts to bypass proxy
	/// (e.g. www.google.com;www.microsoft.com)</param>
	void SetProxyForCurrentProcess(string proxy, string bypassList);
}
