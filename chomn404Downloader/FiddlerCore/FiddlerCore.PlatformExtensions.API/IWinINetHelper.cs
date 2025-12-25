namespace FiddlerCore.PlatformExtensions.API;

/// <summary>
/// Implement this interface in order to provide FiddlerCore with access to native WinINet API.
/// </summary>
internal interface IWinINetHelper
{
	/// <summary>
	/// Clears WinINet's cache.
	/// </summary>
	/// <param name="clearFiles">true if cache files should be cleared, false otherwise.</param>
	/// <param name="clearCookies">true if cookies should be cleared, false otherwise.</param>
	void ClearCacheItems(bool clearFiles, bool clearCookies);

	/// <summary>
	/// Delete all permanent WinINet cookies for a <paramref name="host" />.
	/// </summary>
	/// <param name="host">The hostname whose cookies should be cleared.</param>
	void ClearCookiesForHost(string host);

	/// <summary>
	/// Use this method in order to get cache information for a <paramref name="url" />.
	/// </summary>
	/// <param name="url">The URL for which the cache info is requested.</param>
	/// <returns>String, containing cache information for the given <paramref name="url" />.</returns>
	string GetCacheItemInfo(string url);
}
