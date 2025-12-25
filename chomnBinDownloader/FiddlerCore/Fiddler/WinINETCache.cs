using System;
using FiddlerCore.PlatformExtensions;
using FiddlerCore.PlatformExtensions.API;

namespace Fiddler;

/// <summary>
/// Wrapper for WinINET cache APIs. 
/// </summary>
public class WinINETCache
{
	private const string SupportedOnlyOnWindowsMessage = "This method is supported only on Windows.";

	/// <summary>
	/// Clear all HTTP Cookies from the WinINET Cache
	/// </summary>
	public static void ClearCookies()
	{
		ClearCacheItems(bClearFiles: false, bClearCookies: true);
	}

	/// <summary>
	/// Clear all files from the WinINET Cache
	/// </summary>
	public static void ClearFiles()
	{
		ClearCacheItems(bClearFiles: true, bClearCookies: false);
	}

	/// <summary>
	/// Delete all permanent WinINET cookies for sHost; won't clear memory-only session cookies. Supports hostnames with an optional leading wildcard, e.g. *example.com. NOTE: Will not work on VistaIE Protected Mode cookies.
	/// </summary>
	/// <param name="sHost">The hostname whose cookies should be cleared</param>
	[CodeDescription("Delete all permanent WinINET cookies for sHost; won't clear memory-only session cookies. Supports hostnames with an optional leading wildcard, e.g. *example.com. NOTE: Will not work on VistaIE Protected Mode cookies.")]
	public static void ClearCookiesForHost(string sHost)
	{
		if (!(PlatformExtensionsFactory.Instance.CreatePlatformExtensions() is IWindowsSpecificPlatformExtensions extensions))
		{
			throw new NotSupportedException("This method is supported only on Windows.");
		}
		extensions.WinINetHelper.ClearCookiesForHost(sHost);
	}

	/// <summary>
	/// Clear the Cache items.  Note: May be synchronous, may be asynchronous.
	/// </summary>
	/// <param name="bClearFiles">TRUE if cache files should be cleared</param>
	/// <param name="bClearCookies">TRUE if cookies should be cleared</param>
	public static void ClearCacheItems(bool bClearFiles, bool bClearCookies)
	{
		if (!bClearCookies && !bClearFiles)
		{
			throw new ArgumentException("You must call ClearCacheItems with at least one target");
		}
		if (!FiddlerApplication.DoClearCache(bClearFiles, bClearCookies))
		{
			FiddlerApplication.Log.LogString("Cache clearing was handled by an extension. Default clearing was skipped.");
			return;
		}
		if (!(PlatformExtensionsFactory.Instance.CreatePlatformExtensions() is IWindowsSpecificPlatformExtensions extensions))
		{
			throw new NotSupportedException("This method is supported only on Windows.");
		}
		extensions.WinINetHelper.ClearCacheItems(bClearFiles, bClearCookies);
	}
}
