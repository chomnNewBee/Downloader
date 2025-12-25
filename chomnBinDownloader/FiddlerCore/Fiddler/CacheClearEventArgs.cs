using System.ComponentModel;

namespace Fiddler;

/// <summary>
/// These EventArgs are constructed when FiddlerApplication.OnClearCache is called.
/// </summary>
public class CacheClearEventArgs : CancelEventArgs
{
	/// <summary>
	/// True if the user wants cache files to be cleared
	/// </summary>
	public bool ClearCacheFiles { get; set; }

	/// <summary>
	/// True if the user wants cookies to be cleared
	/// </summary>
	public bool ClearCookies { get; set; }

	/// <summary>
	/// Constructs the Event Args
	/// </summary>
	/// <param name="bClearFiles">Should Cache Files be cleared?</param>
	/// <param name="bClearCookies">Should Cookies be cleared?</param>
	public CacheClearEventArgs(bool bClearFiles, bool bClearCookies)
	{
		ClearCacheFiles = bClearFiles;
		ClearCookies = bClearCookies;
	}
}
