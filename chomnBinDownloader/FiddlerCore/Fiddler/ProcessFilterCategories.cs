namespace Fiddler;

/// <summary>
/// A simple Process Type enumeration used by various filtering features
/// </summary>
public enum ProcessFilterCategories
{
	/// <summary>
	/// Include all Processes
	/// </summary>
	All,
	/// <summary>
	/// Processes which appear to be Web Browsers
	/// </summary>
	Browsers,
	/// <summary>
	/// Processes which appear to NOT be Web Browsers
	/// </summary>
	NonBrowsers,
	/// <summary>
	/// Include only traffic where Process ID isn't known (e.g. remote clients)
	/// </summary>
	HideAll
}
