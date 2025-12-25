using System;
using System.Globalization;
using GoogleAnalytics;

namespace Analytics.GA;

internal class PlatformInfoProvider : IPlatformInfoProvider
{
	public string AnonymousClientId => UniqueClientIdGenerator.Generate();

	public int? ScreenColors => null;

	public Dimensions? ScreenResolution => null;

	public string UserLanguage => CultureInfo.CurrentCulture.Name;

	public Dimensions? ViewPortResolution => null;

	public string UserAgent => null;

	public event EventHandler ViewPortResolutionChanged;

	public event EventHandler ScreenResolutionChanged;

	public void OnTracking()
	{
	}
}
