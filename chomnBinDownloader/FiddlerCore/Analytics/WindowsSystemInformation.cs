using System.Collections.Generic;
using System.Globalization;
using Analytics.Utility;
using GoogleAnalytics;

namespace Analytics;

internal class WindowsSystemInformation
{
	private static Dimensions? screenResolution;

	public static Dimensions ScreenResolution
	{
		get
		{
			if (!screenResolution.HasValue)
			{
				List<WindowsNativeMethods.DisplayInfo> displays = CodeUtil.SafeExpr(WindowsNativeMethods.GetDisplays, new List<WindowsNativeMethods.DisplayInfo>());
				WindowsNativeMethods.DisplayInfo primaryDisplay = displays.Find((WindowsNativeMethods.DisplayInfo d) => d.IsPrimary) ?? new WindowsNativeMethods.DisplayInfo();
				screenResolution = new Dimensions(primaryDisplay.DesktopHorzRes, primaryDisplay.DesktopVertRes);
			}
			return screenResolution.GetValueOrDefault();
		}
	}

	public static string SystemLanguage => CultureInfo.InstalledUICulture.IetfLanguageTag.ToLower();
}
