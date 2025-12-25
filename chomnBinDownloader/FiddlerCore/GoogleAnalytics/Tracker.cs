using System;

namespace GoogleAnalytics;

/// <summary>
/// Represents an object capable of tracking events for a single Google Analytics property.
/// </summary>
internal sealed class Tracker : SimpleTracker
{
	private readonly IPlatformInfoProvider platformInfoProvider;

	/// <summary>
	/// Instantiates a new instance of <see cref="T:GoogleAnalytics.Tracker" />.
	/// </summary>
	/// <param name="propertyId">the property ID to track to.</param>
	/// <param name="platformInfoProvider">An object capable of providing platform and environment specific information.</param>
	/// <param name="serviceManager">The object used to send <see cref="T:GoogleAnalytics.Hit" />s to the service.</param>
	public Tracker(string propertyId, IPlatformInfoProvider platformInfoProvider, IServiceManager serviceManager)
		: base(propertyId, serviceManager)
	{
		this.platformInfoProvider = platformInfoProvider;
		if (platformInfoProvider != null)
		{
			base.ClientId = platformInfoProvider.AnonymousClientId;
			base.ScreenColors = platformInfoProvider.ScreenColors;
			base.ScreenResolution = platformInfoProvider.ScreenResolution;
			base.Language = platformInfoProvider.UserLanguage;
			base.ViewportSize = platformInfoProvider.ViewPortResolution;
			platformInfoProvider.ViewPortResolutionChanged += platformTrackingInfo_ViewPortResolutionChanged;
			platformInfoProvider.ScreenResolutionChanged += platformTrackingInfo_ScreenResolutionChanged;
		}
	}

	private void platformTrackingInfo_ViewPortResolutionChanged(object sender, EventArgs args)
	{
		base.ViewportSize = platformInfoProvider.ViewPortResolution;
	}

	private void platformTrackingInfo_ScreenResolutionChanged(object sender, EventArgs args)
	{
		base.ScreenResolution = platformInfoProvider.ScreenResolution;
	}
}
