using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using Analytics.Enumerations;
using Analytics.GA;
using Analytics.Interfaces;
using GoogleAnalytics;

namespace Analytics;

internal class TrackerBuilder
{
	private readonly IList<IAnalyticsTracker> trackers = new List<IAnalyticsTracker>();

	private readonly IDictionary<string, AnalyticsTrackerType> trackersData = new Dictionary<string, AnalyticsTrackerType>();

	private static readonly TrackerBuilder instance;

	public static TrackerBuilder Instance => instance;

	static TrackerBuilder()
	{
		instance = new TrackerBuilder();
	}

	private TrackerBuilder()
	{
	}

	public TrackerBuilder AddGoogleAnalytics(string trackingId, string applicationName, string appVersion, double dispatchPeriod = 0.0, IWebProxy proxy = null)
	{
		try
		{
			if (trackersData.Any((KeyValuePair<string, AnalyticsTrackerType> t) => t.Key == trackingId && t.Value == AnalyticsTrackerType.GoogleAnalyticsTracker))
			{
				throw new ArgumentException("Google Analytics with that trackingId already exist!");
			}
			IPlatformInfoProvider platformInfoProvider3;
			if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
			{
				IPlatformInfoProvider platformInfoProvider2 = new PlatformInfoProvider();
				platformInfoProvider3 = platformInfoProvider2;
			}
			else
			{
				IPlatformInfoProvider platformInfoProvider2 = new WindowsPlatformInfoProvider();
				platformInfoProvider3 = platformInfoProvider2;
			}
			IPlatformInfoProvider platformInfoProvider = platformInfoProvider3;
			GoogleAnalyticsTracker googleAnalyticsTracker = new GoogleAnalyticsTracker(trackingId, applicationName, appVersion, platformInfoProvider, dispatchPeriod, proxy);
			trackers.Add(googleAnalyticsTracker);
		}
		catch
		{
		}
		return this;
	}

	public ICompositeTracker Build()
	{
		CompositeAnalyticsTracker compositeTracker = new CompositeAnalyticsTracker();
		try
		{
			if (trackers.Count >= 1)
			{
				compositeTracker.AddTrackers(trackers);
			}
		}
		catch (Exception)
		{
		}
		return compositeTracker;
	}
}
