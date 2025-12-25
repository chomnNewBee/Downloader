using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using Analytics.Interfaces;
using GoogleAnalytics;

namespace Analytics.GA;

internal class GoogleAnalyticsTracker : IAnalyticsTracker, IBufferingAnalytics
{
	private const string DefaultCategoryName = "No Category";

	private const int HitFlushTimeout = 2;

	private Tracker googleTracker;

	private TrackerManager trackerManager;

	private readonly IPlatformInfoProvider platformInfoProvider;

	public GoogleAnalyticsTracker(string trackerId, string appName, string appVersion, IPlatformInfoProvider platformInfoProvider, double dispatchPeriod, IWebProxy proxy)
	{
		this.platformInfoProvider = platformInfoProvider;
		trackerManager = new TrackerManager(this.platformInfoProvider, proxy);
		if (dispatchPeriod > 0.0)
		{
			trackerManager.DispatchPeriod = TimeSpan.FromSeconds(dispatchPeriod);
		}
		googleTracker = trackerManager.CreateTracker(trackerId);
		googleTracker.AppName = appName;
		googleTracker.AppVersion = appVersion;
	}

	public void Start(bool newSession)
	{
		if (newSession)
		{
			IDictionary<string, string> trackingData = HitBuilder.CreateScreenView("Start").SetNewSession().Build();
			googleTracker.Send(trackingData);
		}
	}

	public void TrackException(Exception ex, bool isFatal)
	{
		string exceptionDescriptionFormat = ex.GetType().Name + " - " + ex.Message + " - " + ex.StackTrace;
		IDictionary<string, string> trackingData = HitBuilder.CreateException(exceptionDescriptionFormat, isFatal).Build();
		googleTracker.Send(trackingData);
	}

	public void TrackFeature(string category, string eventAction, string label = null)
	{
		IDictionary<string, string> trackingData = GenerateTrackingData(category, eventAction, label);
		googleTracker.Send(trackingData);
	}

	public void TrackFeatureValue(string category, string eventAction, long value)
	{
		IDictionary<string, string> trackingData = GenerateTrackingData(category, eventAction, value);
		googleTracker.Send(trackingData);
	}

	public void Flush()
	{
		Task.Run(async delegate
		{
			await trackerManager.SuspendAsync();
		}).ContinueWith(delegate
		{
			trackerManager.Resume();
		}).Wait(2);
	}

	private IDictionary<string, string> GenerateTrackingData(string category, string eventAction, long value)
	{
		HitBuilder data = null;
		if (category == null)
		{
			category = "No Category";
		}
		string eventName = category + "." + eventAction;
		data = HitBuilder.CreateCustomEvent(eventName, value.ToString(), null, 0L);
		return data.Build();
	}

	private IDictionary<string, string> GenerateTrackingData(string category, string eventAction, string label)
	{
		HitBuilder data = null;
		if (category == null)
		{
			category = "No Category";
		}
		data = HitBuilder.CreateCustomEvent(category, eventAction, label, 0L);
		return data.Build();
	}
}
