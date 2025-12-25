using System;
using System.Reflection;
using Analytics;
using Analytics.Interfaces;

namespace FiddlerCore.Analytics;

internal class FiddlerAnalytics : IAnalytics
{
	private static readonly IAnalytics instance = new FiddlerAnalytics();

	private readonly ICompositeTracker compositeTracker;

	private bool started = false;

	internal static IAnalytics Instance => instance;

	private FiddlerAnalytics()
	{
		AssemblyName fiddlerCoreAssemblyName = Assembly.GetExecutingAssembly().GetName();
		compositeTracker = TrackerBuilder.Instance.AddGoogleAnalytics("UA-111455-46", fiddlerCoreAssemblyName.Name, fiddlerCoreAssemblyName.Version.ToString()).Build();
	}

	public void Start()
	{
		bool newSession = !started;
		compositeTracker.Start(newSession);
		started = true;
	}

	public void Stop()
	{
		compositeTracker.Stop();
		started = false;
	}

	public void TrackException(Exception exception)
	{
		compositeTracker.TrackException(exception);
	}

	public void TrackFeature(string category, string eventAction, string label = null)
	{
		compositeTracker.TrackFeature(category, eventAction, label);
	}

	public void TrackFeatureValue(string category, string eventAction, long value)
	{
		compositeTracker.TrackFeatureValue(category, eventAction, value);
	}
}
