using System;

namespace FiddlerCore.Analytics;

internal sealed class EmptyAnalytics : IAnalytics
{
	public void Start()
	{
	}

	public void Stop()
	{
	}

	public void TrackException(Exception exception)
	{
	}

	public void TrackFeature(string category, string eventAction, string label = null)
	{
	}

	public void TrackFeatureValue(string category, string eventAction, long value)
	{
	}
}
