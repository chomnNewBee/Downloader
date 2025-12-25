using System;

namespace Analytics.Interfaces;

internal interface IAnalyticsTracker
{
	void Start(bool newSession);

	void TrackFeature(string category, string eventAction, string label = null);

	void TrackFeatureValue(string category, string eventAction, long value);

	void TrackException(Exception exception, bool isFatal = false);
}
