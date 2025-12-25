using System;

namespace Analytics.Interfaces;

internal interface ICompositeTracker : IDisposable
{
	event EventHandler TrackerStarted;

	void Start(bool newSession);

	void Stop();

	void TrackFeature(string category, string eventAction, string label = null);

	void TrackFeatureValue(string category, string eventAction, long value);

	void TrackException(Exception exception, bool isFatal = false);
}
