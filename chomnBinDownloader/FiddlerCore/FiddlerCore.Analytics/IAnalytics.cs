using System;
using FiddlerCore.Utilities.SmartAssembly.Attributes;

namespace FiddlerCore.Analytics;

[DoNotObfuscateType]
internal interface IAnalytics
{
	void TrackFeature(string category, string eventAction, string label = null);

	void TrackFeatureValue(string category, string eventAction, long value);

	void TrackException(Exception exception);

	void Start();

	void Stop();
}
