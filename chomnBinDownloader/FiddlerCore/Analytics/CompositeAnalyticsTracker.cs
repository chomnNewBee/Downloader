using System;
using System.Collections.Generic;
using Analytics.Interfaces;

namespace Analytics;

internal class CompositeAnalyticsTracker : ICompositeTracker, IDisposable
{
	private bool isEnabled;

	private IList<IAnalyticsTracker> trackers;

	public event EventHandler TrackerStarted;

	public CompositeAnalyticsTracker()
	{
		trackers = new List<IAnalyticsTracker>();
	}

	protected virtual void OnTrackerStarted(EventArgs e)
	{
		try
		{
			this.TrackerStarted?.Invoke(this, e);
		}
		catch
		{
		}
	}

	public void Start(bool newSession)
	{
		try
		{
			if (isEnabled)
			{
				return;
			}
			isEnabled = true;
			if (!newSession)
			{
				return;
			}
			foreach (IAnalyticsTracker tracker in trackers)
			{
				tracker.Start(newSession);
			}
			OnTrackerStarted(EventArgs.Empty);
		}
		catch
		{
		}
	}

	public void Stop()
	{
		try
		{
			if (!isEnabled)
			{
				return;
			}
			isEnabled = false;
			foreach (IAnalyticsTracker tracker in trackers)
			{
				if (tracker is IBufferingAnalytics)
				{
					(tracker as IBufferingAnalytics).Flush();
				}
			}
		}
		catch
		{
		}
	}

	public void AddTrackers(ICollection<IAnalyticsTracker> trackers)
	{
		try
		{
			foreach (IAnalyticsTracker tracker in trackers)
			{
				this.trackers.Add(tracker);
			}
		}
		catch (Exception)
		{
		}
	}

	public void AddTracker(IAnalyticsTracker tracker)
	{
		trackers.Add(tracker);
	}

	public void TrackException(Exception ex, bool isFatal = false)
	{
		try
		{
			if (!isEnabled)
			{
				return;
			}
			foreach (IAnalyticsTracker tracker in trackers)
			{
				tracker.TrackException(ex);
			}
		}
		catch
		{
		}
	}

	public void TrackFeature(string category, string eventAction, string label = null)
	{
		try
		{
			if (!isEnabled)
			{
				return;
			}
			foreach (IAnalyticsTracker tracker in trackers)
			{
				tracker.TrackFeature(category, eventAction, label);
			}
		}
		catch
		{
		}
	}

	public void TrackFeatureValue(string category, string eventAction, long value)
	{
		try
		{
			if (!isEnabled)
			{
				return;
			}
			foreach (IAnalyticsTracker tracker in trackers)
			{
				tracker.TrackFeatureValue(category, eventAction, value);
			}
		}
		catch
		{
		}
	}

	public void Dispose()
	{
		try
		{
			foreach (IAnalyticsTracker tracker in trackers)
			{
				if (tracker is IOpenSessionAnalytics)
				{
					(tracker as IOpenSessionAnalytics).CloseSession();
				}
			}
		}
		catch
		{
		}
	}
}
