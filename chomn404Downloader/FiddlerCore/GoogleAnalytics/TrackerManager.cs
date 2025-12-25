using System.Collections.Generic;
using System.Net;

namespace GoogleAnalytics;

/// <summary>
/// Provides a way to manage multiple <see cref="T:GoogleAnalytics.Tracker" /> instances.
/// </summary>
internal class TrackerManager : ServiceManager
{
	private readonly IPlatformInfoProvider platformInfoProvider;

	private readonly Dictionary<string, Tracker> trackers;

	/// <summary>
	/// Gets the collection of <see cref="T:GoogleAnalytics.Tracker" /> instances.
	/// </summary>
	protected ICollection<Tracker> Trackers => trackers.Values;

	/// <summary>
	/// Gets or sets the default tracker instance for easy access.
	/// </summary>
	/// <remarks>This always returns the last tracker instance created.</remarks>
	public Tracker DefaultTracker { get; set; }

	/// <summary>
	/// Gets or sets whether the app should log information to Google Analtyics.
	/// </summary>
	/// <remarks>See Google Analytics usage guidelines for more information.</remarks>
	public virtual bool AppOptOut { get; set; }

	/// <summary>
	/// Gets the instance of <see cref="T:GoogleAnalytics.IPlatformInfoProvider" /> used by all <see cref="T:GoogleAnalytics.Tracker" /> instances.
	/// </summary>
	public IPlatformInfoProvider PlatformTrackingInfo => platformInfoProvider;

	/// <summary>
	/// Instantiates a new instance of <see cref="T:GoogleAnalytics.TrackerManager" />.
	/// </summary>
	/// <param name="platformInfoProvider">An object capable of providing platform and environment specific information.</param>
	/// <param name="proxy">A proxy to be used by the manager when dispatching hits. If null, the default IE proxy is used.</param>
	public TrackerManager(IPlatformInfoProvider platformInfoProvider, IWebProxy proxy)
		: base(proxy)
	{
		trackers = new Dictionary<string, Tracker>();
		this.platformInfoProvider = platformInfoProvider;
		base.UserAgent = platformInfoProvider.UserAgent;
	}

	/// <summary>
	/// Gets a <see cref="T:GoogleAnalytics.Tracker" /> using a given property ID. Will creates a new instance if one does not exist yet.
	/// </summary>
	/// <param name="propertyId">The property ID that the <see cref="T:GoogleAnalytics.Tracker" /> should log to.</param>
	/// <returns>The new or existing instance keyed on the property ID.</returns>
	public virtual Tracker CreateTracker(string propertyId)
	{
		propertyId = propertyId ?? string.Empty;
		if (!trackers.ContainsKey(propertyId))
		{
			Tracker tracker = new Tracker(propertyId, platformInfoProvider, this);
			trackers.Add(propertyId, tracker);
			if (DefaultTracker == null)
			{
				DefaultTracker = tracker;
			}
			return tracker;
		}
		return trackers[propertyId];
	}

	/// <summary>
	/// Removes and cleans up a given <see cref="T:GoogleAnalytics.Tracker" />.
	/// </summary>
	/// <param name="tracker">The instance to remove and clean up.</param>
	public void CloseTracker(Tracker tracker)
	{
		trackers.Remove(tracker.PropertyId);
		if (DefaultTracker == tracker)
		{
			DefaultTracker = null;
		}
	}

	/// <inheritdoc />
	public override void EnqueueHit(IDictionary<string, string> @params)
	{
		if (!AppOptOut)
		{
			base.EnqueueHit(@params);
		}
	}
}
