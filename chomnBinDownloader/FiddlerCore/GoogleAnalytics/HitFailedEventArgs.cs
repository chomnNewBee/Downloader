using System;

namespace GoogleAnalytics;

/// <summary>
/// Supplies additional information when <see cref="P:GoogleAnalytics.HitFailedEventArgs.Hit" />s fail to send.
/// </summary>
internal sealed class HitFailedEventArgs : EventArgs
{
	/// <summary>
	/// Gets the <see cref="T:System.Exception" /> thrown when the failure occurred.
	/// </summary>
	public Exception Error { get; private set; }

	/// <summary>
	/// Gets the <see cref="P:GoogleAnalytics.HitFailedEventArgs.Hit" /> associated with the event.
	/// </summary>
	public Hit Hit { get; private set; }

	internal HitFailedEventArgs(Hit hit, Exception error)
	{
		Error = error;
		Hit = hit;
	}
}
