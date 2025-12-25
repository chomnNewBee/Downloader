using System;

namespace GoogleAnalytics;

/// <summary>
/// Supplies additional information when <see cref="P:GoogleAnalytics.HitMalformedEventArgs.Hit" />s are malformed and cannot be sent.
/// </summary>
internal sealed class HitMalformedEventArgs : EventArgs
{
	/// <summary>
	/// Gets the HTTP status code that may provide more information about the problem.
	/// </summary>
	public int HttpStatusCode { get; private set; }

	/// <summary>
	/// Gets the <see cref="P:GoogleAnalytics.HitMalformedEventArgs.Hit" /> associated with the event.
	/// </summary>
	public Hit Hit { get; private set; }

	internal HitMalformedEventArgs(Hit hit, int httpStatusCode)
	{
		HttpStatusCode = httpStatusCode;
		Hit = hit;
	}
}
