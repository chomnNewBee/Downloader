using System;

namespace GoogleAnalytics;

/// <summary>
/// Supplies additional information when <see cref="P:GoogleAnalytics.HitSentEventArgs.Hit" />s are successfully sent.
/// </summary>
internal sealed class HitSentEventArgs : EventArgs
{
	/// <summary>
	/// Gets the response text.
	/// </summary>
	public string Response { get; private set; }

	/// <summary>
	/// Gets the <see cref="P:GoogleAnalytics.HitSentEventArgs.Hit" /> associated with the event.
	/// </summary>
	public Hit Hit { get; private set; }

	internal HitSentEventArgs(Hit hit, string response)
	{
		Response = response;
		Hit = hit;
	}
}
