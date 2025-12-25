using System;

namespace Fiddler;

/// <summary>
/// EventArgs class for the ISessionImporter and ISessionExporter interface callbacks
/// </summary>
public class ProgressCallbackEventArgs : EventArgs
{
	private readonly string _sProgressText;

	private readonly int _PercentDone;

	/// <summary>
	/// Set to TRUE to request that Import/Export process be aborted as soon as convenient
	/// </summary>
	public bool Cancel { get; set; }

	/// <summary>
	/// The string message of the notification
	/// </summary>
	public string ProgressText => _sProgressText;

	/// <summary>
	/// The percentage completed
	/// </summary>
	public int PercentComplete => _PercentDone;

	/// <summary>
	/// Progress Callback 
	/// </summary>
	/// <param name="flCompletionRatio">Float indicating completion ratio, 0.0 to 1.0. Set to 0 if unknown.</param>
	/// <param name="sProgressText">Short string describing current operation, progress, etc</param>
	public ProgressCallbackEventArgs(float flCompletionRatio, string sProgressText)
	{
		_sProgressText = sProgressText ?? string.Empty;
		_PercentDone = (int)Math.Truncate(100f * Math.Max(0f, Math.Min(1f, flCompletionRatio)));
	}
}
