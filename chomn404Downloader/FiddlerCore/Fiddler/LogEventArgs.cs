using System;

namespace Fiddler;

/// <summary>
/// EventArgs class for the LogEvent handler
/// </summary>
public class LogEventArgs : EventArgs
{
	private readonly string _sMessage;

	/// <summary>
	/// The String which has been logged
	/// </summary>
	public string LogString => _sMessage;

	internal LogEventArgs(string sMsg)
	{
		_sMessage = sMsg;
	}
}
