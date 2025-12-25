using System;
using System.Collections.Generic;

namespace Fiddler;

/// <summary>
/// The Logger object is a simple event log message dispatcher
/// </summary>
public class Logger
{
	/// <summary>
	/// Queue of Messages that are be logged (usually during application startup) until another object has loaded and registered for notification of such Messages
	/// </summary>
	private List<string> queueStartupMessages;

	/// <summary>
	/// The Event to raise when a string is logged
	/// </summary>
	public event EventHandler<LogEventArgs> OnLogString;

	/// <summary>
	/// Creates a Logger object
	/// </summary>
	/// <param name="bQueueStartup">True if a queue should be created to store messages during Fiddler's startup</param>
	public Logger(bool bQueueStartup)
	{
		queueStartupMessages = (bQueueStartup ? new List<string>() : null);
	}

	/// <summary>
	/// Flushes previously-queued messages to the newly attached listener.
	/// </summary>
	internal void FlushStartupMessages()
	{
		if (queueStartupMessages == null)
		{
			return;
		}
		EventHandler<LogEventArgs> evtLogString = this.OnLogString;
		if (evtLogString != null)
		{
			List<string> queueCopy = queueStartupMessages;
			queueStartupMessages = null;
			{
				foreach (string sMsg in queueCopy)
				{
					LogEventArgs olsEA = new LogEventArgs(sMsg);
					evtLogString(this, olsEA);
				}
				return;
			}
		}
		queueStartupMessages = null;
	}

	/// <summary>
	/// Log a string with specified string formatting
	/// </summary>
	/// <param name="format">The format string</param>
	/// <param name="args">The arguments to replace in the string</param>
	public void LogFormat(string format, params object[] args)
	{
		LogString(string.Format(format, args));
	}

	/// <summary>
	/// Log a string
	/// </summary>
	/// <param name="sMsg">The string to log</param>
	public void LogString(string sMsg)
	{
		if (string.IsNullOrEmpty(sMsg))
		{
			return;
		}
		FiddlerApplication.DebugSpew(sMsg);
		if (queueStartupMessages != null)
		{
			lock (queueStartupMessages)
			{
				queueStartupMessages.Add(sMsg);
				return;
			}
		}
		EventHandler<LogEventArgs> evtLogString = this.OnLogString;
		if (evtLogString != null)
		{
			LogEventArgs olsEA = new LogEventArgs(sMsg);
			evtLogString(this, olsEA);
		}
	}
}
