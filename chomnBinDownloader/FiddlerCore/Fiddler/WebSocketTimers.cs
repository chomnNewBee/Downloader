using System;
using System.Text;

namespace Fiddler;

/// <summary>
/// Timers
/// </summary>
public class WebSocketTimers
{
	/// <summary>
	/// When was this message read from the sender
	/// </summary>
	public DateTime dtDoneRead;

	/// <summary>
	/// When did transmission of this message to the recipient begin
	/// </summary>
	public DateTime dtBeginSend;

	/// <summary>
	/// When did transmission of this message to the recipient end
	/// </summary>
	public DateTime dtDoneSend;

	/// <summary>
	/// Return the timers formatted to be placed in pseudo-headers used in saving the WebSocketMessage to a stream (SAZ).
	/// NOTE: TRAILING \r\n is critical.
	/// </summary>
	/// <returns></returns>
	internal string ToHeaderString()
	{
		StringBuilder sbResult = new StringBuilder();
		if (dtDoneRead.Ticks > 0)
		{
			sbResult.AppendFormat("DoneRead: {0}\r\n", dtDoneRead.ToString("o"));
		}
		if (dtBeginSend.Ticks > 0)
		{
			sbResult.AppendFormat("BeginSend: {0}\r\n", dtBeginSend.ToString("o"));
		}
		if (dtDoneSend.Ticks > 0)
		{
			sbResult.AppendFormat("DoneSend: {0}\r\n", dtDoneSend.ToString("o"));
		}
		if (sbResult.Length < 2)
		{
			sbResult.Append("\r\n");
		}
		return sbResult.ToString();
	}

	public override string ToString()
	{
		return ToString(bMultiLine: false);
	}

	public string ToString(bool bMultiLine)
	{
		if (bMultiLine)
		{
			return $"DoneRead:\t{dtDoneRead:HH:mm:ss.fff}\r\nBeginSend:\t{dtBeginSend:HH:mm:ss.fff}\r\nDoneSend:\t{dtDoneSend:HH:mm:ss.fff}\r\n{((TimeSpan.Zero < dtDoneSend - dtDoneRead) ? $"\r\n\tOverall Elapsed:\t{dtDoneSend - dtDoneRead:h\\:mm\\:ss\\.fff}\r\n" : string.Empty)}";
		}
		return $"DoneRead: {dtDoneRead:HH:mm:ss.fff}, BeginSend: {dtBeginSend:HH:mm:ss.fff}, DoneSend: {dtDoneSend:HH:mm:ss.fff}{((TimeSpan.Zero < dtDoneSend - dtDoneRead) ? $",Overall Elapsed: {dtDoneSend - dtDoneRead:h\\:mm\\:ss\\.fff}" : string.Empty)}";
	}
}
