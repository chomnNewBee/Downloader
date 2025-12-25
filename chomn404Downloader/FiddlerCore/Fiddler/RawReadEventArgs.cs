using System;

namespace Fiddler;

/// <summary>
/// When the FiddlerApplication.OnReadResponseBuffer event fires, the raw bytes are available via this object.
/// </summary>
public class RawReadEventArgs : EventArgs
{
	private readonly byte[] _arrData;

	private readonly int _iCountBytes;

	private readonly Session _oS;

	/// <summary>
	/// Set to TRUE to request that upload or download process be aborted as soon as convenient
	/// </summary>
	public bool AbortReading { get; set; }

	/// <summary>
	/// Session for which this responseRead is occurring
	/// </summary>
	public Session sessionOwner => _oS;

	/// <summary>
	/// Byte buffer returned from read. Note: Always of fixed size, check iCountOfBytes to see which bytes were set
	/// </summary>
	public byte[] arrDataBuffer => _arrData;

	/// <summary>
	/// Count of latest read from Socket. If less than 1, response was ended.
	/// </summary>
	public int iCountOfBytes => _iCountBytes;

	internal RawReadEventArgs(Session oS, byte[] arrData, int iCountBytes)
	{
		_arrData = arrData;
		_iCountBytes = iCountBytes;
		_oS = oS;
	}
}
