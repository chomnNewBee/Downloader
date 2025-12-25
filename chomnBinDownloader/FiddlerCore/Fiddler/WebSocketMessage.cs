using System;
using System.IO;
using System.Text;

namespace Fiddler;

/// <summary>
/// A WebSocketMessage stores a single frame of a single WebSocket message
/// http://tools.ietf.org/html/rfc6455
/// </summary>
public class WebSocketMessage
{
	private WSMFlags BitFlags;

	private WebSocket _wsOwner;

	private bool _bIsFinalFragment = false;

	/// <summary>
	/// 3 bits frame-rsv1,frame-rsv2,frame-rsv3
	/// </summary>
	private byte _byteReservedFlags = 0;

	/// <summary>
	/// Is this a Request message?
	/// </summary>
	private bool _bOutbound;

	private int _iID;

	/// <summary>
	/// The WebSocketTimers collection tracks the timestamps for this message
	/// </summary>
	public WebSocketTimers Timers = new WebSocketTimers();

	/// <summary>
	/// The raw payload data, which may be masked.
	/// </summary>
	private byte[] _arrRawPayload;

	/// <summary>
	/// The four-byte payload masking key, if any
	/// </summary>
	private byte[] _arrMask;

	/// <summary>
	/// The type of the WebSocket Message's frame
	/// </summary>
	private WebSocketFrameTypes _wsftType;

	public bool IsFinalFrame => _bIsFinalFragment;

	[CodeDescription("Indicates whether this WebSocketMessage was aborted.")]
	public bool WasAborted => (BitFlags & WSMFlags.Aborted) == WSMFlags.Aborted;

	[CodeDescription("Returns TRUE if this is a Client->Server message, FALSE if this is a message from Server->Client.")]
	public bool IsOutbound => _bOutbound;

	public int ID => _iID;

	public int PayloadLength
	{
		get
		{
			if (_arrRawPayload == null)
			{
				return 0;
			}
			return _arrRawPayload.Length;
		}
	}

	[CodeDescription("Returns the raw payload data, which may be masked.")]
	public byte[] PayloadData
	{
		get
		{
			return _arrRawPayload;
		}
		internal set
		{
			_arrRawPayload = value;
		}
	}

	[CodeDescription("Returns the WebSocketMessage's masking key, if any.")]
	public byte[] MaskingKey
	{
		get
		{
			return _arrMask;
		}
		internal set
		{
			_arrMask = value;
		}
	}

	public WebSocketFrameTypes FrameType
	{
		get
		{
			return _wsftType;
		}
		internal set
		{
			_wsftType = value;
		}
	}

	[CodeDescription("If this is a Close frame, returns the close code. Otherwise, returns -1.")]
	public int iCloseReason
	{
		get
		{
			if (FrameType != WebSocketFrameTypes.Close || _arrRawPayload == null || _arrRawPayload.Length < 2)
			{
				return -1;
			}
			byte[] arrCloseReason = new byte[2]
			{
				_arrRawPayload[0],
				_arrRawPayload[1]
			};
			UnmaskData(arrCloseReason, _arrMask, arrCloseReason);
			return (arrCloseReason[0] << 8) + arrCloseReason[1];
		}
	}

	internal void SetBitFlags(WSMFlags oF)
	{
		BitFlags = oF;
	}

	internal void AssignHeader(byte byteHeader)
	{
		_bIsFinalFragment = 128 == (byteHeader & 0x80);
		_byteReservedFlags = (byte)((byteHeader & 0x70) >> 4);
		FrameType = (WebSocketFrameTypes)(byteHeader & 0xFu);
	}

	[CodeDescription("Cancel transmission of this WebSocketMessage.")]
	public void Abort()
	{
		BitFlags |= WSMFlags.Aborted;
	}

	[CodeDescription("Returns the entire WebSocketMessage, including headers.")]
	public byte[] ToByteArray()
	{
		if (_arrRawPayload == null)
		{
			return Utilities.emptyByteArray;
		}
		MemoryStream oMS = new MemoryStream();
		oMS.WriteByte((byte)((uint)((byte)(_bIsFinalFragment ? 128u : 0u) | (byte)(_byteReservedFlags << 4)) | (uint)FrameType));
		ulong ulPayloadLen = (ulong)_arrRawPayload.Length;
		byte[] arrSize = ((_arrRawPayload.Length < 126) ? new byte[1] { (byte)_arrRawPayload.Length } : ((_arrRawPayload.Length < 65535) ? new byte[3]
		{
			126,
			(byte)(ulPayloadLen >> 8),
			(byte)(ulPayloadLen & 0xFF)
		} : new byte[9]
		{
			127,
			(byte)(ulPayloadLen >> 56),
			(byte)((ulPayloadLen & 0xFF000000000000L) >> 48),
			(byte)((ulPayloadLen & 0xFF0000000000L) >> 40),
			(byte)((ulPayloadLen & 0xFF00000000L) >> 32),
			(byte)((ulPayloadLen & 0xFF000000u) >> 24),
			(byte)((ulPayloadLen & 0xFF0000) >> 16),
			(byte)((ulPayloadLen & 0xFF00) >> 8),
			(byte)(ulPayloadLen & 0xFF)
		}));
		if (_arrMask != null)
		{
			arrSize[0] |= 128;
		}
		oMS.Write(arrSize, 0, arrSize.Length);
		if (_arrMask != null)
		{
			oMS.Write(_arrMask, 0, 4);
		}
		oMS.Write(_arrRawPayload, 0, _arrRawPayload.Length);
		return oMS.ToArray();
	}

	internal WebSocketMessage(WebSocket oWSOwner, int iID, bool bIsOutbound)
	{
		_wsOwner = oWSOwner;
		_iID = iID;
		_bOutbound = bIsOutbound;
	}

	[CodeDescription("Returns all info about this message.")]
	public override string ToString()
	{
		return string.Format("WS{0}\nMessageID:\t{1}.{2}\nMessageType:\t{3}\nPayloadString:\t{4}\nMasking:\t{5}\n", _wsOwner.ToString(), _bOutbound ? "Client" : "Server", _iID, _wsftType, PayloadAsString(), (_arrMask == null) ? "<none>" : BitConverter.ToString(_arrMask));
	}

	/// <summary>
	/// Unmasks the first array into the third, using the second as a masking key.
	/// </summary>
	/// <param name="arrIn"></param>
	/// <param name="arrKey"></param>
	/// <param name="arrOut"></param>
	private static void UnmaskData(byte[] arrIn, byte[] arrKey, byte[] arrOut)
	{
		if (Utilities.IsNullOrEmpty(arrKey))
		{
			Buffer.BlockCopy(arrIn, 0, arrOut, 0, arrIn.Length);
			return;
		}
		for (int idx = 0; idx < arrIn.Length; idx++)
		{
			arrOut[idx] = (byte)(arrIn[idx] ^ arrKey[idx % 4]);
		}
	}

	/// <summary>
	/// Masks the first array's data using the key in the second
	/// </summary>
	/// <param name="arrInOut">The data to be masked</param>
	/// <param name="arrKey">A 4-byte obfuscation key, or null.</param>
	private static void MaskDataInPlace(byte[] arrInOut, byte[] arrKey)
	{
		if (arrKey != null)
		{
			for (int idx = 0; idx < arrInOut.Length; idx++)
			{
				arrInOut[idx] ^= arrKey[idx % 4];
			}
		}
	}

	/// <summary>
	/// Replaces the WebSocketMessage's payload with the specified string, masking if needed.
	/// </summary>
	/// <param name="sPayload"></param>
	[CodeDescription("Replaces the WebSocketMessage's payload with the specified string, masking if needed.")]
	public void SetPayload(string sPayload)
	{
		_SetPayloadWithoutCopy(Encoding.UTF8.GetBytes(sPayload));
	}

	/// <summary>
	/// Copies the provided byte array over the WebSocketMessage's payload, masking if needed.
	/// </summary>
	/// <param name="arrNewPayload"></param>
	[CodeDescription("Replaces the WebSocketMessage's payload with the specified byte array, masking if needed.")]
	public void SetPayload(byte[] arrNewPayload)
	{
		byte[] arrCopy = new byte[arrNewPayload.Length];
		Buffer.BlockCopy(arrNewPayload, 0, arrCopy, 0, arrNewPayload.Length);
		_SetPayloadWithoutCopy(arrCopy);
	}

	/// <summary>
	/// Masks the provided array (if necessary) and assigns it to the WebSocketMessage's payload.
	/// </summary>
	/// <param name="arrNewPayload">New array of data</param>
	private void _SetPayloadWithoutCopy(byte[] arrNewPayload)
	{
		MaskDataInPlace(arrNewPayload, _arrMask);
		_arrRawPayload = arrNewPayload;
	}

	/// <summary>
	/// Return the WebSocketMessage's payload as a string.
	/// </summary>
	/// <returns></returns>
	[CodeDescription("Returns the WebSocketMessage's payload as a string, unmasking if needed.")]
	public string PayloadAsString()
	{
		if (_arrRawPayload == null)
		{
			return "<NoPayload>";
		}
		byte[] arrUnmaskedPayload;
		if (_arrMask != null)
		{
			arrUnmaskedPayload = new byte[_arrRawPayload.Length];
			UnmaskData(_arrRawPayload, _arrMask, arrUnmaskedPayload);
		}
		else
		{
			arrUnmaskedPayload = _arrRawPayload;
		}
		if (_wsftType == WebSocketFrameTypes.Text)
		{
			return Encoding.UTF8.GetString(arrUnmaskedPayload);
		}
		return BitConverter.ToString(arrUnmaskedPayload);
	}

	/// <summary>
	/// Copy the WebSocketMessage's payload into a new Byte Array.
	/// </summary>
	/// <returns>A new byte array containing the (unmasked) payload.</returns>
	[CodeDescription("Returns the WebSocketMessage's payload as byte[], unmasking if needed.")]
	public byte[] PayloadAsBytes()
	{
		if (_arrRawPayload == null)
		{
			return Utilities.emptyByteArray;
		}
		byte[] arrUnmaskedPayload = new byte[_arrRawPayload.Length];
		if (_arrMask != null)
		{
			UnmaskData(_arrRawPayload, _arrMask, arrUnmaskedPayload);
		}
		else
		{
			Buffer.BlockCopy(_arrRawPayload, 0, arrUnmaskedPayload, 0, arrUnmaskedPayload.Length);
		}
		return arrUnmaskedPayload;
	}

	/// <summary>
	/// Serialize this message to a stream
	/// </summary>
	/// <param name="oFS"></param>
	internal void SerializeToStream(Stream oFS)
	{
		byte[] arrMessage = ToByteArray();
		string sTimers = Timers.ToHeaderString();
		string sHeaders = string.Format("{0}: {1}\r\nID: {2}\r\nBitFlags: {3}\r\n{4}\r\n", IsOutbound ? "Request-Length" : "Response-Length", arrMessage.Length, ID, (int)BitFlags, sTimers);
		byte[] arrHeaders = Encoding.ASCII.GetBytes(sHeaders);
		oFS.Write(arrHeaders, 0, arrHeaders.Length);
		oFS.Write(arrMessage, 0, arrMessage.Length);
		oFS.WriteByte(13);
		oFS.WriteByte(10);
	}

	/// <summary>
	/// Add the content of the subequent continuation to me.
	/// </summary>
	/// <param name="oWSM"></param>
	internal void Assemble(WebSocketMessage oWSM)
	{
		BitFlags |= WSMFlags.Assembled;
		MemoryStream oMS = new MemoryStream();
		byte[] arrMine = PayloadAsBytes();
		oMS.Write(arrMine, 0, arrMine.Length);
		byte[] arrNext = oWSM.PayloadAsBytes();
		oMS.Write(arrNext, 0, arrNext.Length);
		SetPayload(oMS.ToArray());
		if (oWSM.IsFinalFrame)
		{
			_bIsFinalFragment = true;
		}
		Timers.dtDoneSend = oWSM.Timers.dtDoneSend;
	}
}
