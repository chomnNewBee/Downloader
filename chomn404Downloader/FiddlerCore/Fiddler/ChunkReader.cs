using System.IO;

namespace Fiddler;

/// <summary>
/// Class allows finding the end of a body sent using Transfer-Encoding: Chunked
/// </summary>
internal class ChunkReader
{
	private ChunkedTransferState _state;

	private int _cbRemainingInBlock;

	private int _iOverage = 0;

	private int _iEntityLength = 0;

	internal ChunkedTransferState state => _state;

	internal ChunkReader()
	{
		_state = ChunkedTransferState.ReadStartOfSize;
	}

	private int HexValue(byte b)
	{
		if (b >= 48 && b <= 57)
		{
			return b - 48;
		}
		if (b >= 65 && b <= 70)
		{
			return 10 + (b - 65);
		}
		if (b >= 97 && b <= 102)
		{
			return 10 + (b - 97);
		}
		return -1;
	}

	internal ChunkedTransferState pushBytes(byte[] arrData, int iOffset, int iLen)
	{
		while (iLen > 0)
		{
			switch (_state)
			{
			case ChunkedTransferState.ReadStartOfSize:
			{
				iLen--;
				int iFirstVal = HexValue(arrData[iOffset++]);
				if (iFirstVal < 0)
				{
					return _state = ChunkedTransferState.Malformed;
				}
				if (_cbRemainingInBlock != 0)
				{
					throw new InvalidDataException("?");
				}
				_cbRemainingInBlock = iFirstVal;
				_state = ChunkedTransferState.ReadingSize;
				break;
			}
			case ChunkedTransferState.ReadingSize:
			{
				iLen--;
				byte c = arrData[iOffset++];
				int iVal = HexValue(c);
				if (iVal > -1)
				{
					_cbRemainingInBlock = _cbRemainingInBlock * 16 + iVal;
					break;
				}
				FiddlerApplication.DebugSpew("Reached Non-Size character '0x{0:X}'; block size is {1}", c, _cbRemainingInBlock);
				switch (c)
				{
				case 59:
					_state = ChunkedTransferState.ReadingChunkExtToCR;
					break;
				case 13:
					_state = ChunkedTransferState.ReadLFAfterChunkHeader;
					break;
				default:
					return _state = ChunkedTransferState.Malformed;
				}
				break;
			}
			case ChunkedTransferState.ReadingChunkExtToCR:
				do
				{
					iLen--;
					if (arrData[iOffset++] == 13)
					{
						_state = ChunkedTransferState.ReadLFAfterChunkHeader;
						break;
					}
				}
				while (iLen > 0);
				break;
			case ChunkedTransferState.ReadLFAfterChunkHeader:
				iLen--;
				if (arrData[iOffset++] != 10)
				{
					return _state = ChunkedTransferState.Malformed;
				}
				_state = ((_cbRemainingInBlock == 0) ? ChunkedTransferState.ReadStartOfTrailer : ChunkedTransferState.ReadingBlock);
				break;
			case ChunkedTransferState.ReadingBlock:
				if (_cbRemainingInBlock > iLen)
				{
					_cbRemainingInBlock -= iLen;
					_iEntityLength += iLen;
					return ChunkedTransferState.ReadingBlock;
				}
				if (_cbRemainingInBlock == iLen)
				{
					_cbRemainingInBlock = 0;
					_iEntityLength += iLen;
					return _state = ChunkedTransferState.ReadCRAfterBlock;
				}
				_iEntityLength += _cbRemainingInBlock;
				iLen -= _cbRemainingInBlock;
				iOffset += _cbRemainingInBlock;
				_cbRemainingInBlock = 0;
				_state = ChunkedTransferState.ReadCRAfterBlock;
				break;
			case ChunkedTransferState.ReadCRAfterBlock:
				iLen--;
				if (arrData[iOffset++] != 13)
				{
					return _state = ChunkedTransferState.Malformed;
				}
				_state = ChunkedTransferState.ReadLFAfterBlock;
				break;
			case ChunkedTransferState.ReadLFAfterBlock:
				iLen--;
				if (arrData[iOffset++] != 10)
				{
					return _state = ChunkedTransferState.Malformed;
				}
				_state = ChunkedTransferState.ReadStartOfSize;
				if (_cbRemainingInBlock != 0)
				{
					FiddlerApplication.Log.LogFormat("! BUG BUG BUG Expecting {0} more", _cbRemainingInBlock);
				}
				break;
			case ChunkedTransferState.ReadStartOfTrailer:
				iLen--;
				_state = ((arrData[iOffset++] == 13) ? ChunkedTransferState.ReadFinalLF : ChunkedTransferState.ReadToTrailerCR);
				break;
			case ChunkedTransferState.ReadToTrailerCR:
				iLen--;
				if (arrData[iOffset++] == 13)
				{
					_state = ChunkedTransferState.ReadTrailerLF;
				}
				break;
			case ChunkedTransferState.ReadTrailerLF:
				iLen--;
				_state = ((arrData[iOffset++] == 10) ? ChunkedTransferState.ReadStartOfTrailer : ChunkedTransferState.Malformed);
				break;
			case ChunkedTransferState.ReadFinalLF:
				iLen--;
				_state = ((arrData[iOffset++] == 10) ? ChunkedTransferState.Completed : ChunkedTransferState.Malformed);
				break;
			case ChunkedTransferState.Completed:
				_iOverage = iLen;
				return _state = ChunkedTransferState.Overread;
			default:
				throw new InvalidDataException("We should never get called in state: " + _state);
			}
		}
		return _state;
	}

	internal int getOverage()
	{
		return _iOverage;
	}

	/// <summary>
	/// Number of bytes in the body (sans chunk headers, CRLFs, and trailers)
	/// </summary>
	/// <returns></returns>
	internal int getEntityLength()
	{
		return _iEntityLength;
	}
}
