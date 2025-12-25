using System;
using System.IO;

namespace Fiddler;

/// <summary>
/// This class holds a specialized memory stream with growth characteristics more suitable for reading from a HTTP Stream.
/// The default MemoryStream's Capacity will always grow to 256 bytes, then at least ~2x current capacity up to 1gb (2gb on .NET 4.6), then to the exact length after that.
/// That has three problems:
///
///     The capacity may unnecessarily grow to &gt;85kb, putting the object on the LargeObjectHeap even if we didn't really need 85kb.
///     On 32bit, we may hit a Address Space exhaustion ("Out of memory" exception) prematurely and unnecessarily due to size-doubling
///     After the capacity reaches 1gb in length, the capacity growth never exceeds the length, leading to huge reallocations and copies on every write (fixed in .NET 4.6)
///
/// This class addresses those issues. http://textslashplain.com/2015/08/06/tuning-memorystream/
/// </summary>
internal class PipeReadBuffer : MemoryStream
{
	private static readonly uint LARGE_BUFFER;

	private static readonly uint GROWTH_RATE;

	private const uint LARGE_OBJECT_HEAP_SIZE = 81920u;

	private const uint MAX_ARRAY_INDEX = 2147483591u;

	/// <summary>
	/// A client may submit a "hint" of the expected size. We use that if present.
	/// </summary>
	private uint _HintedSize = 2147483591u;

	static PipeReadBuffer()
	{
		LARGE_BUFFER = 536870911u;
		GROWTH_RATE = 67108864u;
		if (IntPtr.Size == 4)
		{
			LARGE_BUFFER = 67108864u;
			GROWTH_RATE = 16777216u;
		}
	}

	public PipeReadBuffer(bool bIsRequest)
		: base((!bIsRequest) ? 4096 : 0)
	{
	}

	public PipeReadBuffer(int iDefaultCapacity)
		: base(iDefaultCapacity)
	{
	}

	public override void Write(byte[] buffer, int offset, int count)
	{
		int iOrigCapacity = base.Capacity;
		uint iRequiredCapacity = (uint)(base.Position + count);
		if (iRequiredCapacity > iOrigCapacity)
		{
			if (iRequiredCapacity > 2147483591)
			{
				throw new InsufficientMemoryException($"Sorry, the .NET Framework (and Fiddler) cannot handle streams larger than 2 gigabytes. This stream requires {iRequiredCapacity:N0} bytes");
			}
			if (iRequiredCapacity < 81920)
			{
				if (_HintedSize < 81920 && _HintedSize >= iRequiredCapacity)
				{
					Capacity = (int)_HintedSize;
				}
				else if ((long)(iOrigCapacity * 2) > 81920L || (_HintedSize < 2147483591 && _HintedSize >= iRequiredCapacity))
				{
					Capacity = 81920;
				}
			}
			else if (_HintedSize < 2147483591 && _HintedSize >= iRequiredCapacity && _HintedSize < 2097152 + iOrigCapacity * 2)
			{
				Capacity = (int)_HintedSize;
			}
			else if (iRequiredCapacity > LARGE_BUFFER)
			{
				uint iNewSize = iRequiredCapacity + GROWTH_RATE;
				if (iNewSize < 2147483591)
				{
					Capacity = (int)iNewSize;
				}
				else
				{
					Capacity = (int)iRequiredCapacity;
				}
			}
		}
		base.Write(buffer, offset, count);
	}

	/// <summary>
	/// Used by the caller to supply a hint on the expected total size of reads from the pipe.
	/// We cannot blindly trust this value because sometimes the client or server will lie and provide a
	/// huge value that it will never use. This is common for RPC-over-HTTPS tunnels like that used by 
	/// Outlook, for instance.
	///
	/// The Content-Length can also lie by underreporting the size.
	/// </summary>
	/// <param name="iHint">Suggested total buffer size in bytes</param>
	internal void HintTotalSize(uint iHint)
	{
		if (iHint >= 0)
		{
			_HintedSize = iHint;
		}
	}
}
