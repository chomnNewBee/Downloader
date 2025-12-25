using System;
using System.IO;
using System.Runtime.InteropServices;

namespace FiddlerCore.PlatformExtensions.Windows;

internal static class XpressCompressionHelperForWindows
{
	[Flags]
	private enum CompressAlgorithm : uint
	{
		Invalid = 0u,
		Null = 1u,
		MSZIP = 2u,
		XPRESS = 3u,
		XPRESS_HUFF = 4u,
		LZMS = 5u,
		RAW = 0x20000000u
	}

	[DllImport("cabinet", SetLastError = true)]
	private static extern bool CreateDecompressor(CompressAlgorithm Algorithm, IntPtr pAllocators, out IntPtr hDecompressor);

	[DllImport("cabinet", SetLastError = true)]
	private static extern bool CloseCompressor(IntPtr hCompressor);

	[DllImport("cabinet", SetLastError = true)]
	private static extern bool Decompress(IntPtr hDecompressor, byte[] arrCompressedData, UIntPtr cbCompressedDataSize, byte[] arrOutputBuffer, IntPtr cbUncompressedBufferSize, out UIntPtr cbUncompressedDataSize);

	[DllImport("cabinet", SetLastError = true)]
	private static extern bool CloseDecompressor(IntPtr hDecompressor);

	/// <summary>
	/// Requires Win8+
	/// Decompress Xpress|Raw blocks used by WSUS, etc.
	/// Introduction to the API is at http://msdn.microsoft.com/en-us/library/windows/desktop/hh920921(v=vs.85).aspx
	/// </summary>
	/// <param name="compressedData"></param>
	/// <returns></returns>
	public static byte[] Decompress(byte[] arrBlock)
	{
		if (arrBlock.Length < 9)
		{
			return new byte[0];
		}
		MemoryStream msResult = new MemoryStream();
		CreateDecompressor(CompressAlgorithm.XPRESS | CompressAlgorithm.RAW, IntPtr.Zero, out var hDecompressor);
		int ixOffset = 0;
		do
		{
			int iDecompressedSize = BitConverter.ToInt32(arrBlock, ixOffset);
			ixOffset += 4;
			if (iDecompressedSize < 0 || iDecompressedSize > 1000000000)
			{
				throw new InvalidDataException($"Uncompressed data was too large {iDecompressedSize:N0} bytes");
			}
			int iCompressedSize = BitConverter.ToInt32(arrBlock, ixOffset);
			ixOffset += 4;
			if (iCompressedSize + ixOffset > arrBlock.Length)
			{
				throw new InvalidDataException($"Expecting {iCompressedSize:N0} bytes of compressed data, but only {arrBlock.Length - ixOffset:N0} bytes remain in this stream");
			}
			byte[] arrCompressed = new byte[iCompressedSize];
			Buffer.BlockCopy(arrBlock, ixOffset, arrCompressed, 0, arrCompressed.Length);
			byte[] bytesOut = new byte[iDecompressedSize];
			Decompress(hDecompressor, arrCompressed, (UIntPtr)(ulong)arrCompressed.Length, bytesOut, (IntPtr)bytesOut.Length, out var pOutDataSize);
			if (pOutDataSize.ToUInt32() != iDecompressedSize)
			{
			}
			msResult.Write(bytesOut, 0, (int)pOutDataSize.ToUInt32());
			ixOffset += iCompressedSize;
		}
		while (ixOffset < arrBlock.Length);
		CloseDecompressor(hDecompressor);
		return msResult.ToArray();
	}
}
