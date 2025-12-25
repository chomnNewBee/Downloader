using System;
using System.Text;

namespace FiddlerCore.Utilities;

internal static class HexViewHelper
{
	/// <summary>
	/// Pretty-print a Hex view of a byte array. Slow.
	/// </summary>
	/// <param name="inArr">The byte array</param>
	/// <param name="iBytesPerLine">Number of bytes per line</param>
	/// <returns>String containing a pretty-printed array</returns>
	public static string ByteArrayToHexView(byte[] inArr, int iBytesPerLine)
	{
		return ByteArrayToHexView(inArr, iBytesPerLine, inArr.Length, bShowASCII: true);
	}

	/// <summary>
	/// Pretty-print a Hex view of a byte array. Slow.
	/// </summary>
	/// <param name="inArr">The byte array</param>
	/// <param name="iBytesPerLine">Number of bytes per line</param>
	/// <param name="iMaxByteCount">The maximum number of bytes to pretty-print</param>
	/// <returns>String containing a pretty-printed array</returns>
	public static string ByteArrayToHexView(byte[] inArr, int iBytesPerLine, int iMaxByteCount)
	{
		return ByteArrayToHexView(inArr, iBytesPerLine, iMaxByteCount, bShowASCII: true);
	}

	/// <summary>
	/// Pretty-print a Hex view of a byte array. Slow.
	/// </summary>
	/// <param name="inArr">The byte array</param>
	/// <param name="iBytesPerLine">Number of bytes per line</param>
	/// <param name="iMaxByteCount">The maximum number of bytes to pretty-print</param>
	/// <param name="bShowASCII">Show ASCII text at the end of each line</param>
	/// <returns>String containing a pretty-printed array</returns>
	public static string ByteArrayToHexView(byte[] inArr, int iBytesPerLine, int iMaxByteCount, bool bShowASCII)
	{
		return ByteArrayToHexView(inArr, 0, iBytesPerLine, iMaxByteCount, bShowASCII);
	}

	public static string ByteArrayToHexView(byte[] inArr, int iStartAt, int iBytesPerLine, int iMaxByteCount, bool bShowASCII)
	{
		if (inArr == null || inArr.Length == 0)
		{
			return string.Empty;
		}
		if (iBytesPerLine < 1 || iMaxByteCount < 1)
		{
			return string.Empty;
		}
		int iMaxOffset = Math.Min(iMaxByteCount + iStartAt, inArr.Length);
		StringBuilder sbOutput = new StringBuilder(iMaxByteCount * 5);
		int iPtr = iStartAt;
		bool bLastLine = false;
		for (; iPtr < iMaxOffset; iPtr += iBytesPerLine)
		{
			int iLineLen = Math.Min(iBytesPerLine, iMaxOffset - iPtr);
			bLastLine = iLineLen < iBytesPerLine;
			for (int j = 0; j < iLineLen; j++)
			{
				sbOutput.Append(inArr[iPtr + j].ToString("X2"));
				sbOutput.Append(" ");
			}
			if (bLastLine)
			{
				sbOutput.Append(new string(' ', 3 * (iBytesPerLine - iLineLen)));
			}
			if (bShowASCII)
			{
				sbOutput.Append(" ");
				for (int i = 0; i < iLineLen; i++)
				{
					if (inArr[iPtr + i] < 32)
					{
						sbOutput.Append(".");
					}
					else
					{
						sbOutput.Append((char)inArr[iPtr + i]);
					}
				}
				if (bLastLine)
				{
					sbOutput.Append(new string(' ', iBytesPerLine - iLineLen));
				}
			}
			sbOutput.Append("\r\n");
		}
		return sbOutput.ToString();
	}
}
