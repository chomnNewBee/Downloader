using System;
using System.Globalization;
using System.IO;

namespace Fiddler;

/// <summary>
/// The Parser class exposes static methods used to parse strings or byte arrays into HTTP messages.
/// </summary>
public class Parser
{
	/// <summary>
	/// Given a byte[] representing a request, determines the offsets of the components of the line. WARNING: Input MUST contain a LF or an exception will be thrown
	/// </summary>
	/// <param name="arrRequest">Byte array of the request</param>
	/// <param name="ixURIOffset">Returns the index of the byte of the URI in the Request line</param>
	/// <param name="iURILen">Returns the length of the URI in the Request line</param>
	/// <param name="ixHeaderNVPOffset">Returns the index of the first byte of the name/value header pairs</param>
	internal static void CrackRequestLine(byte[] arrRequest, out int ixURIOffset, out int iURILen, out int ixHeaderNVPOffset, out string sMalformedURI)
	{
		ixURIOffset = (iURILen = (ixHeaderNVPOffset = 0));
		int ixPtr = 0;
		sMalformedURI = null;
		do
		{
			if (32 == arrRequest[ixPtr])
			{
				if (ixURIOffset == 0)
				{
					ixURIOffset = ixPtr + 1;
				}
				else if (iURILen == 0)
				{
					iURILen = ixPtr - ixURIOffset;
				}
				else
				{
					sMalformedURI = "Extra whitespace found in Request Line";
				}
			}
			else if (arrRequest[ixPtr] == 10)
			{
				ixHeaderNVPOffset = ixPtr + 1;
			}
			ixPtr++;
		}
		while (ixHeaderNVPOffset == 0);
	}

	/// <summary>
	///
	/// </summary>
	/// <param name="arrData"></param>
	/// <param name="iBodySeekProgress">Index of final byte of headers, if found, or location that search should resume next time</param>
	/// <param name="lngDataLen"></param>
	/// <param name="oWarnings"></param>
	/// <returns></returns>
	internal static bool FindEndOfHeaders(byte[] arrData, ref int iBodySeekProgress, long lngDataLen, out HTTPHeaderParseWarnings oWarnings)
	{
		oWarnings = HTTPHeaderParseWarnings.None;
		while (true)
		{
			bool bFoundNewline = false;
			while (iBodySeekProgress < lngDataLen - 1)
			{
				if (10 == arrData[iBodySeekProgress++])
				{
					bFoundNewline = true;
					break;
				}
			}
			if (!bFoundNewline)
			{
				return false;
			}
			if (10 == arrData[iBodySeekProgress])
			{
				oWarnings = HTTPHeaderParseWarnings.EndedWithLFLF;
				return true;
			}
			if (13 == arrData[iBodySeekProgress])
			{
				break;
			}
			iBodySeekProgress++;
		}
		iBodySeekProgress++;
		if (iBodySeekProgress < lngDataLen)
		{
			if (10 == arrData[iBodySeekProgress])
			{
				if (13 != arrData[iBodySeekProgress - 3])
				{
					oWarnings = HTTPHeaderParseWarnings.EndedWithLFCRLF;
				}
				return true;
			}
			oWarnings = HTTPHeaderParseWarnings.Malformed;
			return false;
		}
		if (iBodySeekProgress > 3)
		{
			iBodySeekProgress -= 4;
		}
		else
		{
			iBodySeekProgress = 0;
		}
		return false;
	}

	private static bool IsPrefixedWithWhitespace(string s)
	{
		if (s.Length > 0 && char.IsWhiteSpace(s[0]))
		{
			return true;
		}
		return false;
	}

	/// <summary>
	/// Parse out HTTP Header lines.
	/// </summary>
	/// <param name="oHeaders">Header collection to *append* headers to</param>
	/// <param name="sHeaderLines">Array of Strings</param>
	/// <param name="iStartAt">Index into array at which parsing should start</param>
	/// <param name="sErrors">String containing any errors encountered</param>
	/// <returns>TRUE if there were no errors, false otherwise</returns>
	internal static bool ParseNVPHeaders(HTTPHeaders oHeaders, string[] sHeaderLines, int iStartAt, ref string sErrors)
	{
		bool bResult = true;
		int ixHeader = iStartAt;
		HTTPHeaderItem oNewHeader = null;
		while (ixHeader < sHeaderLines.Length)
		{
			int ixToken = sHeaderLines[ixHeader].IndexOf(':');
			if (ixToken > 0)
			{
				oNewHeader = oHeaders.Add(sHeaderLines[ixHeader].Substring(0, ixToken), sHeaderLines[ixHeader].Substring(ixToken + 1).TrimStart(' ', '\t'));
			}
			else if (ixToken == 0)
			{
				oNewHeader = null;
				sErrors += $"Missing Header name #{1 + ixHeader - iStartAt}, {sHeaderLines[ixHeader]}\n";
				bResult = false;
			}
			else
			{
				oNewHeader = oHeaders.Add(sHeaderLines[ixHeader], string.Empty);
				sErrors += $"Missing colon in header #{1 + ixHeader - iStartAt}, {sHeaderLines[ixHeader]}\n";
				bResult = false;
			}
			ixHeader++;
			bool bIsContinuation = oNewHeader != null && ixHeader < sHeaderLines.Length && IsPrefixedWithWhitespace(sHeaderLines[ixHeader]);
			while (bIsContinuation)
			{
				FiddlerApplication.Log.LogString("[HTTPWarning] Header folding detected. Not all clients properly handle folded headers.");
				oNewHeader.Value = oNewHeader.Value + " " + sHeaderLines[ixHeader].TrimStart(' ', '\t');
				ixHeader++;
				bIsContinuation = ixHeader < sHeaderLines.Length && IsPrefixedWithWhitespace(sHeaderLines[ixHeader]);
			}
		}
		return bResult;
	}

	/// <summary>
	/// Given a byte array, determines the Headers length
	/// </summary>
	/// <param name="arrData">Input array of data</param>
	/// <param name="iHeadersLen">Returns the calculated length of the headers.</param>
	/// <param name="iEntityBodyOffset">Returns the calculated start of the response body.</param>
	/// <param name="outWarnings">Any HTTPHeaderParseWarnings discovered during parsing.</param>
	/// <returns>True, if the parsing was successful.</returns>
	public static bool FindEntityBodyOffsetFromArray(byte[] arrData, out int iHeadersLen, out int iEntityBodyOffset, out HTTPHeaderParseWarnings outWarnings)
	{
		if (arrData != null && arrData.Length >= 2)
		{
			int iBodySeekProgress = 0;
			long lngDataLen = arrData.Length;
			if (FindEndOfHeaders(arrData, ref iBodySeekProgress, lngDataLen, out outWarnings))
			{
				iEntityBodyOffset = iBodySeekProgress + 1;
				switch (outWarnings)
				{
				case HTTPHeaderParseWarnings.None:
					iHeadersLen = iBodySeekProgress - 3;
					return true;
				case HTTPHeaderParseWarnings.EndedWithLFLF:
					iHeadersLen = iBodySeekProgress - 1;
					return true;
				case HTTPHeaderParseWarnings.EndedWithLFCRLF:
					iHeadersLen = iBodySeekProgress - 2;
					return true;
				}
			}
		}
		iHeadersLen = (iEntityBodyOffset = -1);
		outWarnings = HTTPHeaderParseWarnings.Malformed;
		return false;
	}

	private static int _GetEntityLengthFromHeaders(HTTPHeaders oHeaders, MemoryStream strmData)
	{
		if (oHeaders.ExistsAndEquals("Transfer-Encoding", "chunked"))
		{
			if (Utilities.IsChunkedBodyComplete(null, strmData, strmData.Position, out var _, out var lngEndOfData))
			{
				return (int)(lngEndOfData - strmData.Position);
			}
			return (int)(strmData.Length - strmData.Position);
		}
		string sCL = oHeaders["Content-Length"];
		if (!string.IsNullOrEmpty(sCL))
		{
			long iEntityLength = 0L;
			if (!long.TryParse(sCL, NumberStyles.Integer, NumberFormatInfo.InvariantInfo, out iEntityLength) || iEntityLength < 0)
			{
				return (int)(strmData.Length - strmData.Position);
			}
			return (int)iEntityLength;
		}
		if (oHeaders.ExistsAndContains("Connection", "close"))
		{
			return (int)(strmData.Length - strmData.Position);
		}
		return 0;
	}

	/// <summary>
	/// Given a MemoryStream, attempts to parse a HTTP Request starting at the current position.
	/// </summary>
	/// <returns>TRUE if a request could be parsed, FALSE otherwise</returns>
	public static bool TakeRequest(MemoryStream strmClient, out HTTPRequestHeaders headersRequest, out byte[] arrRequestBody)
	{
		headersRequest = null;
		arrRequestBody = Utilities.emptyByteArray;
		if (strmClient.Length - strmClient.Position < 16)
		{
			return false;
		}
		byte[] arrData = strmClient.GetBuffer();
		long lngDataLen = strmClient.Length;
		int iBodySeekProgress = (int)strmClient.Position;
		if (!FindEndOfHeaders(arrData, ref iBodySeekProgress, lngDataLen, out var _))
		{
			return false;
		}
		byte[] arrHeaders = new byte[1 + iBodySeekProgress - strmClient.Position];
		strmClient.Read(arrHeaders, 0, arrHeaders.Length);
		string sHeaders = CONFIG.oHeaderEncoding.GetString(arrHeaders);
		headersRequest = ParseRequest(sHeaders);
		if (headersRequest != null)
		{
			int iBodyLen = _GetEntityLengthFromHeaders(headersRequest, strmClient);
			arrRequestBody = new byte[iBodyLen];
			strmClient.Read(arrRequestBody, 0, arrRequestBody.Length);
			return true;
		}
		return false;
	}

	/// <summary>
	/// Given a MemoryStream, attempts to parse a HTTP Response starting at the current position
	/// </summary>
	/// <returns>TRUE if a response could be parsed, FALSE otherwise</returns>
	public static bool TakeResponse(MemoryStream strmServer, string sRequestMethod, out HTTPResponseHeaders headersResponse, out byte[] arrResponseBody)
	{
		headersResponse = null;
		arrResponseBody = Utilities.emptyByteArray;
		if (strmServer.Length - strmServer.Position < 16)
		{
			return false;
		}
		byte[] arrData = strmServer.GetBuffer();
		long lngDataLen = strmServer.Length;
		int iBodySeekProgress = (int)strmServer.Position;
		if (!FindEndOfHeaders(arrData, ref iBodySeekProgress, lngDataLen, out var _))
		{
			return false;
		}
		byte[] arrHeaders = new byte[1 + iBodySeekProgress - strmServer.Position];
		strmServer.Read(arrHeaders, 0, arrHeaders.Length);
		string sHeaders = CONFIG.oHeaderEncoding.GetString(arrHeaders);
		headersResponse = ParseResponse(sHeaders);
		if (headersResponse != null)
		{
			if (sRequestMethod == "HEAD")
			{
				return true;
			}
			int iBodyLen = _GetEntityLengthFromHeaders(headersResponse, strmServer);
			if (!(sRequestMethod == "CONNECT") || headersResponse.HTTPResponseCode == 200)
			{
			}
			arrResponseBody = new byte[iBodyLen];
			strmServer.Read(arrResponseBody, 0, arrResponseBody.Length);
			return true;
		}
		return false;
	}

	/// <summary>
	/// Parse the HTTP Request into a headers object.
	/// </summary>
	/// <param name="sRequest">The HTTP Request string, including *at least the headers* with a trailing CRLFCRLF</param>
	/// <returns>HTTPRequestHeaders parsed from the string.</returns>
	public static HTTPRequestHeaders ParseRequest(string sRequest)
	{
		string[] Lines = _GetHeaderLines(sRequest);
		if (Lines == null)
		{
			return null;
		}
		HTTPRequestHeaders oRequestHeaders = new HTTPRequestHeaders(CONFIG.oHeaderEncoding);
		int ixToken = Lines[0].IndexOf(' ');
		if (ixToken > 0)
		{
			oRequestHeaders.HTTPMethod = Lines[0].Substring(0, ixToken).ToUpperInvariant();
			Lines[0] = Lines[0].Substring(ixToken).Trim();
		}
		ixToken = Lines[0].LastIndexOf(' ');
		if (ixToken > 0)
		{
			string sRequestPath = Lines[0].Substring(0, ixToken);
			oRequestHeaders.HTTPVersion = Lines[0].Substring(ixToken).Trim().ToUpperInvariant();
			string sHostAndUserInfo = null;
			if (sRequestPath.OICStartsWith("http://"))
			{
				oRequestHeaders.UriScheme = "http";
				ixToken = sRequestPath.IndexOfAny(new char[2] { '/', '?' }, 7);
				if (ixToken == -1)
				{
					sHostAndUserInfo = sRequestPath.Substring(7);
					oRequestHeaders.RequestPath = "/";
				}
				else
				{
					sHostAndUserInfo = sRequestPath.Substring(7, ixToken - 7);
					oRequestHeaders.RequestPath = sRequestPath.Substring(ixToken);
				}
			}
			else if (sRequestPath.OICStartsWith("https://"))
			{
				oRequestHeaders.UriScheme = "https";
				ixToken = sRequestPath.IndexOfAny(new char[2] { '/', '?' }, 8);
				if (ixToken == -1)
				{
					sHostAndUserInfo = sRequestPath.Substring(8);
					oRequestHeaders.RequestPath = "/";
				}
				else
				{
					sHostAndUserInfo = sRequestPath.Substring(8, ixToken - 8);
					oRequestHeaders.RequestPath = sRequestPath.Substring(ixToken);
				}
			}
			else if (sRequestPath.OICStartsWith("ftp://"))
			{
				oRequestHeaders.UriScheme = "ftp";
				ixToken = sRequestPath.IndexOf('/', 6);
				if (ixToken == -1)
				{
					sHostAndUserInfo = sRequestPath.Substring(6);
					oRequestHeaders.RequestPath = "/";
				}
				else
				{
					sHostAndUserInfo = sRequestPath.Substring(6, ixToken - 6);
					oRequestHeaders.RequestPath = sRequestPath.Substring(ixToken);
				}
			}
			else
			{
				oRequestHeaders.RequestPath = sRequestPath;
			}
			if (sHostAndUserInfo != null)
			{
				int ixAt = sHostAndUserInfo.IndexOf("@");
				if (ixAt > -1)
				{
					oRequestHeaders.UriUserInfo = Utilities.TrimTo(sHostAndUserInfo, ixAt + 1);
					sHostAndUserInfo = sHostAndUserInfo.Substring(ixAt + 1);
				}
			}
			string sErrors = string.Empty;
			if (!ParseNVPHeaders(oRequestHeaders, Lines, 1, ref sErrors))
			{
			}
			if (!string.IsNullOrEmpty(sHostAndUserInfo) && !oRequestHeaders.Exists("Host"))
			{
				oRequestHeaders["Host"] = sHostAndUserInfo.ToLower();
			}
			return oRequestHeaders;
		}
		return null;
	}

	/// <summary>
	/// Break headers off, then convert CRLFs into LFs
	/// </summary>
	/// <param name="sInput"></param>
	/// <returns></returns>
	private static string[] _GetHeaderLines(string sInput)
	{
		if (sInput.Length < 2)
		{
			return null;
		}
		int ixEndofHeaders = sInput.IndexOf("\r\n\r\n", StringComparison.Ordinal);
		if (ixEndofHeaders < 1)
		{
			ixEndofHeaders = sInput.Length;
		}
		string[] Lines = sInput.Substring(0, ixEndofHeaders).Replace("\r\n", "\n").Split(new char[1] { '\n' });
		if (Lines == null || Lines.Length < 1)
		{
			return null;
		}
		return Lines;
	}

	/// <summary>
	/// Parse the HTTP Response into a headers object.
	/// </summary>
	/// <param name="sResponse">The HTTP response as a string, including at least the headers.</param>
	/// <returns>HTTPResponseHeaders parsed from the string.</returns>
	public static HTTPResponseHeaders ParseResponse(string sResponse)
	{
		string[] Lines = _GetHeaderLines(sResponse);
		if (Lines == null)
		{
			return null;
		}
		HTTPResponseHeaders oResponseHeaders = new HTTPResponseHeaders(CONFIG.oHeaderEncoding);
		int ixToken = Lines[0].IndexOf(' ');
		if (ixToken > 0)
		{
			oResponseHeaders.HTTPVersion = Lines[0].Substring(0, ixToken).ToUpperInvariant();
			Lines[0] = Lines[0].Substring(ixToken + 1).Trim();
			if (!oResponseHeaders.HTTPVersion.OICStartsWith("HTTP/"))
			{
				return null;
			}
			oResponseHeaders.HTTPResponseStatus = Lines[0];
			bool bGotStatusCode = false;
			ixToken = Lines[0].IndexOf(' ');
			if (!((ixToken <= 0) ? int.TryParse(Lines[0].Trim(), NumberStyles.Integer, NumberFormatInfo.InvariantInfo, out oResponseHeaders.HTTPResponseCode) : int.TryParse(Lines[0].Substring(0, ixToken).Trim(), NumberStyles.Integer, NumberFormatInfo.InvariantInfo, out oResponseHeaders.HTTPResponseCode)))
			{
				return null;
			}
			string sErrors = string.Empty;
			if (!ParseNVPHeaders(oResponseHeaders, Lines, 1, ref sErrors))
			{
			}
			return oResponseHeaders;
		}
		return null;
	}
}
