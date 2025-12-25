using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Fiddler;

/// <summary>
/// HTTP Request headers object
/// </summary>
public class HTTPRequestHeaders : HTTPHeaders, ICloneable, IEnumerable<HTTPHeaderItem>, IEnumerable
{
	private string _UriScheme = "http";

	/// <summary>
	/// The HTTP Method (e.g. GET, POST, etc)
	/// </summary>
	[CodeDescription("HTTP Method or Verb from HTTP Request.")]
	public string HTTPMethod = string.Empty;

	private byte[] _RawPath = Utilities.emptyByteArray;

	private string _Path = string.Empty;

	private string _uriUserInfo;

	/// <summary>
	/// The (lowercased) URI scheme for this request (https, http, or ftp)
	/// </summary>
	[CodeDescription("URI Scheme for this HTTP Request; usually 'http' or 'https'")]
	public string UriScheme
	{
		get
		{
			return _UriScheme ?? string.Empty;
		}
		set
		{
			_UriScheme = value.ToLowerInvariant();
		}
	}

	/// <summary>
	/// Username:Password info for FTP URLs. (either null or "user:pass@")
	/// (Note: It's silly that this contains a trailing @, but whatever...)
	/// </summary>
	[CodeDescription("For FTP URLs, returns either null or user:pass@")]
	public string UriUserInfo
	{
		get
		{
			return _uriUserInfo;
		}
		internal set
		{
			if (string.Empty == value)
			{
				value = null;
			}
			_uriUserInfo = value;
		}
	}

	/// <summary>
	/// Get or set the request path as a string
	/// </summary>
	[CodeDescription("String representing the HTTP Request path, e.g. '/path.htm'.")]
	public string RequestPath
	{
		get
		{
			return _Path ?? string.Empty;
		}
		set
		{
			if (value == null)
			{
				value = string.Empty;
			}
			_Path = value;
			_RawPath = _HeaderEncoding.GetBytes(value);
		}
	}

	/// <summary>
	/// Get or set the request path as a byte array
	/// </summary>
	[CodeDescription("Byte array representing the HTTP Request path.")]
	public byte[] RawPath
	{
		get
		{
			return _RawPath ?? Utilities.emptyByteArray;
		}
		set
		{
			if (value == null)
			{
				value = Utilities.emptyByteArray;
			}
			_RawPath = Utilities.Dupe(value);
			_Path = _HeaderEncoding.GetString(_RawPath);
		}
	}

	/// <summary>
	/// Warning: You should protect your enumeration using the GetReaderLock
	/// </summary>
	public new IEnumerator<HTTPHeaderItem> GetEnumerator()
	{
		return storage.GetEnumerator();
	}

	/// <summary>
	/// Warning: You should protect your enumeration using the GetReaderLock
	/// </summary>
	IEnumerator IEnumerable.GetEnumerator()
	{
		return storage.GetEnumerator();
	}

	/// <summary>
	/// Clones the HTTP request headers 
	/// </summary>
	/// <returns>The new HTTPRequestHeaders object, cast to an object</returns>
	public object Clone()
	{
		HTTPRequestHeaders oNew = (HTTPRequestHeaders)MemberwiseClone();
		try
		{
			GetReaderLock();
			oNew.storage = new List<HTTPHeaderItem>(storage.Count);
			foreach (HTTPHeaderItem oItem in storage)
			{
				oNew.storage.Add(new HTTPHeaderItem(oItem.Name, oItem.Value));
			}
		}
		finally
		{
			FreeReaderLock();
		}
		return oNew;
	}

	public override int ByteCount()
	{
		int iLen = 4;
		iLen += HTTPMethod.StrLen();
		iLen += RequestPath.StrLen();
		iLen += HTTPVersion.StrLen();
		if (!"CONNECT".OICEquals(HTTPMethod))
		{
			iLen += _UriScheme.StrLen();
			iLen += _uriUserInfo.StrLen();
			iLen += base["Host"].StrLen();
			iLen += 3;
		}
		try
		{
			GetReaderLock();
			for (int x = 0; x < storage.Count; x++)
			{
				iLen += 4;
				iLen += storage[x].Name.StrLen();
				iLen += storage[x].Value.StrLen();
			}
		}
		finally
		{
			FreeReaderLock();
		}
		return iLen + 2;
	}

	/// <summary>
	/// Constructor for HTTP Request headers object
	/// </summary>
	public HTTPRequestHeaders()
	{
	}

	public HTTPRequestHeaders(string sPath, string[] sHeaders)
	{
		HTTPMethod = "GET";
		RequestPath = sPath.Trim();
		if (sHeaders != null)
		{
			string sErrs = string.Empty;
			Parser.ParseNVPHeaders(this, sHeaders, 0, ref sErrs);
		}
	}

	/// <summary>
	/// Constructor for HTTP Request headers object
	/// </summary>
	/// <param name="encodingForHeaders">Text encoding to be used for this set of Headers when converting to a byte array</param>
	public HTTPRequestHeaders(Encoding encodingForHeaders)
	{
		_HeaderEncoding = encodingForHeaders;
	}

	/// <summary>
	/// Parses a string and assigns the headers parsed to this object
	/// </summary>
	/// <param name="sHeaders">The header string</param>
	/// <returns>TRUE if the operation succeeded, false otherwise</returns>
	[CodeDescription("Replaces the current Request header set using a string representing the new HTTP headers.")]
	public override bool AssignFromString(string sHeaders)
	{
		if (string.IsNullOrEmpty(sHeaders))
		{
			throw new ArgumentException("Header string must not be null or empty");
		}
		if (!sHeaders.Contains("\r\n\r\n"))
		{
			sHeaders += "\r\n\r\n";
		}
		HTTPRequestHeaders oCandidateHeaders = null;
		try
		{
			oCandidateHeaders = Parser.ParseRequest(sHeaders);
		}
		catch (Exception)
		{
		}
		if (oCandidateHeaders == null)
		{
			return false;
		}
		HTTPMethod = oCandidateHeaders.HTTPMethod;
		_Path = oCandidateHeaders._Path;
		_RawPath = oCandidateHeaders._RawPath;
		_UriScheme = oCandidateHeaders._UriScheme;
		HTTPVersion = oCandidateHeaders.HTTPVersion;
		_uriUserInfo = oCandidateHeaders._uriUserInfo;
		storage = oCandidateHeaders.storage;
		return true;
	}

	/// <summary>
	/// Returns a byte array representing the HTTP headers.
	/// </summary>
	/// <param name="prependVerbLine">TRUE if the HTTP REQUEST line (method+path+httpversion) should be included</param>
	/// <param name="appendEmptyLine">TRUE if there should be a trailing \r\n byte sequence included</param>
	/// <param name="includeProtocolInPath">TRUE if the SCHEME and HOST should be included in the HTTP REQUEST LINE</param>
	/// <returns>The HTTP headers as a byte[]</returns>
	[CodeDescription("Returns current Request Headers as a byte array.")]
	public byte[] ToByteArray(bool prependVerbLine, bool appendEmptyLine, bool includeProtocolInPath)
	{
		return ToByteArray(prependVerbLine, appendEmptyLine, includeProtocolInPath, null);
	}

	/// <summary>
	/// Returns a byte array representing the HTTP headers.
	/// </summary>
	/// <param name="prependVerbLine">TRUE if the HTTP REQUEST line (method+path+httpversion) should be included</param>
	/// <param name="appendEmptyLine">TRUE if there should be a trailing \r\n byte sequence included</param>
	/// <param name="includeProtocolInPath">TRUE if the SCHEME and HOST should be included in the HTTP REQUEST LINE</param>
	/// <param name="sVerbLineHost">Only meaningful if prependVerbLine is TRUE, the host to use in the HTTP REQUEST LINE</param>
	/// <returns>The HTTP headers as a byte[]</returns>
	[CodeDescription("Returns current Request Headers as a byte array.")]
	public byte[] ToByteArray(bool prependVerbLine, bool appendEmptyLine, bool includeProtocolInPath, string sVerbLineHost)
	{
		if (!prependVerbLine)
		{
			return _HeaderEncoding.GetBytes(ToString(prependVerbLine: false, appendEmptyLine, includeProtocolAndHostInPath: false));
		}
		byte[] arrMethod = Encoding.ASCII.GetBytes(HTTPMethod);
		byte[] arrVersion = Encoding.ASCII.GetBytes(HTTPVersion);
		byte[] arrHeaders = _HeaderEncoding.GetBytes(ToString(prependVerbLine: false, appendEmptyLine, includeProtocolAndHostInPath: false));
		MemoryStream oMS = new MemoryStream(arrHeaders.Length + 1024);
		oMS.Write(arrMethod, 0, arrMethod.Length);
		oMS.WriteByte(32);
		if (includeProtocolInPath && !"CONNECT".OICEquals(HTTPMethod))
		{
			if (sVerbLineHost == null)
			{
				sVerbLineHost = base["Host"];
			}
			byte[] arrHost2 = _HeaderEncoding.GetBytes(_UriScheme + "://" + _uriUserInfo + sVerbLineHost);
			oMS.Write(arrHost2, 0, arrHost2.Length);
		}
		if ("CONNECT".OICEquals(HTTPMethod) && sVerbLineHost != null)
		{
			byte[] arrHost = _HeaderEncoding.GetBytes(sVerbLineHost);
			oMS.Write(arrHost, 0, arrHost.Length);
		}
		else
		{
			oMS.Write(_RawPath, 0, _RawPath.Length);
		}
		oMS.WriteByte(32);
		oMS.Write(arrVersion, 0, arrVersion.Length);
		oMS.WriteByte(13);
		oMS.WriteByte(10);
		oMS.Write(arrHeaders, 0, arrHeaders.Length);
		return oMS.ToArray();
	}

	/// <summary>
	/// Returns a string representing the HTTP headers.
	/// </summary>
	/// <param name="prependVerbLine">TRUE if the HTTP REQUEST line (method+path+httpversion) should be included</param>
	/// <param name="appendEmptyLine">TRUE if there should be a trailing CRLF sequence included</param>
	/// <param name="includeProtocolAndHostInPath">TRUE if the SCHEME and HOST should be included in the HTTP REQUEST LINE (Automatically set to FALSE for CONNECT requests)</param>
	/// <returns>The HTTP headers as a string.</returns>
	[CodeDescription("Returns current Request Headers as a string.")]
	public string ToString(bool prependVerbLine, bool appendEmptyLine, bool includeProtocolAndHostInPath)
	{
		StringBuilder sbResult = new StringBuilder(512);
		if (prependVerbLine)
		{
			if (includeProtocolAndHostInPath && !"CONNECT".OICEquals(HTTPMethod))
			{
				sbResult.AppendFormat("{0} {1}://{2}{3}{4} {5}\r\n", HTTPMethod, _UriScheme, _uriUserInfo, base["Host"], RequestPath, HTTPVersion);
			}
			else
			{
				sbResult.AppendFormat("{0} {1} {2}\r\n", HTTPMethod, RequestPath, HTTPVersion);
			}
		}
		try
		{
			GetReaderLock();
			for (int x = 0; x < storage.Count; x++)
			{
				sbResult.AppendFormat("{0}: {1}\r\n", storage[x].Name, storage[x].Value);
			}
		}
		finally
		{
			FreeReaderLock();
		}
		if (appendEmptyLine)
		{
			sbResult.Append("\r\n");
		}
		return sbResult.ToString();
	}

	/// <summary>
	/// Returns a string representing the HTTP headers, without the SCHEME+HOST in the HTTP REQUEST line
	/// </summary>
	/// <param name="prependVerbLine">TRUE if the HTTP REQUEST line (method+path+httpversion) should be included</param>
	/// <param name="appendEmptyLine">TRUE if there should be a trailing CRLF sequence included</param>
	/// <returns>The header string</returns>
	[CodeDescription("Returns a string representing the HTTP Request.")]
	public string ToString(bool prependVerbLine, bool appendEmptyLine)
	{
		return ToString(prependVerbLine, appendEmptyLine, includeProtocolAndHostInPath: false);
	}

	/// <summary>
	/// Returns a string representing the HTTP headers, without the SCHEME+HOST in the HTTP request line, and no trailing CRLF
	/// </summary>
	/// <returns>The header string</returns>
	[CodeDescription("Returns a string representing the HTTP Request.")]
	public override string ToString()
	{
		return ToString(prependVerbLine: true, appendEmptyLine: false, includeProtocolAndHostInPath: false);
	}
}
