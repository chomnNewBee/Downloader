using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;

namespace Fiddler;

/// <summary>
/// HTTP Response headers object
/// </summary>
public class HTTPResponseHeaders : HTTPHeaders, ICloneable, IEnumerable<HTTPHeaderItem>, IEnumerable
{
	/// <summary>
	/// Status code from HTTP Response. If setting, also set HTTPResponseStatus too!
	/// </summary>
	[CodeDescription("Status code from HTTP Response. Call SetStatus() instead of manipulating directly.")]
	public int HTTPResponseCode = 0;

	/// <summary>
	/// Code AND Description of Response Status (e.g. '200 OK').
	/// </summary>
	[CodeDescription("Status text from HTTP Response (e.g. '200 OK'). Call SetStatus() instead of manipulating directly.")]
	public string HTTPResponseStatus = string.Empty;

	/// <summary>
	/// Gets or sets the text associated with the response code (e.g. "OK", "Not Found", etc)
	/// </summary>
	public string StatusDescription
	{
		get
		{
			if (string.IsNullOrEmpty(HTTPResponseStatus))
			{
				return string.Empty;
			}
			if (HTTPResponseStatus.IndexOf(' ') < 1)
			{
				return string.Empty;
			}
			return Utilities.TrimBefore(HTTPResponseStatus, ' ');
		}
		set
		{
			HTTPResponseStatus = $"{HTTPResponseCode} {value}";
		}
	}

	/// <summary>
	/// Protect your enumeration using GetReaderLock
	/// </summary>
	public new IEnumerator<HTTPHeaderItem> GetEnumerator()
	{
		return storage.GetEnumerator();
	}

	/// <summary>
	/// Protect your enumeration using GetReaderLock
	/// </summary>
	IEnumerator IEnumerable.GetEnumerator()
	{
		return storage.GetEnumerator();
	}

	/// <summary>
	/// Clone this HTTPResponseHeaders object and return the result cast to an Object
	/// </summary>
	/// <returns>The new response headers object, cast to an object</returns>
	public object Clone()
	{
		HTTPResponseHeaders oNew = (HTTPResponseHeaders)MemberwiseClone();
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
		int iLen = 3;
		iLen += HTTPVersion.StrLen();
		iLen += HTTPResponseStatus.StrLen();
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
	/// Update the response status code and text
	/// </summary>
	/// <param name="iCode">HTTP Status code (e.g. 401)</param>
	/// <param name="sDescription">HTTP Status text (e.g. "Access Denied")</param>
	public void SetStatus(int iCode, string sDescription)
	{
		HTTPResponseCode = iCode;
		HTTPResponseStatus = $"{iCode} {sDescription}";
	}

	/// <summary>
	/// Constructor for HTTP Response headers object
	/// </summary>
	public HTTPResponseHeaders()
	{
	}

	public HTTPResponseHeaders(int iStatus, string[] sHeaders)
		: this(iStatus, "Generated", sHeaders)
	{
	}

	public HTTPResponseHeaders(int iStatusCode, string sStatusText, string[] sHeaders)
	{
		SetStatus(iStatusCode, sStatusText);
		if (sHeaders != null)
		{
			string sErrs = string.Empty;
			Parser.ParseNVPHeaders(this, sHeaders, 0, ref sErrs);
		}
	}

	/// <summary>
	/// Constructor for HTTP Response headers object
	/// </summary>
	/// <param name="encodingForHeaders">Text encoding to be used for this set of Headers when converting to a byte array</param>
	public HTTPResponseHeaders(Encoding encodingForHeaders)
	{
		_HeaderEncoding = encodingForHeaders;
	}

	/// <summary>
	/// Returns a byte array representing the HTTP headers.
	/// </summary>
	/// <param name="prependStatusLine">TRUE if the response status line should be included</param>
	/// <param name="appendEmptyLine">TRUE if there should be a trailing \r\n byte sequence included</param>
	/// <returns>Byte[] containing the headers</returns>
	[CodeDescription("Returns a byte[] representing the HTTP headers.")]
	public byte[] ToByteArray(bool prependStatusLine, bool appendEmptyLine)
	{
		return _HeaderEncoding.GetBytes(ToString(prependStatusLine, appendEmptyLine));
	}

	/// <summary>
	/// Returns a string containing http headers
	/// </summary>
	/// <param name="prependStatusLine">TRUE if the response status line should be included</param>
	/// <param name="appendEmptyLine">TRUE if there should be a trailing CRLF included</param>
	/// <returns>String containing http headers</returns>
	[CodeDescription("Returns a string representing the HTTP headers.")]
	public string ToString(bool prependStatusLine, bool appendEmptyLine)
	{
		StringBuilder sbResult = new StringBuilder(512);
		if (prependStatusLine)
		{
			sbResult.AppendFormat("{0} {1}\r\n", HTTPVersion, HTTPResponseStatus);
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
	/// Returns a string containing the http headers
	/// </summary>
	/// <returns>
	/// Returns a string containing http headers with a status line but no trailing CRLF
	/// </returns>
	[CodeDescription("Returns a string containing the HTTP Response headers.")]
	public override string ToString()
	{
		return ToString(prependStatusLine: true, appendEmptyLine: false);
	}

	/// <summary>
	/// Parses a string and assigns the headers parsed to this object
	/// </summary>
	/// <param name="sHeaders">The header string</param>
	/// <returns>TRUE if the operation succeeded, false otherwise</returns>
	[CodeDescription("Replaces the current Response header set using a string representing the new HTTP headers.")]
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
		HTTPResponseHeaders oCandidateHeaders = null;
		try
		{
			oCandidateHeaders = Parser.ParseResponse(sHeaders);
		}
		catch (Exception)
		{
		}
		if (oCandidateHeaders == null)
		{
			return false;
		}
		SetStatus(oCandidateHeaders.HTTPResponseCode, oCandidateHeaders.StatusDescription);
		HTTPVersion = oCandidateHeaders.HTTPVersion;
		storage = oCandidateHeaders.storage;
		return true;
	}
}
