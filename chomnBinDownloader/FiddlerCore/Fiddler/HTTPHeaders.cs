using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Threading;

namespace Fiddler;

/// <summary>
/// Base class for RequestHeaders and ResponseHeaders
/// </summary>
public abstract class HTTPHeaders
{
	/// <summary>
	/// Text encoding to be used when converting this header object to/from a byte array
	/// </summary>
	protected Encoding _HeaderEncoding = CONFIG.oHeaderEncoding;

	/// <summary>
	/// HTTP version (e.g. HTTP/1.1)
	/// </summary>
	[CodeDescription("HTTP version (e.g. HTTP/1.1).")]
	public string HTTPVersion = "HTTP/1.1";

	/// <summary>
	/// Storage for individual HTTPHeaderItems in this header collection
	/// NB: Using a list is important, as order can matter
	/// </summary>
	protected List<HTTPHeaderItem> storage = new List<HTTPHeaderItem>();

	/// <summary>
	/// Gets or sets the value of a header. In the case of Gets, the value of the first header of that name is returned.
	/// If the header does not exist, returns null.
	/// In the case of Sets, the value of the first header of that name is updated.  
	/// If the header does not exist, it is added.
	/// </summary>
	[CodeDescription("Indexer property. Gets or sets the value of a header. In the case of Gets, the value of the FIRST header of that name is returned.\nIf the header does not exist, returns null.\nIn the case of Sets, the value of the FIRST header of that name is updated.\nIf the header does not exist, it is added.")]
	public string this[string HeaderName]
	{
		get
		{
			try
			{
				GetReaderLock();
				for (int x = 0; x < storage.Count; x++)
				{
					if (string.Equals(storage[x].Name, HeaderName, StringComparison.OrdinalIgnoreCase))
					{
						return storage[x].Value;
					}
				}
				return string.Empty;
			}
			finally
			{
				FreeReaderLock();
			}
		}
		set
		{
			for (int x = 0; x < storage.Count; x++)
			{
				if (string.Equals(storage[x].Name, HeaderName, StringComparison.OrdinalIgnoreCase))
				{
					storage[x].Value = value;
					return;
				}
			}
			Add(HeaderName, value);
		}
	}

	/// <summary>
	/// Indexer property. Returns HTTPHeaderItem by index. Throws Exception if index out of bounds
	/// </summary>
	[CodeDescription("Indexer property. Returns HTTPHeaderItem by index.")]
	public HTTPHeaderItem this[int iHeaderNumber]
	{
		get
		{
			try
			{
				GetReaderLock();
				return storage[iHeaderNumber];
			}
			finally
			{
				FreeReaderLock();
			}
		}
		set
		{
			try
			{
				GetWriterLock();
				storage[iHeaderNumber] = value;
			}
			finally
			{
				FreeWriterLock();
			}
		}
	}

	/// <summary>
	/// Get the Reader Lock if you plan to enumerate the Storage collection.
	/// </summary>
	protected internal void GetReaderLock()
	{
		Monitor.Enter(storage);
	}

	protected internal void FreeReaderLock()
	{
		Monitor.Exit(storage);
	}

	/// <summary>
	/// Get the Writer Lock if you plan to change the Storage collection.
	/// NB: You only need this lock if you plan to change the collection itself; you can party on the items in the collection if you like without locking.
	/// </summary>
	protected void GetWriterLock()
	{
		Monitor.Enter(storage);
	}

	/// <summary>
	/// If you get the Writer lock, Free it ASAP or you're going to hang or deadlock the Session
	/// </summary>
	protected void FreeWriterLock()
	{
		Monitor.Exit(storage);
	}

	public abstract bool AssignFromString(string sHeaders);

	/// <summary>
	/// Get byte count of this HTTP header instance.
	/// NOTE: This method should've been abstract.
	/// </summary>
	/// <returns>Byte Count</returns>
	public virtual int ByteCount()
	{
		return ToString().Length;
	}

	internal bool TryGetEntitySize(out uint iSize)
	{
		iSize = 0u;
		if (ExistsAndEquals("Transfer-Encoding", "chunked"))
		{
			return false;
		}
		if (uint.TryParse(this["Content-Length"], NumberStyles.Integer, NumberFormatInfo.InvariantInfo, out iSize))
		{
			return true;
		}
		return false;
	}

	/// <summary>
	/// Number of HTTP headers
	/// </summary>
	/// <returns>Number of HTTP headers</returns>
	[CodeDescription("Returns an integer representing the number of headers.")]
	public int Count()
	{
		try
		{
			GetReaderLock();
			return storage.Count;
		}
		finally
		{
			FreeReaderLock();
		}
	}

	/// <summary>
	/// Returns all instances of the named header
	/// </summary>
	/// <param name="sHeaderName">Header name</param>
	/// <returns>List of instances of the named header</returns>
	public List<HTTPHeaderItem> FindAll(string sHeaderName)
	{
		try
		{
			GetReaderLock();
			return storage.FindAll((HTTPHeaderItem oHI) => string.Equals(sHeaderName, oHI.Name, StringComparison.OrdinalIgnoreCase));
		}
		finally
		{
			FreeReaderLock();
		}
	}

	/// <summary>
	/// Copies the Headers to a new array.
	/// Prefer this method over the enumerator to avoid cross-thread problems.
	/// </summary>
	/// <returns>An array containing HTTPHeaderItems</returns>
	public HTTPHeaderItem[] ToArray()
	{
		try
		{
			GetReaderLock();
			return storage.ToArray();
		}
		finally
		{
			FreeReaderLock();
		}
	}

	/// <summary>
	/// Returns all values of the named header in a single string, delimited by commas
	/// </summary>
	/// <param name="sHeaderName">Header</param>
	/// <returns>Each, Header's, Value</returns>
	public string AllValues(string sHeaderName)
	{
		List<HTTPHeaderItem> oHIs = FindAll(sHeaderName);
		if (oHIs.Count == 0)
		{
			return string.Empty;
		}
		if (oHIs.Count == 1)
		{
			return oHIs[0].Value;
		}
		List<string> sValues = new List<string>();
		foreach (HTTPHeaderItem oHI in oHIs)
		{
			sValues.Add(oHI.Value);
		}
		return string.Join(", ", sValues.ToArray());
	}

	/// <summary>
	/// Returns the count of instances of the named header
	/// </summary>
	/// <param name="sHeaderName">Header name</param>
	/// <returns>Count of instances of the named header</returns>
	public int CountOf(string sHeaderName)
	{
		int iResult = 0;
		try
		{
			GetReaderLock();
			storage.ForEach(delegate(HTTPHeaderItem oHI)
			{
				if (string.Equals(sHeaderName, oHI.Name, StringComparison.OrdinalIgnoreCase))
				{
					int num = iResult + 1;
					iResult = num;
				}
			});
		}
		finally
		{
			FreeReaderLock();
		}
		return iResult;
	}

	/// <summary>
	/// Enumerator for HTTPHeader storage collection
	/// </summary>
	/// <returns>Enumerator</returns>
	public IEnumerator GetEnumerator()
	{
		return storage.GetEnumerator();
	}

	/// <summary>
	/// Adds a new header containing the specified name and value.
	/// </summary>
	/// <param name="sHeaderName">Name of the header to add.</param>
	/// <param name="sValue">Value of the header.</param>
	/// <returns>Returns the newly-created HTTPHeaderItem.</returns>
	[CodeDescription("Add a new header containing the specified name and value.")]
	public HTTPHeaderItem Add(string sHeaderName, string sValue)
	{
		HTTPHeaderItem result = new HTTPHeaderItem(sHeaderName, sValue);
		try
		{
			GetWriterLock();
			storage.Add(result);
		}
		finally
		{
			FreeWriterLock();
		}
		return result;
	}

	/// <summary>
	/// Adds one or more headers
	/// </summary>
	public void AddRange(IEnumerable<HTTPHeaderItem> collHIs)
	{
		try
		{
			GetWriterLock();
			storage.AddRange(collHIs);
		}
		finally
		{
			FreeWriterLock();
		}
	}

	/// <summary>
	/// Returns the Value from a token in the header. Correctly handles double-quoted strings. Requires semicolon for delimiting tokens
	/// Limitation: FAILS if semicolon is in token's value, even if quoted. 
	/// FAILS in the case of crazy headers, e.g. Header: Blah="SoughtToken=Blah" SoughtToken=MissedMe
	///
	/// We really need a "proper" header parser
	/// </summary>
	/// <param name="sHeaderName">Name of the header</param>
	/// <param name="sTokenName">Name of the token</param>
	/// <returns>Value of the token if present; otherwise, null</returns>
	[CodeDescription("Returns a string representing the value of the named token within the named header.")]
	public string GetTokenValue(string sHeaderName, string sTokenName)
	{
		string sHeaderValue = this[sHeaderName];
		if (string.IsNullOrEmpty(sHeaderValue))
		{
			return null;
		}
		return Utilities.ExtractAttributeValue(sHeaderValue, sTokenName);
	}

	/// <summary>
	/// Determines if the Headers collection contains a header of the specified name, with any value.
	/// </summary>
	/// <param name="sHeaderName">The name of the header to check. (case insensitive)</param>
	/// <returns>True, if the header exists.</returns>
	[CodeDescription("Returns true if the Headers collection contains a header of the specified (case-insensitive) name.")]
	public bool Exists(string sHeaderName)
	{
		if (string.IsNullOrEmpty(sHeaderName))
		{
			return false;
		}
		try
		{
			GetReaderLock();
			for (int x = 0; x < storage.Count; x++)
			{
				if (string.Equals(storage[x].Name, sHeaderName, StringComparison.OrdinalIgnoreCase))
				{
					return true;
				}
			}
		}
		finally
		{
			FreeReaderLock();
		}
		return false;
	}

	/// <summary>
	/// Determines if the Headers collection contains any header from the specified list, with any value.
	/// </summary>
	/// <param name="sHeaderNames">list of headers</param>
	/// <returns>True, if any named header exists.</returns>
	[CodeDescription("Returns true if the Headers collection contains a header of the specified (case-insensitive) name.")]
	public bool ExistsAny(IEnumerable<string> sHeaderNames)
	{
		if (sHeaderNames == null)
		{
			return false;
		}
		try
		{
			GetReaderLock();
			for (int x = 0; x < storage.Count; x++)
			{
				foreach (string s in sHeaderNames)
				{
					if (string.Equals(storage[x].Name, s, StringComparison.OrdinalIgnoreCase))
					{
						return true;
					}
				}
			}
		}
		finally
		{
			FreeReaderLock();
		}
		return false;
	}

	/// <summary>
	/// Determines if the Headers collection contains one or more headers of the specified name, and 
	/// sHeaderValue is part of one of those Headers' value.
	/// </summary>
	/// <param name="sHeaderName">The name of the header to check. (case insensitive)</param>
	/// <param name="sHeaderValue">The partial header value. (case insensitive)</param>
	/// <returns>True if the header is found and the value case-insensitively contains the parameter</returns>
	[CodeDescription("Returns true if the collection contains a header of the specified (case-insensitive) name, and sHeaderValue (case-insensitive) is part of the Header's value.")]
	public bool ExistsAndContains(string sHeaderName, string sHeaderValue)
	{
		if (string.IsNullOrEmpty(sHeaderName))
		{
			return false;
		}
		try
		{
			GetReaderLock();
			for (int x = 0; x < storage.Count; x++)
			{
				if (storage[x].Name.OICEquals(sHeaderName) && storage[x].Value.OICContains(sHeaderValue))
				{
					return true;
				}
			}
		}
		finally
		{
			FreeReaderLock();
		}
		return false;
	}

	/// <summary>
	/// Determines if the Headers collection contains a header of the specified name, and sHeaderValue=Header's value. Similar
	/// to a case-insensitive version of: headers[sHeaderName]==sHeaderValue, although it checks all instances of the named header.
	/// </summary>
	/// <param name="sHeaderName">The name of the header to check. (case insensitive)</param>
	/// <param name="sHeaderValue">The full header value. (case insensitive)</param>
	/// <returns>True if the header is found and the value case-insensitively matches the parameter</returns>
	[CodeDescription("Returns true if the collection contains a header of the specified (case-insensitive) name, with value sHeaderValue (case-insensitive).")]
	public bool ExistsAndEquals(string sHeaderName, string sHeaderValue)
	{
		if (string.IsNullOrEmpty(sHeaderName))
		{
			return false;
		}
		try
		{
			GetReaderLock();
			for (int x = 0; x < storage.Count; x++)
			{
				if (storage[x].Name.OICEquals(sHeaderName))
				{
					string sValue = storage[x].Value.Trim();
					if (sValue.OICEquals(sHeaderValue))
					{
						return true;
					}
				}
			}
		}
		finally
		{
			FreeReaderLock();
		}
		return false;
	}

	/// <summary>
	/// Removes all headers from the header collection which have the specified name.
	/// </summary>
	/// <param name="sHeaderName">The name of the header to remove. (case insensitive)</param>
	[CodeDescription("Removes ALL headers from the header collection which have the specified (case-insensitive) name.")]
	public void Remove(string sHeaderName)
	{
		if (string.IsNullOrEmpty(sHeaderName))
		{
			return;
		}
		try
		{
			GetWriterLock();
			for (int x = storage.Count - 1; x >= 0; x--)
			{
				if (storage[x].Name.OICEquals(sHeaderName))
				{
					storage.RemoveAt(x);
				}
			}
		}
		finally
		{
			FreeWriterLock();
		}
	}

	/// <summary>
	/// Removes all headers from the header collection which have the specified names.
	/// </summary>
	/// <param name="arrToRemove">Array of names of headers to remove. (case insensitive)</param>
	[CodeDescription("Removes ALL headers from the header collection which have the specified (case-insensitive) names.")]
	public void RemoveRange(string[] arrToRemove)
	{
		if (arrToRemove == null || arrToRemove.Length < 1)
		{
			return;
		}
		try
		{
			GetWriterLock();
			for (int x = storage.Count - 1; x >= 0; x--)
			{
				foreach (string sToRemove in arrToRemove)
				{
					if (storage[x].Name.OICEquals(sToRemove))
					{
						storage.RemoveAt(x);
						break;
					}
				}
			}
		}
		finally
		{
			FreeWriterLock();
		}
	}

	/// <summary>
	/// Removes a HTTPHeader item from the collection
	/// </summary>
	/// <param name="oRemove">The HTTPHeader item to be removed</param>
	public void Remove(HTTPHeaderItem oRemove)
	{
		try
		{
			GetWriterLock();
			storage.Remove(oRemove);
		}
		finally
		{
			FreeWriterLock();
		}
	}

	/// <summary>
	/// Removes all HTTPHeader items from the collection
	/// </summary>
	public void RemoveAll()
	{
		try
		{
			GetWriterLock();
			storage.Clear();
		}
		finally
		{
			FreeWriterLock();
		}
	}

	/// <summary>
	/// Renames all headers in the header collection which have the specified name.
	/// </summary>
	/// <param name="sOldHeaderName">The name of the header to rename. (case insensitive)</param>
	/// <param name="sNewHeaderName">The new name for the header.</param>
	/// <returns>True if one or more replacements were made.</returns>
	[CodeDescription("Renames ALL headers in the header collection which have the specified (case-insensitive) name.")]
	public bool RenameHeaderItems(string sOldHeaderName, string sNewHeaderName)
	{
		bool bMadeReplacements = false;
		try
		{
			GetReaderLock();
			for (int x = 0; x < storage.Count; x++)
			{
				if (storage[x].Name.OICEquals(sOldHeaderName))
				{
					storage[x].Name = sNewHeaderName;
					bMadeReplacements = true;
				}
			}
		}
		finally
		{
			FreeReaderLock();
		}
		return bMadeReplacements;
	}
}
