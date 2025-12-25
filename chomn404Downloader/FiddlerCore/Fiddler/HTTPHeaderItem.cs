using System;

namespace Fiddler;

/// <summary>
/// Represents a single HTTP header
/// </summary>
public class HTTPHeaderItem : ICloneable
{
	/// <summary>
	/// The name of the HTTP header
	/// </summary>
	[CodeDescription("String name of the HTTP header.")]
	public string Name;

	/// <summary>
	/// The value of the HTTP header
	/// </summary>
	[CodeDescription("String value of the HTTP header.")]
	public string Value;

	/// <summary>
	/// Clones a single HTTP header and returns the clone cast to an object
	/// </summary>
	/// <returns>HTTPHeader Name: Value pair, cast to an object</returns>
	public object Clone()
	{
		return MemberwiseClone();
	}

	/// <summary>
	/// Creates a new HTTP Header item. WARNING: Doesn't do any trimming or validation on the name.
	/// </summary>
	/// <param name="sName">Header name</param>
	/// <param name="sValue">Header value</param>
	public HTTPHeaderItem(string sName, string sValue)
	{
		if (string.IsNullOrEmpty(sName))
		{
			sName = string.Empty;
		}
		if (sValue == null)
		{
			sValue = string.Empty;
		}
		Name = sName;
		Value = sValue;
	}

	/// <summary>
	/// Return a string of the form "NAME: VALUE"
	/// </summary>
	/// <returns>"NAME: VALUE" Header string</returns>
	public override string ToString()
	{
		return $"{Name}: {Value}";
	}
}
