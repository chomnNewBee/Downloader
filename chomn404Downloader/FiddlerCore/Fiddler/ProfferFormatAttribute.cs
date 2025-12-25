using System;

namespace Fiddler;

/// <summary>
/// Attribute allowing developer to specify that a class supports the specified Import/Export Format.
/// </summary>
[AttributeUsage(AttributeTargets.Class, Inherited = false, AllowMultiple = true)]
public sealed class ProfferFormatAttribute : Attribute
{
	private string _sFormatName;

	private string _sFormatDesc;

	private string _sExtensions;

	/// <summary>
	/// Returns the Shortname for this format
	/// </summary>
	public string FormatName => _sFormatName;

	/// <summary>
	/// Returns the Description of this format
	/// </summary>
	public string FormatDescription => _sFormatDesc;

	internal string[] getExtensions()
	{
		if (string.IsNullOrEmpty(_sExtensions))
		{
			return new string[0];
		}
		return _sExtensions.Split(new char[1] { ';' }, StringSplitOptions.RemoveEmptyEntries);
	}

	/// <summary>
	/// Attribute allowing developer to specify that a class supports the specified Import/Export Format
	/// </summary>
	/// <param name="sFormatName">Shortname of the Format (e.g. WebText XML)</param>
	/// <param name="sDescription">Description of the format</param>
	public ProfferFormatAttribute(string sFormatName, string sDescription)
		: this(sFormatName, sDescription, string.Empty)
	{
	}

	/// <summary>
	/// Attribute allowing developer to specify that a class supports the specified Import/Export Format
	/// </summary>
	/// <param name="sFormatName">Shortname of the Format (e.g. WebText XML)</param>
	/// <param name="sDescription">Description of the format</param>
	/// <param name="sExtensions">Semi-colon delimited file extensions (e.g. ".har;.harx")</param>
	public ProfferFormatAttribute(string sFormatName, string sDescription, string sExtensions)
	{
		_sFormatName = sFormatName;
		_sFormatDesc = sDescription;
		_sExtensions = sExtensions;
	}
}
