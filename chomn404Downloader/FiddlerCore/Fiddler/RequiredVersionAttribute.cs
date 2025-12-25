using System;

namespace Fiddler;

/// <summary>
/// Attribute used to specify the minimum version of Fiddler compatible with this extension assembly. 
/// </summary>
[AttributeUsage(AttributeTargets.Assembly, Inherited = false, AllowMultiple = false)]
public sealed class RequiredVersionAttribute : Attribute
{
	private string _sVersion;

	/// <summary>
	/// Getter for the required version string
	/// </summary>
	public string RequiredVersion => _sVersion;

	/// <summary>
	/// Attribute used to specify the minimum version of Fiddler compatible with this extension assembly.
	/// </summary>
	/// <param name="sVersion">The minimal version string (e.g. "2.2.8.8")</param>
	public RequiredVersionAttribute(string sVersion)
	{
		if (sVersion.StartsWith("2."))
		{
			sVersion = "4." + sVersion.Substring(2);
		}
		_sVersion = sVersion;
	}
}
