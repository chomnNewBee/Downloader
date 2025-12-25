using System;

namespace Fiddler;

/// <summary>
/// CodeDescription attributes are used to enable the FiddlerScript Editor to describe available methods, properties, fields, and events.
/// </summary>
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Event, Inherited = false, AllowMultiple = false)]
public sealed class CodeDescription : Attribute
{
	private string sDesc;

	/// <summary>
	/// The descriptive string which should be displayed for this this property, method, or field
	/// </summary>
	public string Description => sDesc;

	/// <summary>
	/// CodeDescription attributes should be constructed by annotating a property, method, or field.
	/// </summary>
	/// <param name="desc">The descriptive string which should be displayed for this this property, method, or field</param>
	public CodeDescription(string desc)
	{
		sDesc = desc;
	}
}
