using System;

namespace Fiddler;

/// <summary>
/// EventArgs for preference-change events.  See http://msdn.microsoft.com/en-us/library/ms229011.aspx.
/// </summary>
public class PrefChangeEventArgs : EventArgs
{
	private readonly string _prefName;

	private readonly string _prefValueString;

	/// <summary>
	/// The name of the preference being added, changed, or removed
	/// </summary>
	public string PrefName => _prefName;

	/// <summary>
	/// The string value of the preference, or null if the preference is being removed
	/// </summary>
	public string ValueString => _prefValueString;

	/// <summary>
	/// Returns TRUE if ValueString=="true", case-insensitively
	/// </summary>
	public bool ValueBool => "True".OICEquals(_prefValueString);

	internal PrefChangeEventArgs(string prefName, string prefValueString)
	{
		_prefName = prefName;
		_prefValueString = prefValueString;
	}
}
