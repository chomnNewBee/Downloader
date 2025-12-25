using System;

namespace Fiddler;

/// <summary>
/// This tuple maps a display descriptive string to a Import/Export type.
/// (The parent dictionary contains the shortname string)
/// </summary>
public class TranscoderTuple
{
	/// <summary>
	/// Textual description of the Format
	/// </summary>
	public string sFormatDescription;

	/// <summary>
	/// Class implementing the format
	/// </summary>
	public Type typeFormatter;

	/// <summary>
	/// All metadata about the provider
	/// </summary>
	private ProfferFormatAttribute _pfa;

	public string sFormatName => _pfa.FormatName;

	/// <summary>
	/// Create a new Transcoder Tuple
	/// </summary>
	/// <param name="pFA">Proffer format description</param>
	/// <param name="oFormatter">Type implementing this format</param>
	internal TranscoderTuple(ProfferFormatAttribute pFA, Type oFormatter)
	{
		_pfa = pFA;
		sFormatDescription = pFA.FormatDescription;
		typeFormatter = oFormatter;
	}

	internal bool HandlesExtension(string sExt)
	{
		string[] extensions = _pfa.getExtensions();
		foreach (string sCandidate in extensions)
		{
			if (sExt.OICEquals(sCandidate))
			{
				return true;
			}
		}
		return false;
	}
}
