namespace Fiddler;

/// <summary>
/// The class that is used to store MIME-type-to-file-extension mapping.
/// </summary>
public class MimeMap
{
	/// <summary>
	/// Gets or sets the MIME type for this mapping. The provided MIME type should be in the format "top-level type name / subtype name"
	/// and should not include the parameters section of the MIME type. E.g. application/json, text/html, image/gif etc. This property
	/// should not be null, empty string or string containing only white spaces, in order Telerik FiddlerCore to load it.
	/// </summary>
	public string MimeType { get; set; }

	/// <summary>
	/// Gets or sets the file extension for this mapping. The provided file extension should start with . (dot). E.g. .txt, .html, .png etc.
	/// This property should not be null, empty string or string containing only white spaces, in order Telerik FiddlerCore to load it.
	/// </summary>
	public string FileExtension { get; set; }

	internal bool IsValid()
	{
		return !string.IsNullOrWhiteSpace(MimeType) && !string.IsNullOrWhiteSpace(FileExtension);
	}

	public override string ToString()
	{
		return $"MIME Type: \"{MimeType}\", File extension: \"{FileExtension}\"";
	}
}
