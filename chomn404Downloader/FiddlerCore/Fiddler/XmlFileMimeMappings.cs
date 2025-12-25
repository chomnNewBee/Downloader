using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Xml.Serialization;

namespace Fiddler;

/// <summary>
/// This class is used to deserialize and store MIME-type-to-file-extension mappings from given XML file.
/// </summary>
/// <remarks>
/// The XML file should be in the following format:
/// <![CDATA[
///
/// <ArrayOfMimeMap>
///   <MimeMap>
///     <MimeType>mime/type</MimeType>
///     <FileExtension>.ext</FileExtension>
///   </MimeMap>
/// </ArrayOfMimeMap>
///
/// ]]>
/// </remarks>
public class XmlFileMimeMappings : IEnumerable<MimeMap>, IEnumerable
{
	private List<MimeMap> mappings;

	/// <summary>
	/// Initializes new instance of <typeparamref name="XmlFileMimeMappings" /> with the specified file path.
	/// </summary>
	/// <param name="filePath">A relative or absolute path to the XML file.</param>
	public XmlFileMimeMappings(string filePath)
	{
		mappings = new List<MimeMap>();
		FileStream xmlFile = new FileStream(filePath, FileMode.Open);
		using (xmlFile)
		{
			XmlSerializer serializer = new XmlSerializer(typeof(List<MimeMap>));
			List<MimeMap> fileMappings = serializer.Deserialize(xmlFile) as List<MimeMap>;
			mappings = fileMappings;
		}
	}

	public IEnumerator<MimeMap> GetEnumerator()
	{
		return mappings.GetEnumerator();
	}

	IEnumerator IEnumerable.GetEnumerator()
	{
		return GetEnumerator();
	}
}
