using System;

namespace Fiddler;

/// <summary>
/// Flags that indicate what problems, if any, were encountered in parsing HTTP headers
/// </summary>
[Flags]
public enum HTTPHeaderParseWarnings
{
	/// <summary>
	/// There were no problems parsing the HTTP headers
	/// </summary>
	None = 0,
	/// <summary>
	/// The HTTP headers ended incorrectly with \n\n
	/// </summary>
	EndedWithLFLF = 1,
	/// <summary>
	/// The HTTP headers ended incorrectly with \n\r\n
	/// </summary>
	EndedWithLFCRLF = 2,
	/// <summary>
	/// The HTTP headers were malformed.
	/// </summary>
	Malformed = 4
}
