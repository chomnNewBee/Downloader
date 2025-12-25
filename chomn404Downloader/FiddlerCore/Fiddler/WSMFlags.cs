using System;

namespace Fiddler;

/// <summary>
/// This enumeration provides the values for the WebSocketMessage object's BitFlags field
/// </summary>
[Flags]
public enum WSMFlags
{
	/// <summary>
	/// No flags are set
	/// </summary>
	None = 0,
	/// <summary>
	/// Message was eaten ("dropped") by Fiddler
	/// </summary>
	Aborted = 1,
	/// <summary>
	/// Message was generated ("injected") by Fiddler itself
	/// </summary>
	GeneratedByFiddler = 2,
	/// <summary>
	/// Fragmented Message was reassembled by Fiddler
	/// </summary>
	Assembled = 4,
	/// <summary>
	/// Breakpointed
	/// </summary>
	Breakpointed = 8
}
