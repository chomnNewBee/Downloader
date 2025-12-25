namespace Fiddler;

/// <summary>
/// State of the current session
/// </summary>
public enum SessionStates
{
	/// <summary>
	/// Object created but nothing's happening yet
	/// </summary>
	Created,
	/// <summary>
	/// Thread is reading the HTTP Request
	/// </summary>
	ReadingRequest,
	/// <summary>
	/// AutoTamperRequest pass 1	 (IAutoTamper,  OnBeforeRequest script method)
	/// </summary>
	AutoTamperRequestBefore,
	/// <summary>
	/// User can tamper using Fiddler Inspectors
	/// </summary>
	HandTamperRequest,
	/// <summary>
	/// AutoTamperRequest pass 2	 (Only used by IAutoTamper)
	/// </summary>
	AutoTamperRequestAfter,
	/// <summary>
	/// Thread is sending the Request to the server
	/// </summary>
	SendingRequest,
	/// <summary>
	/// Thread is reading the HTTP Response
	/// </summary>
	ReadingResponse,
	/// <summary>
	/// AutoTamperResponse pass 1 (Only used by IAutoTamper)
	/// </summary>
	AutoTamperResponseBefore,
	/// <summary>
	/// User can tamper using Fiddler Inspectors
	/// </summary>
	HandTamperResponse,
	/// <summary>
	/// AutoTamperResponse pass 2 (Only used by IAutoTamper)
	/// </summary>
	AutoTamperResponseAfter,
	/// <summary>
	/// Sending response to client application
	/// </summary>
	SendingResponse,
	/// <summary>
	/// Session complete
	/// </summary>
	Done,
	/// <summary>
	/// Session was aborted (client didn't want response, fatal error, etc)
	/// </summary>
	Aborted
}
