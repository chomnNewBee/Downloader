namespace Fiddler;

/// <summary>
/// States for the (future) Session-processing State Machine.
///
/// Fun Idea: We can omit irrelevant states from FiddlerCore and thus not have to litter
/// our state machine itself with a bunch of #if FIDDLERCORE checks...
/// ... except no, that doesn't work because compiler still cares. Rats.
///
/// </summary>
internal enum ProcessingStates : byte
{
	Created,
	GetRequestStart,
	GetRequestHeadersEnd,
	PauseForRequestTampering,
	ResumeFromRequestTampering,
	GetRequestEnd,
	RunRequestRulesStart,
	RunRequestRulesEnd,
	DetermineGatewayStart,
	DetermineGatewayEnd,
	DNSStart,
	DNSEnd,
	ConnectStart,
	ConnectEnd,
	HTTPSHandshakeStart,
	HTTPSHandshakeEnd,
	SendRequestStart,
	SendRequestEnd,
	ReadResponseStart,
	GetResponseHeadersEnd,
	ReadResponseEnd,
	RunResponseRulesStart,
	RunResponseRulesEnd,
	PauseForResponseTampering,
	ResumeFromResponseTampering,
	ReturnBufferedResponseStart,
	ReturnBufferedResponseEnd,
	DoAfterSessionEventStart,
	DoAfterSessionEventEnd,
	Finished
}
