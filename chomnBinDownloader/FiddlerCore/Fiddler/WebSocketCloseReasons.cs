namespace Fiddler;

public enum WebSocketCloseReasons : short
{
	Normal = 1000,
	GoingAway = 1001,
	ProtocolError = 1002,
	UnsupportedData = 1003,
	Undefined1004 = 1004,
	Reserved1005 = 1005,
	Reserved1006 = 1006,
	InvalidPayloadData = 1007,
	PolicyViolation = 1008,
	MessageTooBig = 1009,
	MandatoryExtension = 1010,
	InternalServerError = 1011,
	Reserved1015 = 1015
}
