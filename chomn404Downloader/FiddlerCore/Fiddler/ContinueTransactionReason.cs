namespace Fiddler;

public enum ContinueTransactionReason : byte
{
	/// <summary>
	/// Unknown
	/// </summary>
	None,
	/// <summary>
	/// The new Session is needed to respond to an Authentication Challenge
	/// </summary>
	Authenticate,
	/// <summary>
	/// The new Session is needed to follow a Redirection
	/// </summary>
	Redirect,
	/// <summary>
	/// The new Session is needed to generate a CONNECT tunnel
	/// </summary>
	Tunnel
}
