namespace Fiddler;

/// <summary>
/// When may requests be resent on a new connection?
/// </summary>
public enum RetryMode : byte
{
	/// <summary>
	/// The request may always be retried.
	/// </summary>
	Always,
	/// <summary>
	/// The request may never be retried
	/// </summary>
	Never,
	/// <summary>
	/// The request may only be resent if the HTTP Method is idempotent.
	/// This SHOULD be the default per HTTP spec, but this appears to break tons of servers.
	/// </summary>
	IdempotentOnly
}
