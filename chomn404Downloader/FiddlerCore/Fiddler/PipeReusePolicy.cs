namespace Fiddler;

/// <summary>
/// The policy which describes how this pipe may be reused by a later request. Ordered by least restrictive to most.
/// </summary>
public enum PipeReusePolicy
{
	/// <summary>
	/// The ServerPipe may be freely reused by any subsequent request
	/// </summary>
	NoRestrictions,
	/// <summary>
	/// The ServerPipe may be reused only by a subsequent request from the same client process
	/// </summary>
	MarriedToClientProcess,
	/// <summary>
	/// The ServerPipe may be reused only by a subsequent request from the same client pipe
	/// </summary>
	MarriedToClientPipe,
	/// <summary>
	/// The ServerPipe may not be reused for a subsequent request
	/// </summary>
	NoReuse
}
