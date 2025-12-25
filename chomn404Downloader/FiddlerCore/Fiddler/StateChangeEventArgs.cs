using System;

namespace Fiddler;

/// <summary>
/// Event arguments constructed for the OnStateChanged event raised when a Session's state property changed
/// </summary>
public class StateChangeEventArgs : EventArgs
{
	/// <summary>
	/// The prior state of this session
	/// </summary>
	public readonly SessionStates oldState;

	/// <summary>
	/// The new state of this session
	/// </summary>
	public readonly SessionStates newState;

	/// <summary>
	/// Constructor for the change in state
	/// </summary>
	/// <param name="ssOld">The old state</param>
	/// <param name="ssNew">The new state</param>
	internal StateChangeEventArgs(SessionStates ssOld, SessionStates ssNew)
	{
		oldState = ssOld;
		newState = ssNew;
	}
}
