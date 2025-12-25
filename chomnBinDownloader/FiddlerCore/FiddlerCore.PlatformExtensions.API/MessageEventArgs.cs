using System;

namespace FiddlerCore.PlatformExtensions.API;

/// <summary>
/// This class is used to pass a simple string message to a event handler.
/// </summary>
internal class MessageEventArgs : EventArgs
{
	/// <summary>
	/// Gets the message.
	/// </summary>
	public string Message { get; private set; }

	/// <summary>
	/// Creates and initializes new instance of the <see cref="T:FiddlerCore.PlatformExtensions.API.MessageEventArgs" />. 
	/// </summary>
	/// <param name="message">The message.</param>
	public MessageEventArgs(string message)
	{
		Message = message;
	}
}
