namespace Fiddler;

/// <summary>
/// Interface for the WebSocket and CONNECT Tunnel classes
/// </summary>
public interface ITunnel
{
	long IngressByteCount { get; }

	long EgressByteCount { get; }

	bool IsOpen { get; }

	void CloseTunnel();
}
