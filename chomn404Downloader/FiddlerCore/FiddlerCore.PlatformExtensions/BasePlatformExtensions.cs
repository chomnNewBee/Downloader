using System;
using FiddlerCore.PlatformExtensions.API;

namespace FiddlerCore.PlatformExtensions;

internal abstract class BasePlatformExtensions : IPlatformExtensions
{
	public abstract bool HighResolutionTimersEnabled { get; }

	public abstract IProxyHelper ProxyHelper { get; }

	public event EventHandler<MessageEventArgs> DebugSpew;

	public event EventHandler<MessageEventArgs> Error;

	public event EventHandler<MessageEventArgs> Log;

	public abstract IAutoProxy CreateAutoProxy(bool autoDiscover, string pacUrl, bool autoProxyRunInProcess, bool autoLoginIfChallenged);

	public abstract byte[] DecompressXpress(byte[] data);

	public abstract string PostProcessProcessName(int pid, string processName);

	public abstract void SetUserAgentStringForCurrentProcess(string userAgent);

	public abstract bool TryChangeTimersResolution(bool increase);

	public abstract bool TryGetUptimeInMilliseconds(out ulong milliseconds);

	public abstract bool TryGetListeningProcessOnPort(int port, out string processName, out int processId, out string errorMessage);

	public abstract bool TryMapPortToProcessId(int port, bool includeIPv6, out int processId, out string errorMessage);

	internal void OnDebugSpew(string message)
	{
		OnMessageEvent(this.DebugSpew, message);
	}

	internal void OnError(string message)
	{
		OnMessageEvent(this.Error, message);
	}

	internal void OnLog(string message)
	{
		OnMessageEvent(this.Log, message);
	}

	private void OnMessageEvent(EventHandler<MessageEventArgs> handler, string message)
	{
		handler?.Invoke(this, new MessageEventArgs(message));
	}
}
