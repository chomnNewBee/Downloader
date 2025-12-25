using System;
using FiddlerCore.PlatformExtensions.API;

namespace FiddlerCore.PlatformExtensions;

internal class EmptyProxyHelper : IProxyHelper
{
	private static EmptyProxyHelper instance;

	public static EmptyProxyHelper Instance
	{
		get
		{
			if (instance == null)
			{
				instance = new EmptyProxyHelper();
			}
			return instance;
		}
	}

	private EmptyProxyHelper()
	{
	}

	public void DisableProxyForCurrentProcess()
	{
		throw new NotSupportedException("This method is not supported on your platform.");
	}

	public string GetProxyForCurrentProcessAsHexView()
	{
		throw new NotSupportedException("This method is not supported on your platform.");
	}

	public void ResetProxyForCurrentProcess()
	{
		throw new NotSupportedException("This method is not supported on your platform.");
	}

	public void SetProxyForCurrentProcess(string proxy, string bypassList)
	{
		throw new NotSupportedException("This method is not supported on your platform.");
	}
}
