using System;
using System.Runtime.InteropServices;
using FiddlerCore.PlatformExtensions.API;
using FiddlerCore.PlatformExtensions.Unix.Linux;
using FiddlerCore.PlatformExtensions.Unix.Mac;
using FiddlerCore.PlatformExtensions.Windows;

namespace FiddlerCore.PlatformExtensions;

internal sealed class PlatformExtensionsFactory : IPlatformExtensionsFactory
{
	private static PlatformExtensionsFactory instance;

	public static PlatformExtensionsFactory Instance
	{
		get
		{
			if (instance == null)
			{
				instance = new PlatformExtensionsFactory();
			}
			return instance;
		}
	}

	private PlatformExtensionsFactory()
	{
	}

	public IPlatformExtensions CreatePlatformExtensions()
	{
		if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
		{
			return PlatformExtensionsForWindows.Instance;
		}
		if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
		{
			return PlatformExtensionsForLinux.Instance;
		}
		if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
		{
			return PlatformExtensionsForMac.Instance;
		}
		throw new PlatformNotSupportedException("Your platform is not supported by FiddlerCore.PlatformExtensions");
	}
}
