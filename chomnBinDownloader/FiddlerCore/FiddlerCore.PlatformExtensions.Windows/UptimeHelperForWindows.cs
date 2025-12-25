using System;
using System.Runtime.InteropServices;

namespace FiddlerCore.PlatformExtensions.Windows;

internal static class UptimeHelperForWindows
{
	[DllImport("Kernel32.dll", CharSet = CharSet.Unicode)]
	private static extern ulong GetTickCount64();

	public static bool TryGetUptimeInMilliseconds(out ulong milliseconds)
	{
		milliseconds = 0uL;
		if (Environment.OSVersion.Version.Major > 5)
		{
			milliseconds = GetTickCount64();
			return true;
		}
		return false;
	}
}
