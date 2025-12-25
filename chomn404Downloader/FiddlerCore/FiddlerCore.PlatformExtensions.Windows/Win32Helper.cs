using System;
using System.Runtime.InteropServices;

namespace FiddlerCore.PlatformExtensions.Windows;

internal static class Win32Helper
{
	[DllImport("kernel32.dll", SetLastError = true)]
	internal static extern IntPtr GlobalFree(IntPtr hMem);

	internal static void GlobalFreeIfNonZero(IntPtr hMem)
	{
		if (IntPtr.Zero != hMem)
		{
			GlobalFree(hMem);
		}
	}
}
