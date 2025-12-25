using System;
using System.Runtime.InteropServices;
using System.Text;

namespace FiddlerCore.PlatformExtensions.Windows;

internal static class ProcessHelperForWindows
{
	private const int QueryLimitedInformation = 4096;

	private const int ERROR_INSUFFICIENT_BUFFER = 122;

	private const int ERROR_SUCCESS = 0;

	[DllImport("kernel32.dll")]
	internal static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

	[DllImport("kernel32.dll")]
	private static extern bool CloseHandle(IntPtr hHandle);

	[DllImport("kernel32.dll")]
	internal static extern int GetApplicationUserModelId(IntPtr hProcess, ref uint AppModelIDLength, [MarshalAs(UnmanagedType.LPWStr)] StringBuilder sbAppUserModelID);

	public static string DisambiguateWWAHostApps(int iPID, string sResult)
	{
		if (sResult.Equals("WWAHost", StringComparison.OrdinalIgnoreCase))
		{
			try
			{
				IntPtr ptrProcess = OpenProcess(4096, bInheritHandle: false, iPID);
				if (IntPtr.Zero != ptrProcess)
				{
					uint cchLen = 130u;
					StringBuilder sbName = new StringBuilder((int)cchLen);
					int lResult = GetApplicationUserModelId(ptrProcess, ref cchLen, sbName);
					if (lResult == 0)
					{
						sResult = $"{sResult}!{sbName}";
					}
					else if (122 == lResult)
					{
						sbName = new StringBuilder((int)cchLen);
						if (GetApplicationUserModelId(ptrProcess, ref cchLen, sbName) == 0)
						{
							sResult = $"{sResult}!{sbName}";
						}
					}
					CloseHandle(ptrProcess);
				}
			}
			catch
			{
			}
		}
		return sResult;
	}
}
