using System;
using System.Runtime.InteropServices;
using FiddlerCore.PlatformExtensions.API;

namespace FiddlerCore.PlatformExtensions.Windows;

internal class WinHttpAutoProxy : IAutoProxy, IDisposable
{
	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	private struct WINHTTP_AUTOPROXY_OPTIONS
	{
		[MarshalAs(UnmanagedType.U4)]
		public int dwFlags;

		[MarshalAs(UnmanagedType.U4)]
		public int dwAutoDetectFlags;

		[MarshalAs(UnmanagedType.LPWStr)]
		public string lpszAutoConfigUrl;

		public IntPtr lpvReserved;

		[MarshalAs(UnmanagedType.U4)]
		public int dwReserved;

		/// <summary>
		/// Set to true to send Negotiate creds when challenged to download the script
		/// </summary>
		[MarshalAs(UnmanagedType.Bool)]
		public bool fAutoLoginIfChallenged;
	}

	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	private struct WINHTTP_PROXY_INFO
	{
		[MarshalAs(UnmanagedType.U4)]
		public int dwAccessType;

		public IntPtr lpszProxy;

		public IntPtr lpszProxyBypass;
	}

	private const int WINHTTP_ACCESS_TYPE_DEFAULT_PROXY = 0;

	private const int WINHTTP_ACCESS_TYPE_NO_PROXY = 1;

	private const int WINHTTP_ACCESS_TYPE_NAMED_PROXY = 3;

	private const int WINHTTP_AUTOPROXY_AUTO_DETECT = 1;

	private const int WINHTTP_AUTOPROXY_CONFIG_URL = 2;

	private const int WINHTTP_AUTOPROXY_RUN_INPROCESS = 65536;

	private const int WINHTTP_AUTOPROXY_RUN_OUTPROCESS_ONLY = 131072;

	private const int WINHTTP_AUTO_DETECT_TYPE_DHCP = 1;

	private const int WINHTTP_AUTO_DETECT_TYPE_DNS_A = 2;

	private const int ERROR_WINHTTP_LOGIN_FAILURE = 12015;

	private const int ERROR_WINHTTP_UNABLE_TO_DOWNLOAD_SCRIPT = 12167;

	private const int ERROR_WINHTTP_UNRECOGNIZED_SCHEME = 12006;

	private const int ERROR_WINHTTP_AUTODETECTION_FAILED = 12180;

	private const int ERROR_WINHTTP_BAD_AUTO_PROXY_SCRIPT = 12166;

	private static readonly object WinHttpLock = new object();

	private readonly bool autoDiscover = true;

	private readonly string pacUrl;

	private readonly IntPtr internetSessionHandle;

	private WINHTTP_AUTOPROXY_OPTIONS autoProxyOptions;

	private bool disposed = false;

	public WinHttpAutoProxy(bool autoDiscover, string pacUrl, bool autoProxyRunInProcess, bool autoLoginIfChallenged)
	{
		this.autoDiscover = autoDiscover;
		this.pacUrl = pacUrl;
		autoProxyOptions = GetAutoProxyOptionsStruct(autoDiscover, pacUrl, autoProxyRunInProcess, autoLoginIfChallenged);
		internetSessionHandle = WinHttpOpenThreadSafe("Fiddler", 1, IntPtr.Zero, IntPtr.Zero, 0);
	}

	public bool TryGetProxyForUrl(string url, out string proxy, out string errorMessage)
	{
		if (disposed)
		{
			throw new ObjectDisposedException("WinHttpAutoProxy");
		}
		int iLastError = 0;
		WINHTTP_PROXY_INFO oProxy;
		bool bResult = WinHttpGetProxyForUrlThreadSafe(internetSessionHandle, url, ref autoProxyOptions, out oProxy);
		if (!bResult)
		{
			iLastError = Marshal.GetLastWin32Error();
		}
		if (bResult)
		{
			proxy = Marshal.PtrToStringUni(oProxy.lpszProxy);
			errorMessage = null;
			Win32Helper.GlobalFreeIfNonZero(oProxy.lpszProxy);
			Win32Helper.GlobalFreeIfNonZero(oProxy.lpszProxyBypass);
			return true;
		}
		switch (iLastError)
		{
		case 12180:
			errorMessage = "AutoProxy Detection failed.";
			break;
		case 12167:
			errorMessage = "PAC Script download failed.";
			break;
		case 12015:
			errorMessage = "PAC Script download failure; you must set the AutoProxyLogon registry key to TRUE.";
			break;
		case 12006:
		{
			string wpadUrl = (TryGetPacUrl(out wpadUrl) ? wpadUrl : string.Empty);
			errorMessage = string.Format("PAC Script download failure; Fiddler only supports HTTP/HTTPS for PAC script URLs; WPAD returned '{0}'.", wpadUrl.Replace("\n", "\\n"));
			break;
		}
		case 12166:
			errorMessage = "PAC Script contents were not valid.";
			break;
		default:
			errorMessage = "Proxy determination failed with error code: " + iLastError;
			break;
		}
		proxy = null;
		Win32Helper.GlobalFreeIfNonZero(oProxy.lpszProxy);
		Win32Helper.GlobalFreeIfNonZero(oProxy.lpszProxyBypass);
		return false;
	}

	/// <summary>
	/// Outs WPAD-discovered URL for display purposes (e.g. Help&gt; About); note that we don't actually use this when determining the gateway,
	/// instead relying on the WinHTTPGetProxyForUrl function to do this work for us.
	/// </summary>
	/// <returns>A WPAD url, if found, or String.Empty</returns>
	public bool TryGetPacUrl(out string pacUrl)
	{
		if (!WinHttpDetectAutoProxyConfigUrlThreadSafe(3, out var pszResult) || pszResult == IntPtr.Zero)
		{
			pacUrl = null;
			return false;
		}
		pacUrl = Marshal.PtrToStringUni(pszResult);
		Win32Helper.GlobalFreeIfNonZero(pszResult);
		return true;
	}

	public void Dispose()
	{
		disposed = true;
		WinHttpCloseHandleThreadSafe(internetSessionHandle);
	}

	private static WINHTTP_AUTOPROXY_OPTIONS GetAutoProxyOptionsStruct(bool autoDiscover, string pacUrl, bool autoProxyRunInProcess, bool autoLoginIfChallenged)
	{
		WINHTTP_AUTOPROXY_OPTIONS result = default(WINHTTP_AUTOPROXY_OPTIONS);
		if (autoProxyRunInProcess)
		{
			result.dwFlags = 65536;
		}
		else
		{
			result.dwFlags = 0;
		}
		if (autoDiscover)
		{
			result.dwFlags |= 1;
			result.dwAutoDetectFlags = 3;
		}
		if (pacUrl != null)
		{
			result.dwFlags |= 2;
			result.lpszAutoConfigUrl = pacUrl;
		}
		result.fAutoLoginIfChallenged = autoLoginIfChallenged;
		return result;
	}

	private static IntPtr WinHttpOpenThreadSafe(string pwszUserAgent, int dwAccessType, IntPtr pwszProxyName, IntPtr pwszProxyBypass, int dwFlags)
	{
		lock (WinHttpLock)
		{
			return WinHttpOpen(pwszUserAgent, dwAccessType, pwszProxyName, pwszProxyBypass, dwFlags);
		}
	}

	[DllImport("winhttp.dll", CharSet = CharSet.Unicode, SetLastError = true)]
	private static extern IntPtr WinHttpOpen([In][MarshalAs(UnmanagedType.LPWStr)] string pwszUserAgent, [In] int dwAccessType, [In] IntPtr pwszProxyName, [In] IntPtr pwszProxyBypass, [In] int dwFlags);

	/// <summary>
	/// Note: Be sure to use the same hSession to prevent redownload of the proxy script
	/// </summary>
	private static bool WinHttpGetProxyForUrlThreadSafe(IntPtr hSession, string lpcwszUrl, ref WINHTTP_AUTOPROXY_OPTIONS pAutoProxyOptions, out WINHTTP_PROXY_INFO pProxyInfo)
	{
		lock (WinHttpLock)
		{
			return WinHttpGetProxyForUrl(hSession, lpcwszUrl, ref pAutoProxyOptions, out pProxyInfo);
		}
	}

	[DllImport("winhttp.dll", CharSet = CharSet.Unicode, SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static extern bool WinHttpGetProxyForUrl(IntPtr hSession, [MarshalAs(UnmanagedType.LPWStr)] string lpcwszUrl, [In] ref WINHTTP_AUTOPROXY_OPTIONS pAutoProxyOptions, out WINHTTP_PROXY_INFO pProxyInfo);

	private static bool WinHttpDetectAutoProxyConfigUrlThreadSafe(int dwAutoDetectFlags, out IntPtr ppwszAutoConfigUrl)
	{
		lock (WinHttpLock)
		{
			return WinHttpDetectAutoProxyConfigUrl(dwAutoDetectFlags, out ppwszAutoConfigUrl);
		}
	}

	[DllImport("winhttp.dll", CharSet = CharSet.Unicode, SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static extern bool WinHttpDetectAutoProxyConfigUrl([MarshalAs(UnmanagedType.U4)] int dwAutoDetectFlags, out IntPtr ppwszAutoConfigUrl);

	private static bool WinHttpCloseHandleThreadSafe(IntPtr hInternet)
	{
		lock (WinHttpLock)
		{
			return WinHttpCloseHandle(hInternet);
		}
	}

	[DllImport("winhttp.dll", CharSet = CharSet.Unicode, SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static extern bool WinHttpCloseHandle([In] IntPtr hInternet);
}
