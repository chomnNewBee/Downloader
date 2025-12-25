using System;
using System.Runtime.InteropServices;
using FiddlerCore.PlatformExtensions.API;
using FiddlerCore.Utilities;

namespace FiddlerCore.PlatformExtensions.Windows;

internal class ProxyHelperForWindows : IProxyHelper
{
	[StructLayout(LayoutKind.Sequential)]
	private class INTERNET_PROXY_INFO
	{
		[MarshalAs(UnmanagedType.U4)]
		public uint dwAccessType;

		[MarshalAs(UnmanagedType.LPStr)]
		public string lpszProxy;

		[MarshalAs(UnmanagedType.LPStr)]
		public string lpszProxyBypass;
	}

	private static ProxyHelperForWindows instance;

	private const uint INTERNET_OPEN_TYPE_PRECONFIG = 0u;

	private const uint INTERNET_OPEN_TYPE_DIRECT = 1u;

	private const uint INTERNET_OPEN_TYPE_PROXY = 3u;

	private const uint INTERNET_OPEN_TYPE_PRECONFIG_WITH_NO_AUTOPROXY = 4u;

	private const uint INTERNET_OPTION_REFRESH = 37u;

	private const uint INTERNET_OPTION_PROXY = 38u;

	public static ProxyHelperForWindows Instance
	{
		get
		{
			if (instance == null)
			{
				instance = new ProxyHelperForWindows();
			}
			return instance;
		}
	}

	[DllImport("urlmon.dll", CharSet = CharSet.Auto, EntryPoint = "UrlMkSetSessionOption", SetLastError = true)]
	private static extern int UrlMkSetSessionOptionProxy(uint dwOption, INTERNET_PROXY_INFO structNewProxy, uint dwLen, uint dwZero);

	[DllImport("wininet.dll", CharSet = CharSet.Ansi, SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static extern bool InternetQueryOption(IntPtr hInternet, int Option, byte[] OptionInfo, ref int size);

	private ProxyHelperForWindows()
	{
	}

	public void DisableProxyForCurrentProcess()
	{
		INTERNET_PROXY_INFO oInfo = new INTERNET_PROXY_INFO();
		oInfo.dwAccessType = 1u;
		oInfo.lpszProxy = (oInfo.lpszProxyBypass = null);
		uint dwSize = (uint)Marshal.SizeOf(oInfo);
		int iResult = UrlMkSetSessionOptionProxy(38u, oInfo, dwSize, 0u);
	}

	public string GetProxyForCurrentProcessAsHexView()
	{
		int size = 0;
		byte[] buffer = new byte[1];
		size = buffer.Length;
		if (!InternetQueryOption(IntPtr.Zero, 38, buffer, ref size) && size != buffer.Length)
		{
			buffer = new byte[size];
			size = buffer.Length;
			bool r = InternetQueryOption(IntPtr.Zero, 38, buffer, ref size);
		}
		return HexViewHelper.ByteArrayToHexView(buffer, 16);
	}

	public void ResetProxyForCurrentProcess()
	{
		int iResult = UrlMkSetSessionOptionProxy(37u, null, 0u, 0u);
	}

	public void SetProxyForCurrentProcess(string proxy, string bypassList)
	{
		INTERNET_PROXY_INFO oInfo = new INTERNET_PROXY_INFO();
		oInfo.dwAccessType = 3u;
		oInfo.lpszProxy = proxy;
		oInfo.lpszProxyBypass = bypassList;
		uint dwSize = (uint)Marshal.SizeOf(oInfo);
		int iResult = UrlMkSetSessionOptionProxy(38u, oInfo, dwSize, 0u);
	}
}
