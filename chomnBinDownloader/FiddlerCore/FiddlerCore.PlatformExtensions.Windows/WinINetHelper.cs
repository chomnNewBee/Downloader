using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using FiddlerCore.PlatformExtensions.API;

namespace FiddlerCore.PlatformExtensions.Windows;

internal class WinINetHelper : IWinINetHelper
{
	private enum WININETCACHEENTRYTYPE
	{
		None = 0,
		NORMAL_CACHE_ENTRY = 1,
		STICKY_CACHE_ENTRY = 4,
		EDITED_CACHE_ENTRY = 8,
		TRACK_OFFLINE_CACHE_ENTRY = 16,
		TRACK_ONLINE_CACHE_ENTRY = 32,
		SPARSE_CACHE_ENTRY = 65536,
		COOKIE_CACHE_ENTRY = 1048576,
		URLHISTORY_CACHE_ENTRY = 2097152,
		ALL = 3211325
	}

	/// <summary>
	/// For PInvoke: Contains information about an entry in the Internet cache
	/// </summary>
	[StructLayout(LayoutKind.Sequential)]
	private class INTERNET_CACHE_ENTRY_INFOA
	{
		public uint dwStructureSize;

		public IntPtr lpszSourceUrlName;

		public IntPtr lpszLocalFileName;

		public WININETCACHEENTRYTYPE CacheEntryType;

		public uint dwUseCount;

		public uint dwHitRate;

		public uint dwSizeLow;

		public uint dwSizeHigh;

		public FILETIME LastModifiedTime;

		public FILETIME ExpireTime;

		public FILETIME LastAccessTime;

		public FILETIME LastSyncTime;

		public IntPtr lpHeaderInfo;

		public uint dwHeaderInfoSize;

		public IntPtr lpszFileExtension;

		public WININETCACHEENTRYINFOUNION _Union;
	}

	[StructLayout(LayoutKind.Explicit)]
	private struct WININETCACHEENTRYINFOUNION
	{
		[FieldOffset(0)]
		public uint dwReserved;

		[FieldOffset(0)]
		public uint dwExemptDelta;
	}

	private static WinINetHelper instance;

	private const int CACHEGROUP_SEARCH_ALL = 0;

	private const int CACHEGROUP_FLAG_FLUSHURL_ONDELETE = 2;

	private const int ERROR_FILE_NOT_FOUND = 2;

	private const int ERROR_NO_MORE_ITEMS = 259;

	private const int ERROR_INSUFFICENT_BUFFER = 122;

	public static WinINetHelper Instance
	{
		get
		{
			if (instance == null)
			{
				instance = new WinINetHelper();
			}
			return instance;
		}
	}

	private WinINetHelper()
	{
	}

	public void ClearCacheItems(bool clearFiles, bool clearCookies)
	{
		if (Environment.OSVersion.Version.Major > 5)
		{
			PlatformExtensionsForWindows.Instance.OnLog(string.Format("Windows Vista+ detected. Calling INETCPL to clear [{0}{1}].", clearFiles ? "CacheFiles" : string.Empty, clearCookies ? "Cookies" : string.Empty));
			VistaClearTracks(clearFiles, clearCookies);
			return;
		}
		if (clearCookies)
		{
			ClearCookiesForHost("*");
		}
		if (!clearFiles)
		{
			return;
		}
		PlatformExtensionsForWindows.Instance.OnLog("Beginning WinINET Cache clearing...");
		long groupId = 0L;
		int cacheEntryInfoBufferSizeInitial = 0;
		int cacheEntryInfoBufferSize = 0;
		IntPtr cacheEntryInfoBuffer = IntPtr.Zero;
		IntPtr enumHandle = IntPtr.Zero;
		bool returnValue = false;
		enumHandle = FindFirstUrlCacheGroup(0, 0, IntPtr.Zero, 0, ref groupId, IntPtr.Zero);
		int iLastError = Marshal.GetLastWin32Error();
		if (enumHandle != IntPtr.Zero && 259 != iLastError && 2 != iLastError)
		{
			do
			{
				returnValue = DeleteUrlCacheGroup(groupId, 2, IntPtr.Zero);
				iLastError = Marshal.GetLastWin32Error();
				if (!returnValue && 2 == iLastError)
				{
					returnValue = FindNextUrlCacheGroup(enumHandle, ref groupId, IntPtr.Zero);
					iLastError = Marshal.GetLastWin32Error();
				}
			}
			while (returnValue || (259 != iLastError && 2 != iLastError));
		}
		enumHandle = FindFirstUrlCacheEntryEx(null, 0, WININETCACHEENTRYTYPE.ALL, 0L, IntPtr.Zero, ref cacheEntryInfoBufferSizeInitial, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
		iLastError = Marshal.GetLastWin32Error();
		if (IntPtr.Zero == enumHandle && 259 == iLastError)
		{
			return;
		}
		cacheEntryInfoBufferSize = cacheEntryInfoBufferSizeInitial;
		cacheEntryInfoBuffer = Marshal.AllocHGlobal(cacheEntryInfoBufferSize);
		enumHandle = FindFirstUrlCacheEntryEx(null, 0, WININETCACHEENTRYTYPE.ALL, 0L, cacheEntryInfoBuffer, ref cacheEntryInfoBufferSizeInitial, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
		iLastError = Marshal.GetLastWin32Error();
		do
		{
			INTERNET_CACHE_ENTRY_INFOA internetCacheEntry = (INTERNET_CACHE_ENTRY_INFOA)Marshal.PtrToStructure(cacheEntryInfoBuffer, typeof(INTERNET_CACHE_ENTRY_INFOA));
			cacheEntryInfoBufferSizeInitial = cacheEntryInfoBufferSize;
			if (WININETCACHEENTRYTYPE.COOKIE_CACHE_ENTRY != (internetCacheEntry.CacheEntryType & WININETCACHEENTRYTYPE.COOKIE_CACHE_ENTRY))
			{
				returnValue = DeleteUrlCacheEntry(internetCacheEntry.lpszSourceUrlName);
			}
			returnValue = FindNextUrlCacheEntryEx(enumHandle, cacheEntryInfoBuffer, ref cacheEntryInfoBufferSizeInitial, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
			iLastError = Marshal.GetLastWin32Error();
			if (!returnValue && 259 == iLastError)
			{
				break;
			}
			if (!returnValue && cacheEntryInfoBufferSizeInitial > cacheEntryInfoBufferSize)
			{
				cacheEntryInfoBufferSize = cacheEntryInfoBufferSizeInitial;
				cacheEntryInfoBuffer = Marshal.ReAllocHGlobal(cacheEntryInfoBuffer, (IntPtr)cacheEntryInfoBufferSize);
				returnValue = FindNextUrlCacheEntryEx(enumHandle, cacheEntryInfoBuffer, ref cacheEntryInfoBufferSizeInitial, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
			}
		}
		while (returnValue);
		Marshal.FreeHGlobal(cacheEntryInfoBuffer);
		PlatformExtensionsForWindows.Instance.OnLog("Completed WinINET Cache clearing.");
	}

	public void ClearCookiesForHost(string host)
	{
		host = host.Trim();
		if (host.Length < 1)
		{
			return;
		}
		string sFilter;
		if (host == "*")
		{
			sFilter = string.Empty;
			if (Environment.OSVersion.Version.Major > 5)
			{
				VistaClearTracks(clearFiles: false, clearCookies: true);
				return;
			}
		}
		else
		{
			sFilter = (host.StartsWith("*") ? host.Substring(1).ToLower() : ("@" + host.ToLower()));
		}
		int cacheEntryInfoBufferSizeInitial = 0;
		int cacheEntryInfoBufferSize = 0;
		IntPtr cacheEntryInfoBuffer = IntPtr.Zero;
		IntPtr enumHandle = IntPtr.Zero;
		enumHandle = FindFirstUrlCacheEntry("cookie:", IntPtr.Zero, ref cacheEntryInfoBufferSizeInitial);
		if (enumHandle == IntPtr.Zero && 259 == Marshal.GetLastWin32Error())
		{
			return;
		}
		cacheEntryInfoBufferSize = cacheEntryInfoBufferSizeInitial;
		cacheEntryInfoBuffer = Marshal.AllocHGlobal(cacheEntryInfoBufferSize);
		enumHandle = FindFirstUrlCacheEntry("cookie:", cacheEntryInfoBuffer, ref cacheEntryInfoBufferSizeInitial);
		while (true)
		{
			INTERNET_CACHE_ENTRY_INFOA internetCacheEntry = (INTERNET_CACHE_ENTRY_INFOA)Marshal.PtrToStructure(cacheEntryInfoBuffer, typeof(INTERNET_CACHE_ENTRY_INFOA));
			cacheEntryInfoBufferSizeInitial = cacheEntryInfoBufferSize;
			if (WININETCACHEENTRYTYPE.COOKIE_CACHE_ENTRY == (internetCacheEntry.CacheEntryType & WININETCACHEENTRYTYPE.COOKIE_CACHE_ENTRY))
			{
				bool bDeleteThisCookie;
				if (sFilter.Length == 0)
				{
					bDeleteThisCookie = true;
				}
				else
				{
					string sCandidateHost = Marshal.PtrToStringAnsi(internetCacheEntry.lpszSourceUrlName);
					int ixSlash = sCandidateHost.IndexOf('/');
					if (ixSlash > 0)
					{
						sCandidateHost = sCandidateHost.Remove(ixSlash);
					}
					sCandidateHost = sCandidateHost.ToLower();
					bDeleteThisCookie = sCandidateHost.EndsWith(sFilter);
				}
				if (bDeleteThisCookie)
				{
					bool returnValue = DeleteUrlCacheEntry(internetCacheEntry.lpszSourceUrlName);
				}
			}
			while (true)
			{
				bool returnValue = FindNextUrlCacheEntry(enumHandle, cacheEntryInfoBuffer, ref cacheEntryInfoBufferSizeInitial);
				if (returnValue || 259 != Marshal.GetLastWin32Error())
				{
					if (returnValue || cacheEntryInfoBufferSizeInitial <= cacheEntryInfoBufferSize)
					{
						break;
					}
					cacheEntryInfoBufferSize = cacheEntryInfoBufferSizeInitial;
					cacheEntryInfoBuffer = Marshal.ReAllocHGlobal(cacheEntryInfoBuffer, (IntPtr)cacheEntryInfoBufferSize);
					continue;
				}
				Marshal.FreeHGlobal(cacheEntryInfoBuffer);
				return;
			}
		}
	}

	public string GetCacheItemInfo(string url)
	{
		int cacheEntryInfoBufferSizeInitial = 0;
		int cacheEntryInfoBufferSize = 0;
		IntPtr cacheEntryInfoBuffer = IntPtr.Zero;
		bool bResult = GetUrlCacheEntryInfoA(url, cacheEntryInfoBuffer, ref cacheEntryInfoBufferSizeInitial);
		int iLastError = Marshal.GetLastWin32Error();
		if (bResult || iLastError != 122)
		{
			return $"This URL is not present in the WinINET cache. [Code: {iLastError}]";
		}
		cacheEntryInfoBufferSize = cacheEntryInfoBufferSizeInitial;
		cacheEntryInfoBuffer = Marshal.AllocHGlobal(cacheEntryInfoBufferSize);
		bResult = GetUrlCacheEntryInfoA(url, cacheEntryInfoBuffer, ref cacheEntryInfoBufferSizeInitial);
		iLastError = Marshal.GetLastWin32Error();
		if (!bResult)
		{
			Marshal.FreeHGlobal(cacheEntryInfoBuffer);
			return "GetUrlCacheEntryInfoA with buffer failed. 2=filenotfound 122=insufficient buffer, 259=nomoreitems. Last error: " + iLastError + "\n";
		}
		INTERNET_CACHE_ENTRY_INFOA internetCacheEntry = (INTERNET_CACHE_ENTRY_INFOA)Marshal.PtrToStructure(cacheEntryInfoBuffer, typeof(INTERNET_CACHE_ENTRY_INFOA));
		cacheEntryInfoBufferSizeInitial = cacheEntryInfoBufferSize;
		long lngLastMod = ((long)internetCacheEntry.LastModifiedTime.dwHighDateTime << 32) | (uint)internetCacheEntry.LastModifiedTime.dwLowDateTime;
		long lngLastAccess = ((long)internetCacheEntry.LastAccessTime.dwHighDateTime << 32) | (uint)internetCacheEntry.LastAccessTime.dwLowDateTime;
		long lngLastSync = ((long)internetCacheEntry.LastSyncTime.dwHighDateTime << 32) | (uint)internetCacheEntry.LastSyncTime.dwLowDateTime;
		long lngExpire = ((long)internetCacheEntry.ExpireTime.dwHighDateTime << 32) | (uint)internetCacheEntry.ExpireTime.dwLowDateTime;
		string sResult = "Url:\t\t" + Marshal.PtrToStringAnsi(internetCacheEntry.lpszSourceUrlName) + "\nCache File:\t" + Marshal.PtrToStringAnsi(internetCacheEntry.lpszLocalFileName) + "\nSize:\t\t" + (((ulong)internetCacheEntry.dwSizeHigh << 32) + internetCacheEntry.dwSizeLow).ToString("0,0") + " bytes\nFile Extension:\t" + Marshal.PtrToStringAnsi(internetCacheEntry.lpszFileExtension) + "\nHit Rate:\t" + internetCacheEntry.dwHitRate + "\nUse Count:\t" + internetCacheEntry.dwUseCount + "\nDon't Scavenge for:\t" + internetCacheEntry._Union.dwExemptDelta + " seconds\nLast Modified:\t" + DateTime.FromFileTime(lngLastMod).ToString() + "\nLast Accessed:\t" + DateTime.FromFileTime(lngLastAccess).ToString() + "\nLast Synced:  \t" + DateTime.FromFileTime(lngLastSync).ToString() + "\nEntry Expires:\t" + DateTime.FromFileTime(lngExpire).ToString() + "\n";
		Marshal.FreeHGlobal(cacheEntryInfoBuffer);
		return sResult;
	}

	private void VistaClearTracks(bool clearFiles, bool clearCookies)
	{
		int iFlag = 0;
		if (clearCookies)
		{
			iFlag |= 2;
		}
		if (clearFiles)
		{
			iFlag |= 0x100C;
		}
		try
		{
			using (Process.Start("rundll32.exe", "inetcpl.cpl,ClearMyTracksByProcess " + iFlag))
			{
			}
		}
		catch (Exception eX)
		{
			PlatformExtensionsForWindows.Instance.OnError("Failed to launch ClearMyTracksByProcess.\n" + eX.Message);
		}
	}

	[DllImport("wininet.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static extern bool GetUrlCacheEntryInfoA(string lpszUrlName, IntPtr lpCacheEntryInfo, ref int lpdwCacheEntryInfoBufferSize);

	[DllImport("wininet.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
	private static extern IntPtr FindFirstUrlCacheGroup(int dwFlags, int dwFilter, IntPtr lpSearchCondition, int dwSearchCondition, ref long lpGroupId, IntPtr lpReserved);

	[DllImport("wininet.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static extern bool FindNextUrlCacheGroup(IntPtr hFind, ref long lpGroupId, IntPtr lpReserved);

	[DllImport("wininet.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static extern bool DeleteUrlCacheGroup(long GroupId, int dwFlags, IntPtr lpReserved);

	[DllImport("wininet.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi, EntryPoint = "FindFirstUrlCacheEntryA", ExactSpelling = true, SetLastError = true)]
	private static extern IntPtr FindFirstUrlCacheEntry([MarshalAs(UnmanagedType.LPTStr)] string lpszUrlSearchPattern, IntPtr lpFirstCacheEntryInfo, ref int lpdwFirstCacheEntryInfoBufferSize);

	[DllImport("wininet.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi, EntryPoint = "FindNextUrlCacheEntryA", ExactSpelling = true, SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static extern bool FindNextUrlCacheEntry(IntPtr hFind, IntPtr lpNextCacheEntryInfo, ref int lpdwNextCacheEntryInfoBufferSize);

	[DllImport("wininet.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi, EntryPoint = "FindFirstUrlCacheEntryExA", ExactSpelling = true, SetLastError = true)]
	private static extern IntPtr FindFirstUrlCacheEntryEx([MarshalAs(UnmanagedType.LPTStr)] string lpszUrlSearchPattern, int dwFlags, WININETCACHEENTRYTYPE dwFilter, long GroupId, IntPtr lpFirstCacheEntryInfo, ref int lpdwFirstCacheEntryInfoBufferSize, IntPtr lpReserved, IntPtr pcbReserved2, IntPtr lpReserved3);

	[DllImport("wininet.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi, EntryPoint = "FindNextUrlCacheEntryExA", ExactSpelling = true, SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static extern bool FindNextUrlCacheEntryEx(IntPtr hEnumHandle, IntPtr lpNextCacheEntryInfo, ref int lpdwNextCacheEntryInfoBufferSize, IntPtr lpReserved, IntPtr pcbReserved2, IntPtr lpReserved3);

	[DllImport("wininet.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi, EntryPoint = "DeleteUrlCacheEntryA", ExactSpelling = true, SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static extern bool DeleteUrlCacheEntry(IntPtr lpszUrlName);
}
