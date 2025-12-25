using System;
using System.Collections.Generic;
using System.Diagnostics;
using FiddlerCore.PlatformExtensions;
using FiddlerCore.PlatformExtensions.API;

namespace Fiddler;

/// <summary>
/// This class allows fast-lookup of a ProcessName from a ProcessID.
/// </summary>
internal static class ProcessHelper
{
	/// <summary>
	/// Structure mapping a Process ID (PID) to a ProcessName
	/// </summary>
	internal struct ProcessNameCacheEntry
	{
		/// <summary>
		/// The TickCount when this entry was created
		/// </summary>
		internal readonly ulong ulLastLookup;

		/// <summary>
		/// The ProcessName (e.g. IEXPLORE.EXE)
		/// </summary>
		internal readonly string sProcessName;

		/// <summary>
		/// Create a PID-&gt;ProcessName mapping
		/// </summary>
		/// <param name="_sProcessName">The ProcessName (e.g. IEXPLORE.EXE)</param>
		internal ProcessNameCacheEntry(string _sProcessName)
		{
			ulLastLookup = Utilities.GetTickCount();
			sProcessName = _sProcessName;
		}
	}

	private static bool bDisambiguateWWAHostApps;

	private const uint MSEC_PROCESSNAME_CACHE_LIFETIME = 30000u;

	private static readonly Dictionary<int, ProcessNameCacheEntry> dictProcessNames;

	/// <summary>
	/// Static constructor which registers for cleanup
	/// </summary>
	static ProcessHelper()
	{
		bDisambiguateWWAHostApps = false;
		dictProcessNames = new Dictionary<int, ProcessNameCacheEntry>();
		FiddlerApplication.Janitor.assignWork(ScavengeCache, 60000u);
		if (Utilities.IsWin8OrLater() && FiddlerApplication.Prefs.GetBoolPref("fiddler.ProcessInfo.DecorateWithAppName", bDefault: true))
		{
			bDisambiguateWWAHostApps = true;
		}
	}

	/// <summary>
	/// Prune the cache of expiring PIDs
	/// </summary>
	internal static void ScavengeCache()
	{
		lock (dictProcessNames)
		{
			List<int> oExpiringPIDs = new List<int>();
			foreach (KeyValuePair<int, ProcessNameCacheEntry> oEntry in dictProcessNames)
			{
				if (oEntry.Value.ulLastLookup < Utilities.GetTickCount() - 30000)
				{
					oExpiringPIDs.Add(oEntry.Key);
				}
			}
			foreach (int iKey in oExpiringPIDs)
			{
				dictProcessNames.Remove(iKey);
			}
		}
	}

	/// <summary>
	/// Map a Process ID (PID) to a Process Name
	/// </summary>
	/// <param name="iPID">The PID</param>
	/// <returns>A Process Name (e.g. IEXPLORE.EXE) or String.Empty</returns>
	internal static string GetProcessName(int iPID)
	{
		try
		{
			if (dictProcessNames.TryGetValue(iPID, out var oCacheEntry))
			{
				if (oCacheEntry.ulLastLookup > Utilities.GetTickCount() - 30000)
				{
					return oCacheEntry.sProcessName;
				}
				lock (dictProcessNames)
				{
					dictProcessNames.Remove(iPID);
				}
			}
			string sResult = Process.GetProcessById(iPID).ProcessName.ToLower();
			if (string.IsNullOrEmpty(sResult))
			{
				return string.Empty;
			}
			if (bDisambiguateWWAHostApps)
			{
				IPlatformExtensions extensions = PlatformExtensionsFactory.Instance.CreatePlatformExtensions();
				sResult = extensions.PostProcessProcessName(iPID, sResult);
			}
			lock (dictProcessNames)
			{
				if (!dictProcessNames.ContainsKey(iPID))
				{
					dictProcessNames.Add(iPID, new ProcessNameCacheEntry(sResult));
				}
			}
			return sResult;
		}
		catch (Exception)
		{
			return string.Empty;
		}
	}
}
