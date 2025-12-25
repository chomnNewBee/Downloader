using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security;
using System.Text;
using System.Threading;
using FiddlerCore.Utilities;

namespace Fiddler;

internal class DNSResolver
{
	/// <summary>
	/// A DNSCacheEntry holds a cached resolution from the DNS
	/// </summary>
	private class DNSCacheEntry
	{
		/// <summary>
		/// TickCount of this record's creation
		/// </summary>
		internal ulong iLastLookup;

		/// <summary>
		/// IPAddresses for this hostname
		/// </summary>
		internal IPAddress[] arrAddressList;

		/// <summary>
		/// Construct a new cache entry
		/// </summary>
		/// <param name="arrIPs">The address information to add to the cache</param>
		internal DNSCacheEntry(IPAddress[] arrIPs)
		{
			iLastLookup = Utilities.GetTickCount();
			arrAddressList = arrIPs;
		}
	}

	/// <summary>
	/// Cache of Hostname-&gt;Address mappings
	/// </summary>
	private static readonly Dictionary<string, DNSCacheEntry> dictAddresses;

	/// <summary>
	/// Number of milliseconds that a DNS cache entry may be reused without validation.
	/// </summary>
	internal static ulong MSEC_DNS_CACHE_LIFETIME;

	/// <summary>
	/// Maximum number of A/AAAA records to cache for DNS entries.
	/// Beware: Changing this number changes how many IP-failovers Fiddler will perform if fiddler.network.dns.fallback is set,
	/// and increasing the number will consume more memory in the cache.
	/// </summary>
	private static readonly int COUNT_MAX_A_RECORDS;

	static DNSResolver()
	{
		COUNT_MAX_A_RECORDS = FiddlerApplication.Prefs.GetInt32Pref("fiddler.network.dns.MaxAddressCount", 5);
		MSEC_DNS_CACHE_LIFETIME = (ulong)FiddlerApplication.Prefs.GetInt32Pref("fiddler.network.timeouts.dnscache", 150000);
		dictAddresses = new Dictionary<string, DNSCacheEntry>();
		FiddlerApplication.Janitor.assignWork(ScavengeCache, 30000u);
	}

	/// <summary>
	/// Clear the DNS Cache. Called by the NetworkChange event handler in the oProxy object
	/// </summary>
	internal static void ClearCache()
	{
		lock (dictAddresses)
		{
			dictAddresses.Clear();
		}
	}

	/// <summary>
	/// Remove all expired DNSCache entries; called by the Janitor
	/// </summary>
	public static void ScavengeCache()
	{
		if (dictAddresses.Count < 1)
		{
			return;
		}
		if (CONFIG.bDebugSpew)
		{
			FiddlerApplication.DebugSpew("Scavenging DNS Cache...");
		}
		List<string> entriesToExpire = new List<string>();
		lock (dictAddresses)
		{
			foreach (KeyValuePair<string, DNSCacheEntry> oDE in dictAddresses)
			{
				if (oDE.Value.iLastLookup < Utilities.GetTickCount() - MSEC_DNS_CACHE_LIFETIME)
				{
					entriesToExpire.Add(oDE.Key);
				}
			}
			if (CONFIG.bDebugSpew)
			{
				FiddlerApplication.DebugSpew("Expiring " + entriesToExpire.Count + " of " + dictAddresses.Count + " DNS Records.");
			}
			foreach (string sKey in entriesToExpire)
			{
				dictAddresses.Remove(sKey);
			}
		}
		if (CONFIG.bDebugSpew)
		{
			FiddlerApplication.DebugSpew("Done scavenging DNS Cache...");
		}
	}

	/// <summary>
	/// Show the contents of the DNS Resolver cache
	/// </summary>
	/// <returns></returns>
	public static string InspectCache()
	{
		StringBuilder sbResult = new StringBuilder(8192);
		sbResult.AppendFormat("DNSResolver Cache\nfiddler.network.timeouts.dnscache: {0}ms\nContents\n--------\n", MSEC_DNS_CACHE_LIFETIME);
		lock (dictAddresses)
		{
			foreach (KeyValuePair<string, DNSCacheEntry> oDE in dictAddresses)
			{
				StringBuilder sbAddressList = new StringBuilder();
				sbAddressList.Append(" [");
				IPAddress[] arrAddressList = oDE.Value.arrAddressList;
				foreach (IPAddress ipAddr in arrAddressList)
				{
					sbAddressList.Append(ipAddr.ToString());
					sbAddressList.Append(", ");
				}
				sbAddressList.Remove(sbAddressList.Length - 2, 2);
				sbAddressList.Append("]");
				sbResult.AppendFormat("\tHostName: {0}, Age: {1}ms, AddressList:{2}\n", oDE.Key, Utilities.GetTickCount() - oDE.Value.iLastLookup, sbAddressList.ToString());
			}
		}
		sbResult.Append("--------\n");
		return sbResult.ToString();
	}

	/// <summary>
	/// Gets first available IP Address from DNS. Throws if address not found!
	/// </summary>
	/// <param name="sRemoteHost">String containing the host</param>
	/// <param name="bCheckCache">True to use Fiddler's DNS cache.</param>
	/// <returns>IPAddress of target, if found.</returns>
	public static IPAddress GetIPAddress(string sRemoteHost, bool bCheckCache)
	{
		return GetIPAddressList(sRemoteHost, bCheckCache, null)[0];
	}

	private static void AssignIPEPList(ServerChatter.MakeConnectionExecutionState _esState, IPAddress[] _arrIPs)
	{
		List<IPEndPoint> oDests = new List<IPEndPoint>(_arrIPs.Length);
		foreach (IPAddress ipA in _arrIPs)
		{
			oDests.Add(new IPEndPoint(ipA, _esState.iServerPort));
		}
		_esState.arrIPEPDest = oDests.ToArray();
	}

	internal static bool ResolveWentAsync(ServerChatter.MakeConnectionExecutionState _es, SessionTimers oTimers, AsyncCallback callbackAsync)
	{
		if (_es == null)
		{
			throw new ArgumentNullException("_es");
		}
		if (callbackAsync == null)
		{
			throw new ArgumentNullException("callbackAsync");
		}
		if (_es.sServerHostname == null)
		{
			throw new InvalidOperationException("_es.sServerHostname must not be null");
		}
		string sRemoteHost = _es.sServerHostname;
		IPAddress[] arrResults = null;
		Stopwatch oSW = Stopwatch.StartNew();
		IPAddress ipDest = Utilities.IPFromString(sRemoteHost);
		if (ipDest != null)
		{
			arrResults = new IPAddress[1] { ipDest };
			if (oTimers != null)
			{
				oTimers.DNSTime = (int)oSW.ElapsedMilliseconds;
			}
			AssignIPEPList(_es, arrResults);
			return false;
		}
		sRemoteHost = sRemoteHost.ToLower();
		lock (dictAddresses)
		{
			if (dictAddresses.TryGetValue(sRemoteHost, out var oCacheEntry))
			{
				if (oCacheEntry.iLastLookup > Utilities.GetTickCount() - MSEC_DNS_CACHE_LIFETIME)
				{
					arrResults = oCacheEntry.arrAddressList;
				}
				else
				{
					dictAddresses.Remove(sRemoteHost);
				}
			}
		}
		if (arrResults != null)
		{
			if (oTimers != null)
			{
				oTimers.DNSTime = (int)oSW.ElapsedMilliseconds;
			}
			AssignIPEPList(_es, arrResults);
			Interlocked.Increment(ref COUNTERS.DNSCACHE_HITS);
			return false;
		}
		if ((sRemoteHost.OICEndsWith(".onion") || sRemoteHost.OICEndsWith(".i2p")) && !FiddlerApplication.Prefs.GetBoolPref("fiddler.network.dns.ResolveOnionHosts", bDefault: false))
		{
			throw new SecurityException("Hostnames ending in '.onion' and '.i2p' cannot be resolved by DNS. You must send such requests through a TOR or i2p gateway, e.g. oSession[\"X-OverrideGateway\"] = \"socks=127.0.0.1:9150\";");
		}
		Interlocked.Increment(ref COUNTERS.ASYNC_DNS);
		Interlocked.Increment(ref COUNTERS.TOTAL_ASYNC_DNS);
		Dns.BeginGetHostAddresses(sRemoteHost, delegate(IAsyncResult iar)
		{
			Interlocked.Decrement(ref COUNTERS.ASYNC_DNS);
			try
			{
				if (iar.AsyncState is SessionTimers sessionTimers)
				{
					sessionTimers.DNSTime = (int)oSW.ElapsedMilliseconds;
					Interlocked.Add(ref COUNTERS.TOTAL_ASYNC_DNS_MS, oSW.ElapsedMilliseconds);
				}
				IPAddress[] arrResult = Dns.EndGetHostAddresses(iar);
				arrResult = trimAddressList(arrResult);
				if (arrResult.Length < 1)
				{
					throw new Exception("No valid addresses were found for this hostname");
				}
				lock (dictAddresses)
				{
					if (!dictAddresses.ContainsKey(sRemoteHost))
					{
						dictAddresses.Add(sRemoteHost, new DNSCacheEntry(arrResult));
					}
				}
				AssignIPEPList(_es, arrResult);
			}
			catch (Exception lastException)
			{
				_es.lastException = lastException;
			}
			callbackAsync(iar);
		}, oTimers);
		return true;
	}

	/// <summary>
	/// Gets IP Addresses for host from DNS. Throws if address not found!
	/// </summary>
	/// <param name="sRemoteHost">String containing the host</param>
	/// <param name="bCheckCache">True to use Fiddler's DNS cache.</param>
	/// <param name="oTimers">The Timers object to which the DNS lookup time should be stored, or null</param>
	/// <returns>List of IPAddresses of target, if any found.</returns>
	public static IPAddress[] GetIPAddressList(string sRemoteHost, bool bCheckCache, SessionTimers oTimers)
	{
		IPAddress[] arrResult = null;
		Stopwatch oSW = Stopwatch.StartNew();
		IPAddress ipDest = Utilities.IPFromString(sRemoteHost);
		if (ipDest != null)
		{
			arrResult = new IPAddress[1] { ipDest };
			if (oTimers != null)
			{
				oTimers.DNSTime = (int)oSW.ElapsedMilliseconds;
			}
			return arrResult;
		}
		sRemoteHost = sRemoteHost.ToLower();
		if (bCheckCache)
		{
			lock (dictAddresses)
			{
				if (dictAddresses.TryGetValue(sRemoteHost, out var oCacheEntry))
				{
					if (oCacheEntry.iLastLookup > Utilities.GetTickCount() - MSEC_DNS_CACHE_LIFETIME)
					{
						arrResult = oCacheEntry.arrAddressList;
					}
					else
					{
						dictAddresses.Remove(sRemoteHost);
					}
				}
			}
		}
		if (arrResult == null)
		{
			if ((sRemoteHost.OICEndsWith(".onion") || sRemoteHost.OICEndsWith(".i2p")) && !FiddlerApplication.Prefs.GetBoolPref("fiddler.network.dns.ResolveOnionHosts", bDefault: false))
			{
				throw new SecurityException("Hostnames ending in '.onion' and '.i2p' cannot be resolved by DNS. You must send such requests through a TOR or i2p gateway, e.g. oSession[\"X-OverrideGateway\"] = \"socks=127.0.0.1:9150\";");
			}
			try
			{
				arrResult = Dns.GetHostAddresses(sRemoteHost);
			}
			catch
			{
				if (oTimers != null)
				{
					oTimers.DNSTime = (int)oSW.ElapsedMilliseconds;
				}
				throw;
			}
			arrResult = trimAddressList(arrResult);
			if (arrResult.Length < 1)
			{
				throw new Exception("No valid IPv4 addresses were found for this host.");
			}
			if (arrResult.Length != 0)
			{
				lock (dictAddresses)
				{
					if (!dictAddresses.ContainsKey(sRemoteHost))
					{
						dictAddresses.Add(sRemoteHost, new DNSCacheEntry(arrResult));
					}
				}
			}
		}
		if (oTimers != null)
		{
			oTimers.DNSTime = (int)oSW.ElapsedMilliseconds;
		}
		return arrResult;
	}

	/// <summary>
	/// Trim an address list, removing the duplicate entries, any IPv6-entries if IPv6 is disabled, 
	/// and entries beyond the COUNT_MAX_A_RECORDS limit.
	/// </summary>
	/// <param name="arrResult">The list to filter</param>
	/// <returns>A filtered address list</returns>
	private static IPAddress[] trimAddressList(IPAddress[] arrResult)
	{
		List<IPAddress> listFinalAddrs = new List<IPAddress>();
		for (int i = 0; i < arrResult.Length; i++)
		{
			if (!listFinalAddrs.Contains(arrResult[i]) && (CONFIG.EnableIPv6 || arrResult[i].AddressFamily == AddressFamily.InterNetwork))
			{
				listFinalAddrs.Add(arrResult[i]);
				if (COUNT_MAX_A_RECORDS == listFinalAddrs.Count)
				{
					break;
				}
			}
		}
		return listFinalAddrs.ToArray();
	}

	internal static string GetCanonicalName(string sHostname)
	{
		try
		{
			IPHostEntry iphe = Dns.GetHostEntry(sHostname);
			return iphe.HostName;
		}
		catch (Exception eX)
		{
			FiddlerApplication.Log.LogFormat("Failed to retrieve CNAME for \"{0}\", because '{1}'", sHostname, FiddlerCore.Utilities.Utilities.DescribeException(eX));
			return string.Empty;
		}
	}

	internal static string GetAllInfo(string sHostname)
	{
		IPHostEntry iphe;
		try
		{
			iphe = Dns.GetHostEntry(sHostname);
		}
		catch (Exception eX)
		{
			return $"FiddlerDNS> DNS Lookup for \"{sHostname}\" failed because '{FiddlerCore.Utilities.Utilities.DescribeException(eX)}'\n";
		}
		StringBuilder sbResult = new StringBuilder();
		sbResult.AppendFormat("FiddlerDNS> DNS Lookup for \"{0}\":\r\n", sHostname);
		sbResult.AppendFormat("CNAME:\t{0}\n", iphe.HostName);
		sbResult.AppendFormat("Aliases:\t{0}\n", string.Join(";", iphe.Aliases));
		sbResult.AppendLine("Addresses:");
		IPAddress[] addressList = iphe.AddressList;
		foreach (IPAddress ipAddr in addressList)
		{
			sbResult.AppendFormat("\t{0}\r\n", ipAddr.ToString());
		}
		return sbResult.ToString();
	}
}
