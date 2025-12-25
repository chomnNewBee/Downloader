using System;
using System.Collections.Generic;
using System.Text;

namespace Fiddler;

/// <summary>
/// The HostList allows fast determination of whether a given host is in the list. It supports leading wildcards (e.g. *.foo.com), and the special tokens  &lt;local&gt; &lt;nonlocal&gt; and &lt;loopback&gt;.
/// Note: List is *not* threadsafe; instead of updating it, construct a new one.
/// </summary>
public class HostList
{
	/// <summary>
	/// This private tuple allows us to associate a Hostname and a Port
	/// </summary>
	private class HostPortTuple
	{
		/// <summary>
		/// Port specified in the rule
		/// </summary>
		public int _iPort;

		/// <summary>
		/// Hostname specified in the rule
		/// </summary>
		public string _sHostname;

		public bool _bTailMatch;

		/// <summary>
		/// Create a new HostPortTuple
		/// </summary>
		internal HostPortTuple(string sHostname, int iPort)
		{
			_iPort = iPort;
			if (sHostname.StartsWith("*"))
			{
				_bTailMatch = true;
				_sHostname = sHostname.Substring(1);
			}
			else
			{
				_sHostname = sHostname;
			}
		}
	}

	private HashSet<string> slSimpleHosts = new HashSet<string>();

	private List<HostPortTuple> hplComplexRules = new List<HostPortTuple>();

	private bool bEverythingMatches;

	private bool bNonPlainHostnameMatches;

	private bool bPlainHostnameMatches;

	private bool bLoopbackMatches;

	/// <summary>
	/// Generate an empty HostList
	/// </summary>
	public HostList()
	{
	}

	/// <summary>
	/// Create a hostlist and assign it an initial set of sites
	/// </summary>
	/// <param name="sInitialList">List of hostnames, including leading wildcards, and optional port specifier. Special tokens are *, &lt;local&gt;, &lt;nonlocal&gt;, and &lt;loopback&gt;.</param>
	public HostList(string sInitialList)
		: this()
	{
		if (!string.IsNullOrEmpty(sInitialList))
		{
			AssignFromString(sInitialList);
		}
	}

	/// <summary>
	/// Clear the HostList
	/// </summary>
	public void Clear()
	{
		bLoopbackMatches = (bPlainHostnameMatches = (bNonPlainHostnameMatches = (bEverythingMatches = false)));
		slSimpleHosts.Clear();
		hplComplexRules.Clear();
	}

	/// <summary>
	/// Clear the List and assign the new string as the contents of the list.
	/// </summary>
	/// <param name="sIn">List of hostnames, including leading wildcards, and optional port specifier. Special tokens are *, &lt;local&gt;, &lt;nonlocal&gt;, and &lt;loopback&gt;.</param>
	/// <returns>TRUE if the list was constructed without errors</returns>
	public bool AssignFromString(string sIn)
	{
		string sDontCare;
		return AssignFromString(sIn, out sDontCare);
	}

	/// <summary>
	/// Clear the list and assign the new string as the contents of the list.
	/// </summary>
	/// <param name="sIn">List of hostnames, including leading wildcards, and optional port specifier. Special tokens are *, &lt;local&gt;, &lt;nonlocal&gt;, and &lt;loopback&gt;.</param>
	/// <param name="sErrors">Outparam string containing list of parsing errors</param>
	/// <returns>TRUE if the list was constructed without errors</returns>
	public bool AssignFromString(string sIn, out string sErrors)
	{
		sErrors = string.Empty;
		Clear();
		if (sIn == null)
		{
			return true;
		}
		sIn = sIn.Trim();
		if (sIn.Length < 1)
		{
			return true;
		}
		string[] sRules = sIn.ToLower().Split(new char[6] { ',', ';', '\t', ' ', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
		string[] array = sRules;
		foreach (string sRule in array)
		{
			if (sRule.Equals("*"))
			{
				bEverythingMatches = true;
				continue;
			}
			if (sRule.StartsWith("<"))
			{
				if (sRule.Equals("<loopback>"))
				{
					bLoopbackMatches = true;
					continue;
				}
				if (sRule.Equals("<local>"))
				{
					bPlainHostnameMatches = true;
					continue;
				}
				if (sRule.Equals("<nonlocal>"))
				{
					bNonPlainHostnameMatches = true;
					continue;
				}
			}
			if (sRule.Length < 1)
			{
				continue;
			}
			if (sRule.Contains("?"))
			{
				sErrors += $"Ignored invalid rule '{sRule}'-- ? may not appear.\n";
				continue;
			}
			if (sRule.LastIndexOf("*") > 0)
			{
				sErrors += $"Ignored invalid rule '{sRule}'-- * may only appear once, at the front of the string.\n";
				continue;
			}
			int iPort = -1;
			Utilities.CrackHostAndPort(sRule, out var sHostOnly, ref iPort);
			if (-1 == iPort && !sHostOnly.StartsWith("*"))
			{
				slSimpleHosts.Add(sRule);
				continue;
			}
			HostPortTuple oHP = new HostPortTuple(sHostOnly, iPort);
			hplComplexRules.Add(oHP);
		}
		if (bNonPlainHostnameMatches && bPlainHostnameMatches)
		{
			bEverythingMatches = true;
		}
		return string.IsNullOrEmpty(sErrors);
	}

	/// <summary>
	/// Return the current list of rules as a string
	/// </summary>
	/// <returns>String containing current rules, using "; " as a delimiter between entries</returns>
	public override string ToString()
	{
		StringBuilder sbOutput = new StringBuilder();
		if (bEverythingMatches)
		{
			sbOutput.Append("*; ");
		}
		if (bPlainHostnameMatches)
		{
			sbOutput.Append("<local>; ");
		}
		if (bNonPlainHostnameMatches)
		{
			sbOutput.Append("<nonlocal>; ");
		}
		if (bLoopbackMatches)
		{
			sbOutput.Append("<loopback>; ");
		}
		foreach (string sRule in slSimpleHosts)
		{
			sbOutput.Append(sRule);
			sbOutput.Append("; ");
		}
		foreach (HostPortTuple hpt in hplComplexRules)
		{
			if (hpt._bTailMatch)
			{
				sbOutput.Append("*");
			}
			sbOutput.Append(hpt._sHostname);
			if (hpt._iPort > -1)
			{
				sbOutput.Append(":");
				sbOutput.Append(hpt._iPort.ToString());
			}
			sbOutput.Append("; ");
		}
		if (sbOutput.Length > 1)
		{
			sbOutput.Remove(sbOutput.Length - 1, 1);
		}
		return sbOutput.ToString();
	}

	/// <summary>
	/// Determine if a given Host is in the list
	/// </summary>
	/// <param name="sHost">A Host string, potentially including a port</param>
	/// <returns>TRUE if the Host's hostname matches a rule in the list</returns>
	public bool ContainsHost(string sHost)
	{
		int iOut = -1;
		Utilities.CrackHostAndPort(sHost, out var sHostname, ref iOut);
		return ContainsHost(sHostname, iOut);
	}

	/// <summary>
	/// Determine if a given Hostname is in the list
	/// </summary>
	/// <param name="sHostname">A hostname, NOT including a port</param>
	/// <returns>TRUE if the hostname matches a rule in the list</returns>
	public bool ContainsHostname(string sHostname)
	{
		return ContainsHost(sHostname, -1);
	}

	/// <summary>
	/// Determine if a given Host:Port pair matches an entry in the list
	/// </summary>
	/// <param name="sHostname">A hostname, NOT including the port</param>
	/// <param name="iPort">The port</param>
	/// <returns>TRUE if the hostname matches a rule in the list</returns>
	public bool ContainsHost(string sHostname, int iPort)
	{
		if (bEverythingMatches)
		{
			return true;
		}
		if (bPlainHostnameMatches || bNonPlainHostnameMatches)
		{
			bool bIsPlain = Utilities.isPlainHostName(sHostname);
			if (bPlainHostnameMatches && bIsPlain)
			{
				return true;
			}
			if (bNonPlainHostnameMatches && !bIsPlain)
			{
				return true;
			}
		}
		if (bLoopbackMatches && Utilities.isLocalhostname(sHostname))
		{
			return true;
		}
		sHostname = sHostname.ToLower();
		if (slSimpleHosts.Contains(sHostname))
		{
			return true;
		}
		foreach (HostPortTuple hpt in hplComplexRules)
		{
			if (iPort == hpt._iPort || -1 == hpt._iPort)
			{
				if (hpt._bTailMatch && sHostname.EndsWith(hpt._sHostname))
				{
					return true;
				}
				if (hpt._sHostname == sHostname)
				{
					return true;
				}
			}
		}
		return false;
	}
}
