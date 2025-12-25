using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace Fiddler;

/// <summary>
/// This class maintains the Proxy Bypass List for the upstream gateway. 
/// In the constructor, pass the desired proxy bypass string, as retrieved from WinINET for the Options screen.
/// Then, call the IsBypass(sTarget) method to determine if the Gateway should be bypassed
/// </summary>
internal class ProxyBypassList
{
	/// <summary>
	/// List of regular expressions for matching against request Scheme://HostPort.
	/// NB: This list is either null or contains at least one item.
	/// </summary>
	private List<Regex> _RegExBypassList;

	/// <summary>
	/// Boolean flag indicating whether the bypass list contained a &lt;local&gt; token.
	/// </summary>
	private bool _BypassOnLocal;

	/// <summary>
	/// Does the bypassList contain any rules at all?
	/// </summary>
	public bool HasEntries => _BypassOnLocal || _RegExBypassList != null;

	/// <summary>
	/// Pass the desired proxy bypass string retrieved from WinINET.
	/// </summary>
	/// <param name="sBypassList"></param>
	public ProxyBypassList(string sBypassList)
	{
		if (!string.IsNullOrEmpty(sBypassList))
		{
			AssignBypassList(sBypassList);
		}
	}

	[Obsolete]
	public bool IsBypass(string sSchemeHostPort)
	{
		string sScheme = Utilities.TrimAfter(sSchemeHostPort, "://");
		string sHostAndPort = Utilities.TrimBefore(sSchemeHostPort, "://");
		return IsBypass(sScheme, sHostAndPort);
	}

	/// <summary>
	/// Given the rules for this bypasslist, should this target bypass the proxy?
	/// </summary>
	/// <param name="sScheme">The URI Scheme</param>
	/// <param name="sHostAndPort">The Host and PORT</param>
	/// <returns>True if this request should not be sent to the gateway proxy</returns>
	public bool IsBypass(string sScheme, string sHostAndPort)
	{
		if (_BypassOnLocal && Utilities.isPlainHostName(sHostAndPort))
		{
			return true;
		}
		if (_RegExBypassList != null)
		{
			string sSchemeHostPort = sScheme + "://" + sHostAndPort;
			for (int i = 0; i < _RegExBypassList.Count; i++)
			{
				if (_RegExBypassList[i].IsMatch(sSchemeHostPort))
				{
					return true;
				}
			}
		}
		return false;
	}

	/// <summary>
	/// Convert the string representing the bypass list into an array of rules escaped and ready to be turned into regular expressions
	/// </summary>
	/// <param name="sBypassList"></param>
	private void AssignBypassList(string sBypassList)
	{
		_BypassOnLocal = false;
		_RegExBypassList = null;
		if (string.IsNullOrEmpty(sBypassList))
		{
			return;
		}
		if (CONFIG.bDebugSpew)
		{
			FiddlerApplication.DebugSpew("Build Bypass List from: {0}\n", sBypassList);
		}
		string[] arrEntries = sBypassList.Split(new char[1] { ';' }, StringSplitOptions.RemoveEmptyEntries);
		if (arrEntries.Length < 1)
		{
			return;
		}
		List<string> _slBypassRules = null;
		string[] array = arrEntries;
		foreach (string strEntry in array)
		{
			string strTrimmedEntry = strEntry.Trim();
			if (strTrimmedEntry.Length == 0)
			{
				continue;
			}
			if (strTrimmedEntry.OICEquals("<local>"))
			{
				_BypassOnLocal = true;
			}
			else if (!strTrimmedEntry.OICEquals("<-loopback>"))
			{
				if (!strTrimmedEntry.Contains("://"))
				{
					strTrimmedEntry = "*://" + strTrimmedEntry;
				}
				bool bNeedsPortWildcard = strTrimmedEntry.IndexOf(':') == strTrimmedEntry.LastIndexOf(':');
				strTrimmedEntry = Utilities.RegExEscape(strTrimmedEntry, bAddPrefixCaret: true, !bNeedsPortWildcard);
				if (bNeedsPortWildcard)
				{
					strTrimmedEntry += "(:\\d+)?$";
				}
				if (_slBypassRules == null)
				{
					_slBypassRules = new List<string>();
				}
				if (!_slBypassRules.Contains(strTrimmedEntry))
				{
					_slBypassRules.Add(strTrimmedEntry);
				}
			}
		}
		if (_slBypassRules == null)
		{
			return;
		}
		if (CONFIG.bDebugSpew)
		{
			FiddlerApplication.DebugSpew("Proxy Bypass List:\n{0}\n-----\n", string.Join("  \n", _slBypassRules.ToArray()));
		}
		_RegExBypassList = new List<Regex>(_slBypassRules.Count);
		foreach (string sRule in _slBypassRules)
		{
			try
			{
				Regex oRE = new Regex(sRule, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
				_RegExBypassList.Add(oRE);
			}
			catch
			{
				FiddlerApplication.Log.LogFormat("Invalid rule in Proxy Bypass list. '{0}'", sRule);
			}
		}
		if (_RegExBypassList.Count < 1)
		{
			_RegExBypassList = null;
		}
	}
}
