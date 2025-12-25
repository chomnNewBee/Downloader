using System;
using System.IO;
using System.Net;
using FiddlerCore.PlatformExtensions;
using FiddlerCore.PlatformExtensions.API;

namespace Fiddler;

/// <summary>
/// The AutoProxy class is used to handle upstream gateways when the client was configured to use WPAD or a Proxy AutoConfig (PAC) script.
/// </summary>
internal class AutoProxy : IDisposable
{
	private readonly IPlatformExtensions platformExtensions = PlatformExtensionsFactory.Instance.CreatePlatformExtensions();

	private readonly IAutoProxy autoProxy;

	/// <summary>
	/// Indication as to whether AutoProxy information is valid. 0=Unknown/Enabled; 1=Valid/Enabled; -1=Invalid/Disabled
	/// </summary>
	internal int iAutoProxySuccessCount = 0;

	private readonly string _sPACScriptLocation;

	private readonly bool _bUseAutoDiscovery = true;

	private bool bIsDisposed;

	/// <summary>
	/// Get the text of the file located at a specified file URI, or null if the URI is non-file or the file is not found.
	/// </summary>
	private static string GetPACFileText(string sURI)
	{
		try
		{
			Uri oURI = new Uri(sURI);
			if (!oURI.IsFile)
			{
				return null;
			}
			string sFilename = oURI.LocalPath;
			if (!File.Exists(sFilename))
			{
				FiddlerApplication.Log.LogFormat("! Failed to find the configured PAC script '{0}'", sFilename);
				return null;
			}
			return File.ReadAllText(sFilename);
		}
		catch (Exception eX)
		{
			FiddlerApplication.Log.LogFormat("! Failed to host the configured PAC script {0}", eX);
			return null;
		}
	}

	public AutoProxy(bool bAutoDiscover, string sAutoConfigUrl)
	{
		_bUseAutoDiscovery = bAutoDiscover;
		if (!string.IsNullOrEmpty(sAutoConfigUrl))
		{
			if (sAutoConfigUrl.OICStartsWith("file:") || sAutoConfigUrl.StartsWith("\\\\") || (sAutoConfigUrl.Length > 2 && sAutoConfigUrl[1] == ':'))
			{
				Proxy.sUpstreamPACScript = GetPACFileText(sAutoConfigUrl);
				if (!string.IsNullOrEmpty(Proxy.sUpstreamPACScript))
				{
					FiddlerApplication.Log.LogFormat("!WARNING: System proxy was configured to use a file-protocol sourced script ({0}). Proxy scripts delivered by the file protocol are not supported by many clients. Please see http://blogs.msdn.com/b/ieinternals/archive/2013/10/11/web-proxy-configuration-and-ie11-changes.aspx for more information.", sAutoConfigUrl);
					sAutoConfigUrl = "http://" + CONFIG.sFiddlerListenHostPort + "/UpstreamProxy.pac";
				}
			}
			_sPACScriptLocation = sAutoConfigUrl;
		}
		bool autoProxyRunInProcess = FiddlerApplication.Prefs.GetBoolPref("fiddler.network.gateway.DetermineInProcess", bDefault: false);
		autoProxy = platformExtensions.CreateAutoProxy(bAutoDiscover, sAutoConfigUrl, autoProxyRunInProcess, CONFIG.bAutoProxyLogon);
	}

	/// <summary>
	/// Returns a string containing the currently selected autoproxy options
	/// </summary>
	/// <returns></returns>
	public override string ToString()
	{
		string sResult = null;
		if (iAutoProxySuccessCount < 0)
		{
			sResult = "\tOffline/disabled\n";
		}
		else
		{
			if (_bUseAutoDiscovery)
			{
				string sURI = GetWPADUrl();
				if (string.IsNullOrEmpty(sURI))
				{
					sURI = "Not detected";
				}
				sResult = $"\tWPAD: {sURI}\n";
			}
			if (_sPACScriptLocation != null)
			{
				sResult = sResult + "\tConfig script: " + _sPACScriptLocation + "\n";
			}
		}
		return sResult ?? "\tDisabled";
	}

	/// <summary>
	/// Get WPAD-discovered URL for display purposes (e.g. Help&gt; About); note that we don't actually use this when determining the gateway,
	/// instead relying on the this.autoProxy.TryGetProxyForUrl method to do this work for us.
	/// </summary>
	/// <returns>A WPAD url, if found, or String.Empty</returns>
	private string GetWPADUrl()
	{
		if (autoProxy.TryGetPacUrl(out var wpadUrl))
		{
			return wpadUrl;
		}
		return string.Empty;
	}

	/// <summary>
	/// Return gateway endpoint for requested Url. TODO: Add caching layer on our side? TODO: Support multiple results?
	/// </summary>
	/// <param name="sUrl">The URL for which the gateway should be determined</param>
	/// <param name="ipepResult">The Endpoint of the Gateway, or null</param>
	/// <returns>TRUE if WinHttpGetProxyForUrl succeeded</returns>
	public bool GetAutoProxyForUrl(string sUrl, out IPEndPoint ipepResult)
	{
		if (bIsDisposed)
		{
			ipepResult = null;
			return false;
		}
		if (autoProxy.TryGetProxyForUrl(sUrl, out var sProxy, out var errorMessage))
		{
			ipepResult = Utilities.IPEndPointFromHostPortString(sProxy);
			if (ipepResult == null)
			{
				FiddlerApplication.Log.LogFormat("Proxy Configuration Script specified an unreachable proxy: {0} for URL: {1}", sProxy, sUrl);
			}
			return true;
		}
		if (string.IsNullOrEmpty(errorMessage))
		{
			FiddlerApplication._Log.LogString("Fiddler.Network.AutoProxy> " + errorMessage);
		}
		ipepResult = null;
		return false;
	}

	/// <summary>
	/// Dispose AutoProxy.
	/// </summary>
	public void Dispose()
	{
		autoProxy.Dispose();
		bIsDisposed = true;
	}
}
