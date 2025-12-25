using System;
using System.Collections.Generic;
using System.Linq;
using FiddlerCore.Utilities;
using Telerik.NetworkConnections;

namespace Fiddler;

internal class Connectoids
{
	private readonly NetworkConnectionsManager connectionsManager;

	/// <summary>
	/// Dictionary of all Connectoids, indexed by the Connectoid's Name
	/// </summary>
	internal Dictionary<NetworkConnectionFullName, ProxySettings> ConnectionNamesToInitialProxySettingsMap { get; } = new Dictionary<NetworkConnectionFullName, ProxySettings>();


	internal Connectoids(NetworkConnectionsManager connectionsManager)
	{
		//IL_00fd: Unknown result type (might be due to invalid IL or missing references)
		//IL_0104: Expected O, but got Unknown
		//IL_01a2: Unknown result type (might be due to invalid IL or missing references)
		//IL_01a9: Expected O, but got Unknown
		this.connectionsManager = connectionsManager;
		IEnumerable<NetworkConnectionFullName> connectionNames = connectionsManager.GetAllConnectionFullNames();
		foreach (NetworkConnectionFullName connectionName in connectionNames)
		{
			if (CONFIG.bDebugSpew)
			{
				FiddlerApplication.DebugSpew("Collecting information for connection '{0}'", connectionName);
			}
			if (ConnectionNamesToInitialProxySettingsMap.ContainsKey(connectionName))
			{
				continue;
			}
			try
			{
				ProxySettings initialProxySettings = connectionsManager.GetCurrentProxySettingsForConnection(connectionName);
				if ((ProxySettings)null == initialProxySettings)
				{
					FiddlerApplication.Log.LogFormat("!WARNING: Failed to get proxy information for Connection '{0}'.", connectionName);
					continue;
				}
				if (!string.IsNullOrEmpty(initialProxySettings.HttpProxyHost) && !CONFIG.bIsViewOnly && $"{initialProxySettings.HttpProxyHost}:{initialProxySettings.HttpProxyPort}".Contains(CONFIG.sFiddlerListenHostPort))
				{
					FiddlerApplication.Log.LogString("When connecting, upstream proxy settings were already pointed at Fiddler. Clearing upstream proxy.");
					initialProxySettings = new ProxySettings();
				}
				if (!string.IsNullOrEmpty(initialProxySettings.ProxyAutoConfigUrl) && (initialProxySettings.ProxyAutoConfigUrl.OICEquals("file://" + CONFIG.GetPath("Pac")) || initialProxySettings.ProxyAutoConfigUrl.OICEquals("file:///" + Utilities.UrlPathEncode(CONFIG.GetPath("Pac").Replace('\\', '/'))) || initialProxySettings.ProxyAutoConfigUrl.OICEquals("http://" + CONFIG.sFiddlerListenHostPort + "/proxy.pac")))
				{
					FiddlerApplication.Log.LogString("When connecting, upstream proxy script was already pointed at Fiddler. Clearing upstream proxy.");
					initialProxySettings = new ProxySettings();
				}
				ConnectionNamesToInitialProxySettingsMap.Add(connectionName, initialProxySettings);
			}
			catch (Exception eX)
			{
				FiddlerApplication.Log.LogFormat("!WARNING: Failed to get proxy information for Connection '{0}' due to {1}", connectionName, FiddlerCore.Utilities.Utilities.DescribeException(eX));
			}
		}
	}

	/// <summary>
	/// Return the configured default connectoid's proxy information.
	/// </summary>
	/// <returns>Either proxy information from "DefaultLAN" or the user-specified connectoid</returns>
	internal virtual ProxySettings GetDefaultConnectionGatewayInfo(string connectionNamespace, string connectionName)
	{
		//IL_001d: Unknown result type (might be due to invalid IL or missing references)
		//IL_0027: Expected O, but got Unknown
		//IL_0073: Unknown result type (might be due to invalid IL or missing references)
		//IL_007d: Expected O, but got Unknown
		//IL_0039: Unknown result type (might be due to invalid IL or missing references)
		//IL_0043: Expected O, but got Unknown
		//IL_0061: Unknown result type (might be due to invalid IL or missing references)
		//IL_0068: Expected O, but got Unknown
		string sConnName = CONFIG.sHookConnectionNamed;
		if (string.IsNullOrEmpty(sConnName))
		{
			sConnName = connectionName;
		}
		if (!ConnectionNamesToInitialProxySettingsMap.ContainsKey(new NetworkConnectionFullName(connectionNamespace, connectionName)))
		{
			sConnName = connectionName;
			if (!ConnectionNamesToInitialProxySettingsMap.ContainsKey(new NetworkConnectionFullName(connectionNamespace, sConnName)))
			{
				FiddlerApplication.Log.LogString($"!WARNING: The {connectionName} Gateway information could not be obtained.");
				return new ProxySettings();
			}
		}
		return ConnectionNamesToInitialProxySettingsMap[new NetworkConnectionFullName(connectionNamespace, sConnName)];
	}

	/// <summary>
	/// Enumerates all of the connectoids and determines if the bIsHooked field is incorrect. If so, correct the value 
	/// and return TRUE to indicate that work was done.
	/// </summary>
	/// <param name="fiddlerProxySettings">The Proxy:Port string to look for (e.g. Config.FiddlerListenHostPort)</param>
	/// <returns>TRUE if any of the connectoids' Hook state was inaccurate.</returns>
	internal virtual bool MarkUnhookedConnections(ProxySettings fiddlerProxySettings)
	{
		if (CONFIG.bIsViewOnly)
		{
			return false;
		}
		bool bAnyMismatch = false;
		foreach (ProxySettings proxySettings in ConnectionNamesToInitialProxySettingsMap.Keys.Where(ShouldBeHooked).Select((Func<NetworkConnectionFullName, ProxySettings>)connectionsManager.GetCurrentProxySettingsForConnection))
		{
			if (proxySettings != fiddlerProxySettings)
			{
				bAnyMismatch = true;
			}
		}
		return bAnyMismatch;
	}

	/// <summary>
	/// Updates all (or CONFIG.sHookConnectionNamed-specified) connectoids to point at the argument-provided proxy information.
	/// </summary>
	/// <param name="proxySettings">The proxy info to set into the Connectoid</param>
	/// <returns>TRUE if updating at least one connectoid was successful</returns>
	internal virtual bool HookConnections(ProxySettings proxySettings)
	{
		if (CONFIG.bIsViewOnly)
		{
			return false;
		}
		bool bResult = false;
		foreach (NetworkConnectionFullName oC in ConnectionNamesToInitialProxySettingsMap.Keys)
		{
			if (ShouldBeHooked(oC))
			{
				connectionsManager.SetProxySettingsForConnections(proxySettings, (NetworkConnectionFullName[])(object)new NetworkConnectionFullName[1] { oC });
				bResult = true;
			}
		}
		return bResult;
	}

	internal bool ShouldBeHooked(NetworkConnectionFullName connectionName)
	{
		return CONFIG.HookAllConnections || (connectionName.Namespace == CONFIG.sHookConnectionNamespace && connectionName.Name == CONFIG.sHookConnectionNamed);
	}

	/// <summary>
	/// Restore original proxy settings for any connectoid we changed.
	/// </summary>
	/// <returns>FALSE if any connectoids failed to unhook</returns>
	internal virtual bool UnhookAllConnections()
	{
		if (CONFIG.bIsViewOnly)
		{
			return true;
		}
		foreach (NetworkConnectionFullName oC in ConnectionNamesToInitialProxySettingsMap.Keys.Where(ShouldBeHooked))
		{
			connectionsManager.SetProxySettingsForConnections(ConnectionNamesToInitialProxySettingsMap[oC], (NetworkConnectionFullName[])(object)new NetworkConnectionFullName[1] { oC });
		}
		return true;
	}
}
