using System.Reflection;
using Telerik.NetworkConnections;

namespace FiddlerCore.Analytics;

internal static class AnalyticsExtensions
{
	public static void TrackMachineInformation(this IAnalytics analytics, string osVersion, string dotNetVersion, string processor)
	{
		if (analytics != null)
		{
			analytics.TrackFeature("MachineInfo", "OS", osVersion);
			analytics.TrackFeature("MachineInfo", "_NET", dotNetVersion);
			analytics.TrackFeature("MachineInfo", "CPU", processor);
		}
	}

	public static void TrackApplicationInformation(this IAnalytics analytics)
	{
		analytics.TrackFeature("TargetFramework", "NETSTANDARD2_1");
		Assembly entryAssembly = Assembly.GetEntryAssembly();
		string applicationName;
		if (entryAssembly == null)
		{
			applicationName = "Unmanaged";
		}
		else
		{
			string entryAssemblyFullName = entryAssembly.FullName;
			AssemblyName entryAssemblyName = new AssemblyName(entryAssemblyFullName);
			applicationName = entryAssemblyName.Name;
		}
		analytics.TrackFeature("ApplicationName", applicationName);
	}

	public static void TrackSystemProxyInfo(this IAnalytics analytics, ProxySettings systemProxySettings)
	{
		if (analytics == null || systemProxySettings == null)
		{
			return;
		}
		if (systemProxySettings.UseWebProxyAutoDiscovery)
		{
			analytics.TrackFeature("SystemProxyInfo", "AutoDetect");
		}
		if (systemProxySettings.ProxyAutoConfigEnabled && systemProxySettings.ProxyAutoConfigUrl != null)
		{
			analytics.TrackFeature("SystemProxyInfo", "UseConfigScript");
		}
		if (systemProxySettings.HttpProxyEnabled && systemProxySettings.HttpsProxyEnabled && systemProxySettings.FtpProxyEnabled && systemProxySettings.SocksProxyEnabled)
		{
			analytics.TrackFeature("SystemProxyInfo", "AllValidProtocolsEnabled");
			return;
		}
		if (systemProxySettings.HttpProxyEnabled)
		{
			analytics.TrackFeature("SystemProxyInfo", "HttpEnabled");
		}
		if (systemProxySettings.HttpsProxyEnabled)
		{
			analytics.TrackFeature("SystemProxyInfo", "HttpsEnabled");
		}
		if (systemProxySettings.FtpProxyEnabled)
		{
			analytics.TrackFeature("SystemProxyInfo", "FtpEnabled");
		}
		if (systemProxySettings.SocksProxyEnabled)
		{
			analytics.TrackFeature("SystemProxyInfo", "SocksEnabled");
		}
	}
}
