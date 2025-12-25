using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;

namespace Analytics;

internal class UniqueClientIdGenerator
{
	public static string Generate()
	{
		try
		{
			string mac = GetFirstMachineMac();
			if (mac == null)
			{
				return "no-mac";
			}
			string machineName = Environment.MachineName;
			if (string.IsNullOrWhiteSpace(machineName))
			{
				return "no-machine-name";
			}
			byte[] bytes = Encoding.UTF8.GetBytes(machineName + mac);
			byte[] hash = SHA256.Create().ComputeHash(bytes);
			return BitConverter.ToString(hash).Replace("-", string.Empty);
		}
		catch (Exception)
		{
			return "exception";
		}
	}

	private static string GetFirstMachineMac()
	{
		NetworkInterface[] networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();
		IEnumerable<string> macs = networkInterfaces.Select((NetworkInterface nic) => nic.GetPhysicalAddress().ToString().ToUpperInvariant());
		IEnumerable<string> filteredMacs = macs.Where((string m) => m.Length == 12);
		IEnumerable<string> sortedMacs = filteredMacs.OrderBy((string x) => x);
		return sortedMacs.FirstOrDefault();
	}
}
