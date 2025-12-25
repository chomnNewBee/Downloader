using System;
using System.ComponentModel;
using System.Diagnostics;

namespace FiddlerCore.PlatformExtensions.Unix;

internal static class PortProcessMapperForUnix
{
	private const string lsofCommand = "lsof";

	private const string lsofArgumentsFormat = "-n -o -P -F p -i tcp:{0}{1}";

	private const string tcpListenStateOnly = " -s tcp:LISTEN";

	private static readonly int iProxyPID = Process.GetCurrentProcess().Id;

	internal static bool TryMapLocalPortToProcessId(int iPort, out int processId, out string errorMessage)
	{
		string lsofArguments = $"-n -o -P -F p -i tcp:{iPort}{string.Empty}";
		processId = GetPIDFromLSOF(lsofArguments, out errorMessage);
		if (string.IsNullOrEmpty(errorMessage))
		{
			return true;
		}
		return false;
	}

	internal static bool TryGetListeningProcessOnPort(int port, out string processName, out int processId, out string errorMessage)
	{
		string lsofArguments = string.Format("-n -o -P -F p -i tcp:{0}{1}", port, " -s tcp:LISTEN");
		processId = GetPIDFromLSOF(lsofArguments, out errorMessage);
		if (processId < 1)
		{
			processName = string.Empty;
			if (string.IsNullOrEmpty(errorMessage))
			{
				return true;
			}
			return false;
		}
		try
		{
			processName = Process.GetProcessById(processId).ProcessName.ToLower();
		}
		catch (Exception eX)
		{
			errorMessage = $"Unable to get process name of processId: {processId}\n{eX}";
			processName = string.Empty;
			return false;
		}
		if (string.IsNullOrEmpty(processName))
		{
			processName = "unknown";
		}
		return true;
	}

	private static int GetPIDFromLSOF(string lsofArguments, out string errorMessage)
	{
		int iCandidatePID = 0;
		try
		{
			using (Process oProc = new Process())
			{
				oProc.StartInfo.UseShellExecute = false;
				oProc.StartInfo.RedirectStandardOutput = true;
				oProc.StartInfo.RedirectStandardError = false;
				oProc.StartInfo.CreateNoWindow = true;
				oProc.StartInfo.FileName = "lsof";
				oProc.StartInfo.Arguments = lsofArguments;
				oProc.Start();
				string sLine;
				while ((sLine = oProc.StandardOutput.ReadLine()) != null)
				{
					if (sLine.StartsWith("p", StringComparison.OrdinalIgnoreCase))
					{
						string sProcID = sLine.Substring(1);
						if (int.TryParse(sProcID, out var iPID) && iPID != iProxyPID)
						{
							iCandidatePID = iPID;
						}
					}
				}
				try
				{
					oProc.WaitForExit(1);
				}
				catch
				{
				}
			}
			errorMessage = null;
			return iCandidatePID;
		}
		catch (Win32Exception eXX)
		{
			errorMessage = $"Process-determination failed. lsof returned {eXX.NativeErrorCode}.\n{eXX}";
		}
		catch (Exception eX)
		{
			errorMessage = $"Process-determination failed.\n{eX}";
		}
		return 0;
	}
}
