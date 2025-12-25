using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace FiddlerCore.PlatformExtensions.Windows;

internal static class PortProcessMapperForWindows
{
	/// <summary>
	/// Enumeration of possible queries that can be issued using GetExtendedTcpTable
	/// http://msdn2.microsoft.com/en-us/library/aa366386.aspx
	/// </summary>
	private enum TcpTableType
	{
		BasicListener,
		BasicConnections,
		BasicAll,
		/// <summary>
		/// Processes listening on Ports
		/// </summary>
		OwnerPidListener,
		/// <summary>
		/// Processes with active TCP/IP connections
		/// </summary>
		OwnerPidConnections,
		OwnerPidAll,
		OwnerModuleListener,
		OwnerModuleConnections,
		OwnerModuleAll
	}

	private const int AF_INET = 2;

	private const int AF_INET6 = 23;

	private const int ERROR_INSUFFICIENT_BUFFER = 122;

	private const int NO_ERROR = 0;

	internal static bool TryMapLocalPortToProcessId(int iPort, bool bEnableIPv6, out int processId, out string errorMessage)
	{
		processId = FindPIDForPort(iPort, bEnableIPv6, out errorMessage);
		if (string.IsNullOrEmpty(errorMessage))
		{
			return true;
		}
		return false;
	}

	internal static bool TryGetListeningProcess(int iPort, out string processName, out int processId, out string errorMessage)
	{
		int iPID = 0;
		try
		{
			iPID = FindPIDForConnection(iPort, 2u, TcpTableType.OwnerPidListener, out errorMessage);
			if (iPID < 1)
			{
				iPID = FindPIDForConnection(iPort, 23u, TcpTableType.OwnerPidListener, out errorMessage);
			}
			processId = iPID;
			if (iPID < 1)
			{
				processName = string.Empty;
				if (string.IsNullOrEmpty(errorMessage))
				{
					return true;
				}
				return false;
			}
			processName = Process.GetProcessById(iPID).ProcessName.ToLower();
			if (string.IsNullOrEmpty(processName))
			{
				processName = "unknown";
			}
			return true;
		}
		catch (Exception eX)
		{
			processName = string.Empty;
			processId = 0;
			errorMessage = "Unable to call IPHelperAPI function" + eX.Message;
			return false;
		}
	}

	/// <summary>
	/// Given a local port number, uses GetExtendedTcpTable to find the originating process ID. 
	/// First checks the IPv4 connections, then looks at IPv6 connections.
	/// </summary>
	/// <param name="iTargetPort">Client applications' port</param>
	/// <returns>ProcessID, or 0 if not found</returns>
	private static int FindPIDForPort(int iTargetPort, bool bEnableIPv6, out string errorMessage)
	{
		int iPID = 0;
		try
		{
			iPID = FindPIDForConnection(iTargetPort, 2u, TcpTableType.OwnerPidConnections, out errorMessage);
			if (iPID > 0 || !bEnableIPv6)
			{
				return iPID;
			}
			return FindPIDForConnection(iTargetPort, 23u, TcpTableType.OwnerPidConnections, out errorMessage);
		}
		catch (Exception eX)
		{
			errorMessage = $"Fiddler.Network.TCPTable> Unable to call IPHelperAPI function: {eX.Message}";
		}
		return 0;
	}

	/// <summary>
	/// Calls the GetExtendedTcpTable function to map a port to a process ID.
	/// This function is (over) optimized for performance.
	/// </summary>
	/// <param name="iTargetPort">Client port</param>
	/// <param name="iAddressType">AF_INET or AF_INET6</param>
	/// <returns>PID, if found, or 0</returns>
	private static int FindPIDForConnection(int iTargetPort, uint iAddressType, TcpTableType whichTable, out string errorMessage)
	{
		IntPtr ptrTcpTable = IntPtr.Zero;
		uint cbBufferSize = 32768u;
		try
		{
			ptrTcpTable = Marshal.AllocHGlobal(32768);
			uint dwResult = GetExtendedTcpTable(ptrTcpTable, ref cbBufferSize, sort: false, iAddressType, whichTable, 0u);
			while (122 == dwResult)
			{
				Marshal.FreeHGlobal(ptrTcpTable);
				cbBufferSize += 2048;
				ptrTcpTable = Marshal.AllocHGlobal((int)cbBufferSize);
				dwResult = GetExtendedTcpTable(ptrTcpTable, ref cbBufferSize, sort: false, iAddressType, whichTable, 0u);
			}
			if (dwResult != 0)
			{
				errorMessage = $"!GetExtendedTcpTable() returned error #0x{dwResult:x} when looking for port {iTargetPort}";
				return 0;
			}
			int iOffsetToFirstPort;
			int iOffsetToPIDInRow;
			int iTableRowSize;
			if (iAddressType == 2)
			{
				iOffsetToFirstPort = 12;
				iOffsetToPIDInRow = 12;
				iTableRowSize = 24;
			}
			else
			{
				iOffsetToFirstPort = 24;
				iOffsetToPIDInRow = 32;
				iTableRowSize = 56;
			}
			int iTargetPortInNetOrder = ((iTargetPort & 0xFF) << 8) + ((iTargetPort & 0xFF00) >> 8);
			int iRowCount = Marshal.ReadInt32(ptrTcpTable);
			if (iRowCount == 0)
			{
				errorMessage = null;
				return 0;
			}
			IntPtr ptrRow = (IntPtr)((long)ptrTcpTable + iOffsetToFirstPort);
			for (int i = 0; i < iRowCount; i++)
			{
				if (iTargetPortInNetOrder == Marshal.ReadInt32(ptrRow))
				{
					errorMessage = null;
					return Marshal.ReadInt32(ptrRow, iOffsetToPIDInRow);
				}
				ptrRow = (IntPtr)((long)ptrRow + iTableRowSize);
			}
		}
		finally
		{
			Marshal.FreeHGlobal(ptrTcpTable);
		}
		errorMessage = null;
		return 0;
	}

	[DllImport("iphlpapi.dll", ExactSpelling = true, SetLastError = true)]
	private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref uint dwTcpTableLength, [MarshalAs(UnmanagedType.Bool)] bool sort, uint ipVersion, TcpTableType tcpTableType, uint reserved);
}
