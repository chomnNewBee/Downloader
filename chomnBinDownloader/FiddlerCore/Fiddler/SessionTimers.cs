using System;
using System.Collections.Generic;
using System.Text;
using FiddlerCore.PlatformExtensions;
using FiddlerCore.PlatformExtensions.API;

namespace Fiddler;

/// <summary>
/// A SessionTimers object holds timing information about a single Session.
/// </summary>
public class SessionTimers
{
	public class NetTimestamps
	{
		public struct NetTimestamp
		{
			public readonly long tsRead;

			public readonly int cbRead;

			public NetTimestamp(long tsReadMS, int count)
			{
				tsRead = tsReadMS;
				cbRead = count;
			}
		}

		private List<NetTimestamp> listTimeAndSize = new List<NetTimestamp>();

		public int Count => listTimeAndSize.Count;

		/// <summary>
		/// Log a Read's size and timestamp
		/// </summary>
		/// <param name="tsRead">Number of milliseconds since first calling .Read()</param>
		/// <param name="bytesRead">Number of bytes returned in this read</param>
		public void AddRead(long tsRead, int bytesRead)
		{
			listTimeAndSize.Add(new NetTimestamp(tsRead, bytesRead));
		}

		public NetTimestamp[] ToArray()
		{
			return listTimeAndSize.ToArray();
		}

		/// <summary>
		/// Return the ReadTimings as an array. Only one read is counted per millisecond
		/// </summary>
		/// <returns></returns>
		public NetTimestamp[] ToFoldedArray(int iMSFold)
		{
			List<NetTimestamp> listFolded = new List<NetTimestamp>();
			foreach (NetTimestamp NTS in listTimeAndSize)
			{
				if (listFolded.Count < 1 || listFolded[listFolded.Count - 1].tsRead + iMSFold < NTS.tsRead)
				{
					listFolded.Add(NTS);
				}
				int cbTotal = listFolded[listFolded.Count - 1].cbRead;
				cbTotal += NTS.cbRead;
				listFolded.RemoveAt(listFolded.Count - 1);
				listFolded.Add(new NetTimestamp(NTS.tsRead, cbTotal));
			}
			return listFolded.ToArray();
		}

		public override string ToString()
		{
			StringBuilder sbResult = new StringBuilder();
			sbResult.AppendFormat("There were {0} reads.\n<table>", listTimeAndSize.Count);
			foreach (NetTimestamp oNTS in listTimeAndSize)
			{
				sbResult.AppendFormat("<tr><td>{0}<td>{1:N0}</td><tr>\n", oNTS.tsRead, oNTS.cbRead);
			}
			sbResult.AppendFormat("</table>");
			return sbResult.ToString();
		}

		/// <summary>
		/// Create a new List and append to it
		/// </summary>
		/// <param name="oExistingTS"></param>
		/// <returns></returns>
		internal static NetTimestamps FromCopy(NetTimestamps oExistingTS)
		{
			NetTimestamps ntsResult = new NetTimestamps();
			if (oExistingTS != null)
			{
				ntsResult.listTimeAndSize.AddRange(oExistingTS.listTimeAndSize);
			}
			return ntsResult;
		}
	}

	private NetTimestamps tsClientReads;

	private NetTimestamps tsServerReads;

	/// <summary>
	/// The time at which the client's HTTP connection to Fiddler was established
	/// </summary>
	public DateTime ClientConnected;

	/// <summary>
	/// The time at which the request's first Send() to Fiddler completes
	/// </summary>
	public DateTime ClientBeginRequest;

	/// <summary>
	/// The time at which the request headers were received
	/// </summary>
	public DateTime FiddlerGotRequestHeaders;

	/// <summary>
	/// The time at which the request to Fiddler completes (aka RequestLastWrite)
	/// </summary>
	public DateTime ClientDoneRequest;

	/// <summary>
	/// The time at which the server connection has been established
	/// </summary>
	public DateTime ServerConnected;

	/// <summary>
	/// The time at which Fiddler begins sending the HTTP request to the server (FiddlerRequestFirstSend)
	/// </summary>
	public DateTime FiddlerBeginRequest;

	/// <summary>
	/// The time at which Fiddler has completed sending the HTTP request to the server (FiddlerRequestLastSend).
	/// BUG: Should be named "FiddlerEndRequest". 
	/// NOTE: Value here is often misleading due to buffering inside WinSock's send() call.
	/// </summary>
	public DateTime ServerGotRequest;

	/// <summary>
	/// The time at which Fiddler receives the first byte of the server's response (ServerResponseFirstRead)
	/// </summary>
	public DateTime ServerBeginResponse;

	/// <summary>
	/// The time at which Fiddler received the server's headers
	/// </summary>
	public DateTime FiddlerGotResponseHeaders;

	/// <summary>
	/// The time at which Fiddler has completed receipt of the server's response (ServerResponseLastRead)
	/// </summary>
	public DateTime ServerDoneResponse;

	/// <summary>
	/// The time at which Fiddler has begun sending the Response to the client (ClientResponseFirstSend)
	/// </summary>
	public DateTime ClientBeginResponse;

	/// <summary>
	/// The time at which Fiddler has completed sending the Response to the client (ClientResponseLastSend)
	/// </summary>
	public DateTime ClientDoneResponse;

	/// <summary>
	/// The number of milliseconds spent determining which gateway should be used to handle this request
	/// (Should be mutually exclusive to DNSTime!=0)
	/// </summary>
	public int GatewayDeterminationTime;

	/// <summary>
	/// The number of milliseconds spent waiting for DNS
	/// </summary>
	public int DNSTime;

	/// <summary>
	/// The number of milliseconds spent waiting for the server TCP/IP connection establishment
	/// </summary>
	public int TCPConnectTime;

	/// <summary>
	/// The number of milliseconds elapsed while performing the HTTPS handshake with the server
	/// </summary>
	public int HTTPSHandshakeTime;

	private static readonly IPlatformExtensions platformExtensions = PlatformExtensionsFactory.Instance.CreatePlatformExtensions();

	public NetTimestamps ClientReads
	{
		get
		{
			if (tsClientReads == null)
			{
				tsClientReads = new NetTimestamps();
			}
			return tsClientReads;
		}
		internal set
		{
			tsClientReads = value;
		}
	}

	public NetTimestamps ServerReads
	{
		get
		{
			if (tsServerReads == null)
			{
				tsServerReads = new NetTimestamps();
			}
			return tsServerReads;
		}
		internal set
		{
			tsServerReads = value;
		}
	}

	/// <summary>
	/// Enables High-Resolution timers, which are bad for battery-life but good for the accuracy of timestamps.
	/// See http://technet.microsoft.com/en-us/sysinternals/bb897568 for the ClockRes utility that shows current clock resolution.
	/// NB: Exiting Fiddler reverts this to the default value.
	/// </summary>
	public static bool EnableHighResolutionTimers
	{
		get
		{
			return platformExtensions.HighResolutionTimersEnabled;
		}
		set
		{
			if (!platformExtensions.TryChangeTimersResolution(value))
			{
				FiddlerApplication.Log.LogString("Changing time resolution failed.");
			}
		}
	}

	internal SessionTimers Clone()
	{
		return (SessionTimers)MemberwiseClone();
	}

	/// <summary>
	/// Override of ToString shows timer info in a fancy format
	/// </summary>
	/// <returns>Timing information as a string</returns>
	public override string ToString()
	{
		return ToString(bMultiLine: false);
	}

	/// <summary>
	/// Override of ToString shows timer info in a fancy format
	/// </summary>
	/// <param name="bMultiLine">TRUE if the result can contain linebreaks; false if comma-delimited format preferred</param>
	/// <returns>Timing information as a string</returns>
	public string ToString(bool bMultiLine)
	{
		if (bMultiLine)
		{
			return $"ClientConnected:\t{ClientConnected:HH:mm:ss.fff}\r\nClientBeginRequest:\t{ClientBeginRequest:HH:mm:ss.fff}\r\nGotRequestHeaders:\t{FiddlerGotRequestHeaders:HH:mm:ss.fff}\r\nClientDoneRequest:\t{ClientDoneRequest:HH:mm:ss.fff}\r\nDetermine Gateway:\t{GatewayDeterminationTime}ms\r\nDNS Lookup: \t\t{DNSTime}ms\r\nTCP/IP Connect:\t{TCPConnectTime}ms\r\nHTTPS Handshake:\t{HTTPSHandshakeTime}ms\r\nServerConnected:\t{ServerConnected:HH:mm:ss.fff}\r\nFiddlerBeginRequest:\t{FiddlerBeginRequest:HH:mm:ss.fff}\r\nServerGotRequest:\t{ServerGotRequest:HH:mm:ss.fff}\r\nServerBeginResponse:\t{ServerBeginResponse:HH:mm:ss.fff}\r\nGotResponseHeaders:\t{FiddlerGotResponseHeaders:HH:mm:ss.fff}\r\nServerDoneResponse:\t{ServerDoneResponse:HH:mm:ss.fff}\r\nClientBeginResponse:\t{ClientBeginResponse:HH:mm:ss.fff}\r\nClientDoneResponse:\t{ClientDoneResponse:HH:mm:ss.fff}\r\n\r\n{((TimeSpan.Zero < ClientDoneResponse - ClientBeginRequest) ? $"\tOverall Elapsed:\t{ClientDoneResponse - ClientBeginRequest:h\\:mm\\:ss\\.fff}\r\n" : string.Empty)}";
		}
		return $"ClientConnected: {ClientConnected:HH:mm:ss.fff}, ClientBeginRequest: {ClientBeginRequest:HH:mm:ss.fff}, GotRequestHeaders: {FiddlerGotRequestHeaders:HH:mm:ss.fff}, ClientDoneRequest: {ClientDoneRequest:HH:mm:ss.fff}, Determine Gateway: {GatewayDeterminationTime}ms, DNS Lookup: {DNSTime}ms, TCP/IP Connect: {TCPConnectTime}ms, HTTPS Handshake: {HTTPSHandshakeTime}ms, ServerConnected: {ServerConnected:HH:mm:ss.fff},FiddlerBeginRequest: {FiddlerBeginRequest:HH:mm:ss.fff}, ServerGotRequest: {ServerGotRequest:HH:mm:ss.fff}, ServerBeginResponse: {ServerBeginResponse:HH:mm:ss.fff}, GotResponseHeaders: {FiddlerGotResponseHeaders:HH:mm:ss.fff}, ServerDoneResponse: {ServerDoneResponse:HH:mm:ss.fff}, ClientBeginResponse: {ClientBeginResponse:HH:mm:ss.fff}, ClientDoneResponse: {ClientDoneResponse:HH:mm:ss.fff}{((TimeSpan.Zero < ClientDoneResponse - ClientBeginRequest) ? $", Overall Elapsed: {ClientDoneResponse - ClientBeginRequest:h\\:mm\\:ss\\.fff}" : string.Empty)}";
	}
}
