namespace Fiddler;

internal static class COUNTERS
{
	internal static int ASYNC_DNS;

	internal static long TOTAL_ASYNC_DNS;

	internal static long TOTAL_ASYNC_DNS_MS;

	internal static int DNSCACHE_HITS;

	internal static int ASYNC_WAIT_CLIENT_REUSE;

	internal static long TOTAL_ASYNC_WAIT_CLIENT_REUSE;

	internal static long TOTAL_DELAY_ACCEPT_CONNECTION;

	internal static long CONNECTIONS_ACCEPTED;

	public static string Summarize()
	{
		return $"-= Counters =-\nDNS Lookups underway:\t{ASYNC_DNS:N0}\nTotal DNS Async:\t{TOTAL_ASYNC_DNS:N0}\nAsync DNS saved(ms):\t{TOTAL_ASYNC_DNS_MS:N0}\nDNS Cache Hits:\t\t{DNSCACHE_HITS:N0}\n\nAwaiting Client Reuse:\t{ASYNC_WAIT_CLIENT_REUSE:N0}\nTotal Client Reuse:\t{TOTAL_ASYNC_WAIT_CLIENT_REUSE:N0}\n\nConnections Accepted:\t{CONNECTIONS_ACCEPTED:N0}\nAccept delay ms:\t{TOTAL_DELAY_ACCEPT_CONNECTION:N0}\n";
	}
}
