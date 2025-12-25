namespace Fiddler;

/// <summary>
/// The MockTunnel represents a CONNECT tunnel which was reloaded from a SAZ file.
/// </summary>
internal class MockTunnel : ITunnel
{
	private long _lngBytesEgress = 0L;

	private long _lngBytesIngress = 0L;

	public long IngressByteCount => _lngBytesIngress;

	public long EgressByteCount => _lngBytesEgress;

	public bool IsOpen => false;

	public MockTunnel(long lngEgress, long lngIngress)
	{
		_lngBytesEgress = lngEgress;
		_lngBytesIngress = lngIngress;
	}

	public void CloseTunnel()
	{
	}
}
