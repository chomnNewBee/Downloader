using Fiddler;

namespace FiddlerCore.SazProvider;

internal class SazProvider : ISAZProvider
{
	public bool BufferLocally => false;

	public bool SupportsEncryption => true;

	public ISAZWriter CreateSAZ(string sFilename)
	{
		return new SazWriter(this, sFilename);
	}

	public ISAZReader LoadSAZ(string sFilename)
	{
		return new SazReader(this, sFilename);
	}
}
