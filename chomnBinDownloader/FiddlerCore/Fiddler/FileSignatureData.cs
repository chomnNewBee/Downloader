namespace Fiddler;

internal class FileSignatureData
{
	public byte[] MagicBytes { get; private set; }

	public int Offset { get; private set; }

	public string Extension { get; private set; }

	public FileSignatureData(byte[] magicBytes, int offset, string extension)
	{
		MagicBytes = magicBytes;
		Offset = offset;
		Extension = extension;
	}

	public FileSignatureData(byte[] magicBytes, string extension)
		: this(magicBytes, 0, extension)
	{
	}
}
