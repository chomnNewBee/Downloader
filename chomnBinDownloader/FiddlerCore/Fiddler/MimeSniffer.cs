using System.Collections.Generic;
using System.Linq;

namespace Fiddler;

internal class MimeSniffer
{
	private static MimeSniffer instance;

	private List<FileSignatureData> signatures;

	public static MimeSniffer Instance
	{
		get
		{
			if (instance == null)
			{
				instance = new MimeSniffer();
			}
			return instance;
		}
	}

	private MimeSniffer()
	{
		InitializeSignatures();
	}

	public bool TrySniff(byte[] responseBodyBytes, out string sniffedExtension)
	{
		sniffedExtension = null;
		if (Utilities.IsNullOrEmpty(responseBodyBytes))
		{
			return false;
		}
		foreach (FileSignatureData signature in signatures)
		{
			if (Utilities.HasMagicBytes(responseBodyBytes, signature.Offset, signature.MagicBytes))
			{
				sniffedExtension = signature.Extension;
				return true;
			}
		}
		return false;
	}

	private void InitializeSignatures()
	{
		List<FileSignatureData> list = new List<FileSignatureData>();
		list.Add(new FileSignatureData(new byte[2] { 80, 75 }, ".zip"));
		list.Add(new FileSignatureData(new byte[2] { 77, 90 }, ".exe"));
		list.Add(new FileSignatureData(new byte[2] { 55, 122 }, ".7z"));
		list.Add(new FileSignatureData(new byte[4] { 82, 97, 114, 33 }, ".rar"));
		list.Add(new FileSignatureData(new byte[5] { 37, 80, 68, 70, 45 }, ".pdf"));
		list.Add(new FileSignatureData(new byte[2] { 66, 77 }, ".bmp"));
		List<FileSignatureData> unsortedSignatures = list;
		signatures = unsortedSignatures.OrderByDescending((FileSignatureData s) => s.MagicBytes.Length).ToList();
	}
}
