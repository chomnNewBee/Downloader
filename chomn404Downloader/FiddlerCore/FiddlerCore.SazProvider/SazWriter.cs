using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;
using Fiddler;
using Ionic.Zip;

namespace FiddlerCore.SazProvider;

internal class SazWriter : ISAZWriter
{
	[Serializable]
	[CompilerGenerated]
	private sealed class _003C_003Ec
	{
		public static readonly _003C_003Ec _003C_003E9 = new _003C_003Ec();

		public static WriteDelegate _003C_003E9__11_0;

		internal void _003CWriteODCXML_003Eb__11_0(string sn, Stream strmToWrite)
		{
			byte[] arrODCXML = Encoding.UTF8.GetBytes("<?xml version=\"1.0\" encoding=\"utf-8\" ?>\r\n<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\r\n<Default Extension=\"htm\" ContentType=\"text/html\" />\r\n<Default Extension=\"xml\" ContentType=\"application/xml\" />\r\n<Default Extension=\"txt\" ContentType=\"text/plain\" />\r\n</Types>");
			strmToWrite.Write(arrODCXML, 0, arrODCXML.Length);
		}
	}

	private ZipFile _oZip;

	private string _EncryptionMethod;

	private string _EncryptionStrength;

	private readonly SazProvider provider;

	public string EncryptionMethod
	{
		get
		{
			//IL_0017: Unknown result type (might be due to invalid IL or missing references)
			if (string.IsNullOrEmpty(_EncryptionMethod))
			{
				StoreEncryptionInfo(_oZip.Encryption);
			}
			return _EncryptionMethod;
		}
	}

	public string EncryptionStrength
	{
		get
		{
			//IL_0017: Unknown result type (might be due to invalid IL or missing references)
			if (string.IsNullOrEmpty(_EncryptionStrength))
			{
				StoreEncryptionInfo(_oZip.Encryption);
			}
			return _EncryptionStrength;
		}
	}

	public string Filename { get; }

	public string Comment
	{
		get
		{
			return _oZip.Comment;
		}
		set
		{
			_oZip.Comment = value;
		}
	}

	internal SazWriter(SazProvider provider, string sFilename)
	{
		//IL_0018: Unknown result type (might be due to invalid IL or missing references)
		//IL_0022: Expected O, but got Unknown
		this.provider = provider;
		Filename = sFilename;
		_oZip = new ZipFile(sFilename);
		_oZip.UseZip64WhenSaving = (Zip64Option)1;
		_oZip.AddDirectoryByName("raw");
	}

	private void StoreEncryptionInfo(EncryptionAlgorithm oEA)
	{
		//IL_0001: Unknown result type (might be due to invalid IL or missing references)
		//IL_0002: Unknown result type (might be due to invalid IL or missing references)
		//IL_0003: Unknown result type (might be due to invalid IL or missing references)
		//IL_0004: Unknown result type (might be due to invalid IL or missing references)
		//IL_0005: Unknown result type (might be due to invalid IL or missing references)
		//IL_0007: Unknown result type (might be due to invalid IL or missing references)
		//IL_0019: Expected I4, but got Unknown
		switch (oEA - 1)
		{
		case 0:
			_EncryptionMethod = "PKZip";
			_EncryptionStrength = "56";
			break;
		case EncryptionAlgorithm.PkzipWeak :
			_EncryptionMethod = "WinZipAes";
			_EncryptionStrength = "128";
			break;
		case EncryptionAlgorithm.WinZipAes128:
			_EncryptionMethod = "WinZipAes";
			_EncryptionStrength = "256";
			break;
		default:
			_EncryptionMethod = "Unknown";
			_EncryptionStrength = "0";
			break;
		}
	}

	public void AddFile(string sFilename, SAZWriterDelegate oSWD)
	{
		//IL_0015: Unknown result type (might be due to invalid IL or missing references)
		//IL_001b: Expected O, but got Unknown
		WriteDelegate oWD = (WriteDelegate)delegate(string sFN, Stream oS)
		{
			oSWD(oS);
		};
		_oZip.AddEntry(sFilename, oWD);
	}

	/// <summary>
	/// Writes the ContentTypes XML to the ZIP so Packaging APIs can read it.
	/// See http://en.wikipedia.org/wiki/Open_Packaging_Conventions
	/// </summary>
	/// <param name="odfZip"></param>
	private void WriteODCXML()
	{
		//IL_0020: Unknown result type (might be due to invalid IL or missing references)
		//IL_0025: Unknown result type (might be due to invalid IL or missing references)
		//IL_002b: Expected O, but got Unknown
		ZipFile oZip = _oZip;
		object obj = _003C_003Ec._003C_003E9__11_0;
		if (obj == null)
		{
			WriteDelegate val = delegate(string sn, Stream strmToWrite)
			{
				byte[] bytes = Encoding.UTF8.GetBytes("<?xml version=\"1.0\" encoding=\"utf-8\" ?>\r\n<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\r\n<Default Extension=\"htm\" ContentType=\"text/html\" />\r\n<Default Extension=\"xml\" ContentType=\"application/xml\" />\r\n<Default Extension=\"txt\" ContentType=\"text/plain\" />\r\n</Types>");
				strmToWrite.Write(bytes, 0, bytes.Length);
			};
			_003C_003Ec._003C_003E9__11_0 = val;
			obj = (object)val;
		}
		oZip.AddEntry("[Content_Types].xml", (WriteDelegate)obj);
	}

	public bool CompleteArchive()
	{
		WriteODCXML();
		_oZip.Save();
		_oZip = null;
		return true;
	}

	public bool SetPassword(string sPassword)
	{
		if (!string.IsNullOrEmpty(sPassword))
		{
			if (CONFIG.bUseAESForSAZ)
			{
				if (FiddlerApplication.Prefs.GetBoolPref("fiddler.saz.AES.Use256Bit", bDefault: false))
				{
					_oZip.Encryption = (EncryptionAlgorithm)3;
				}
				else
				{
					_oZip.Encryption = (EncryptionAlgorithm)2;
				}
			}
			_oZip.Password = sPassword;
		}
		return true;
	}
}
