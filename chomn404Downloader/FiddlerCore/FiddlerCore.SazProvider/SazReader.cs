using System;
using System.Collections.Generic;
using System.IO;
using Fiddler;
using Ionic.Zip;

namespace FiddlerCore.SazProvider;

internal class SazReader : ISAZReader2, ISAZReader
{
	private ZipFile _oZip;

	private string _sPassword;

	private readonly SazProvider provider;

	public string Filename { get; }

	public string Comment => _oZip.Comment;

	public string EncryptionMethod { get; private set; }

	public string EncryptionStrength { get; private set; }

	public GetPasswordDelegate PasswordCallback { get; set; }

	public void Close()
	{
		_oZip.Dispose();
		_oZip = null;
	}

	private bool PromptForPassword(string partName)
	{
		if (PasswordCallback == null)
		{
			throw new ArgumentNullException("GetPasswordDelegate not set. Use the Utilities.ReadSessionArchive(string, string, GetPasswordDelegate) overload.");
		}
		_sPassword = PasswordCallback(Filename, partName);
		if (!string.IsNullOrEmpty(_sPassword))
		{
			_oZip.Password = _sPassword;
			return true;
		}
		return false;
	}

	public Stream GetFileStream(string sFilename)
	{
		//IL_003a: Unknown result type (might be due to invalid IL or missing references)
		ZipEntry oZE = _oZip[sFilename];
		if (oZE == null)
		{
			return null;
		}
		if (oZE.UsesEncryption && string.IsNullOrEmpty(_sPassword))
		{
			StoreEncryptionInfo(oZE.Encryption);
			if (!PromptForPassword(sFilename))
			{
				throw new OperationCanceledException("Password required.");
			}
		}
		Stream strmResult = null;
		while (true)
		{
			try
			{
				strmResult = (Stream)(object)oZE.OpenReader();
			}
			catch (BadPasswordException)
			{
				if (!PromptForPassword(sFilename))
				{
					throw new OperationCanceledException("Password required.");
				}
				continue;
			}
			catch (Exception)
			{
			}
			break;
		}
		return strmResult;
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
			EncryptionMethod = "PKZip";
			EncryptionStrength = "56";
			break;
		case EncryptionAlgorithm.PkzipWeak :
			EncryptionMethod = "WinZipAes";
			EncryptionStrength = "128";
			break;
		case EncryptionAlgorithm.WinZipAes128:
			EncryptionMethod = "WinZipAes";
			EncryptionStrength = "256";
			break;
		default:
			EncryptionMethod = "Unknown";
			EncryptionStrength = "0";
			break;
		}
	}

	public byte[] GetFileBytes(string sFilename)
	{
		Stream strmBytes = GetFileStream(sFilename);
		if (strmBytes == null)
		{
			return null;
		}
		byte[] arrData = Fiddler.Utilities.ReadEntireStream(strmBytes);
		strmBytes.Close();
		return arrData;
	}

	public string[] GetRequestFileList()
	{
		List<string> listFiles = new List<string>();
		foreach (ZipEntry oZE in _oZip)
		{
			if (oZE.FileName.EndsWith("_c.txt", StringComparison.OrdinalIgnoreCase) && oZE.FileName.StartsWith("raw/", StringComparison.OrdinalIgnoreCase))
			{
				listFiles.Add(oZE.FileName);
			}
		}
		return listFiles.ToArray();
	}

	internal SazReader(SazProvider provider, string sFilename)
	{
		//IL_0018: Unknown result type (might be due to invalid IL or missing references)
		//IL_0022: Expected O, but got Unknown
		this.provider = provider;
		Filename = sFilename;
		_oZip = new ZipFile(sFilename);
		foreach (string s in _oZip.EntryFileNames)
		{
		}
	}
}
