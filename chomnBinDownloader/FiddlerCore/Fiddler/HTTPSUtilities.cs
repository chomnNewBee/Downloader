using System;
using System.Collections.Generic;
using System.Text;

namespace Fiddler;

/// <summary>
/// Utility functions common to parsing both ClientHello and ServerHello messages
/// </summary>
internal class HTTPSUtilities
{
	/// <summary>
	/// Gets a textual string from a TLS extension
	/// </summary>
	internal static string GetExtensionString(byte[] arrData)
	{
		List<string> sItems = new List<string>();
		int iProtStrLen;
		for (int iPtr = 0; iPtr < arrData.Length; iPtr += 1 + iProtStrLen)
		{
			iProtStrLen = arrData[iPtr];
			sItems.Add(Encoding.ASCII.GetString(arrData, iPtr + 1, iProtStrLen));
		}
		return string.Join(", ", sItems.ToArray());
	}

	/// <summary>
	/// Builds a string from an ALPN List of strings
	/// </summary>
	internal static string GetProtocolListAsString(byte[] arrData)
	{
		int iSize = (arrData[0] << 8) + arrData[1];
		byte[] arrList = new byte[iSize];
		Buffer.BlockCopy(arrData, 2, arrList, 0, arrList.Length);
		return GetExtensionString(arrList);
	}

	/// <summary>
	/// List Sig/Hash pairs from  RFC5246 and TLS/1.3 spec
	/// </summary>
	/// <param name="arrData"></param>
	/// <returns></returns>
	internal static string GetSignatureAndHashAlgsAsString(byte[] arrData)
	{
		int iSize = (arrData[0] << 8) + arrData[1];
		StringBuilder sbPairs = new StringBuilder();
		for (int ix = 2; ix < iSize + 2; ix += 2)
		{
			switch ((arrData[ix] << 8) + arrData[ix + 1])
			{
			case 1025:
				sbPairs.Append("rsa_pkcs1_sha256");
				break;
			case 1281:
				sbPairs.Append("rsa_pkcs1_sha384");
				break;
			case 1537:
				sbPairs.Append("rsa_pkcs1_sha512");
				break;
			case 1027:
				sbPairs.Append("ecdsa_secp256r1_sha256");
				break;
			case 1283:
				sbPairs.Append("ecdsa_secp384r1_sha384");
				break;
			case 1539:
				sbPairs.Append("ecdsa_secp521r1_sha512");
				break;
			case 2052:
				sbPairs.Append("rsa_pss_rsae_sha256");
				break;
			case 2053:
				sbPairs.Append("rsa_pss_rsae_sha384");
				break;
			case 2054:
				sbPairs.Append("rsa_pss_rsae_sha512");
				break;
			case 2055:
				sbPairs.Append("ed25519");
				break;
			case 2056:
				sbPairs.Append("ed448");
				break;
			case 2057:
				sbPairs.Append("rsa_pss_pss_sha256");
				break;
			case 2058:
				sbPairs.Append("rsa_pss_pss_sha384");
				break;
			case 2059:
				sbPairs.Append("rsa_pss_pss_sha512");
				break;
			case 513:
				sbPairs.Append("rsa_pkcs1_sha1");
				break;
			case 515:
				sbPairs.Append("ecdsa_sha1");
				break;
			default:
				switch (arrData[ix + 1])
				{
				case 0:
					sbPairs.Append("NoSig");
					break;
				case 1:
					sbPairs.Append("rsa");
					break;
				case 2:
					sbPairs.Append("dsa");
					break;
				case 3:
					sbPairs.Append("ecdsa");
					break;
				default:
					sbPairs.AppendFormat("Unknown[0x{0:x}]", arrData[ix + 1]);
					break;
				}
				sbPairs.AppendFormat("_");
				switch (arrData[ix])
				{
				case 0:
					sbPairs.Append("NoHash");
					break;
				case 1:
					sbPairs.Append("md4");
					break;
				case 2:
					sbPairs.Append("sha1");
					break;
				case 3:
					sbPairs.Append("sha224");
					break;
				case 4:
					sbPairs.Append("sha256");
					break;
				case 5:
					sbPairs.Append("sha384");
					break;
				case 6:
					sbPairs.Append("sha512");
					break;
				default:
					sbPairs.AppendFormat("Unknown[0x{0:x}]", arrData[ix]);
					break;
				}
				break;
			}
			sbPairs.AppendFormat(", ");
		}
		if (sbPairs.Length > 1)
		{
			sbPairs.Length -= 2;
		}
		return sbPairs.ToString();
	}

	/// <summary>
	/// Describes a block of padding, with a friendly summary if all bytes are 0s
	/// https://www.ietf.org/archive/id/draft-agl-tls-padding-03.txt
	/// </summary>
	internal static string DescribePadding(byte[] arrPadding)
	{
		for (int ix = 0; ix < arrPadding.Length; ix++)
		{
			if (arrPadding[ix] != 0)
			{
				return Utilities.ByteArrayToString(arrPadding);
			}
		}
		return arrPadding.Length.ToString("N0") + " null bytes";
	}

	/// <summary>
	/// List defined Supported Groups &amp; ECC Curves from RFC4492
	/// </summary>
	/// <returns></returns>
	internal static string GetSupportedGroupsAsString(byte[] arrGroupData)
	{
		List<string> listECCs = new List<string>();
		if (arrGroupData.Length < 2)
		{
			return string.Empty;
		}
		int iSize = (arrGroupData[0] << 8) + arrGroupData[1];
		for (int iX = 2; iX < arrGroupData.Length - 1; iX += 2)
		{
			ushort uShort = (ushort)((arrGroupData[iX] << 8) | arrGroupData[iX + 1]);
			switch (uShort)
			{
			case 1:
				listECCs.Add("sect163k1 [0x1]");
				break;
			case 2:
				listECCs.Add("sect163r1 [0x2]");
				break;
			case 3:
				listECCs.Add("sect163r2 [0x3]");
				break;
			case 4:
				listECCs.Add("sect193r1 [0x4]");
				break;
			case 5:
				listECCs.Add("sect193r2 [0x5]");
				break;
			case 6:
				listECCs.Add("sect233k1 [0x6]");
				break;
			case 7:
				listECCs.Add("sect233r1 [0x7]");
				break;
			case 8:
				listECCs.Add("sect239k1 [0x8]");
				break;
			case 9:
				listECCs.Add("sect283k1 [0x9]");
				break;
			case 10:
				listECCs.Add("sect283r1 [0xa]");
				break;
			case 11:
				listECCs.Add("sect409k1 [0xb]");
				break;
			case 12:
				listECCs.Add("sect409r1 [0xc]");
				break;
			case 13:
				listECCs.Add("sect571k1 [0xd]");
				break;
			case 14:
				listECCs.Add("sect571r1 [0xe]");
				break;
			case 15:
				listECCs.Add("secp160k1 [0xf]");
				break;
			case 16:
				listECCs.Add("secp160r1 [0x10]");
				break;
			case 17:
				listECCs.Add("secp160r2 [0x11]");
				break;
			case 18:
				listECCs.Add("secp192k1 [0x12]");
				break;
			case 19:
				listECCs.Add("secp192r1 [0x13]");
				break;
			case 20:
				listECCs.Add("secp224k1 [0x14]");
				break;
			case 21:
				listECCs.Add("secp224r1 [0x15]");
				break;
			case 22:
				listECCs.Add("secp256k1 [0x16]");
				break;
			case 23:
				listECCs.Add("secp256r1 [0x17]");
				break;
			case 24:
				listECCs.Add("secp384r1 [0x18]");
				break;
			case 25:
				listECCs.Add("secp521r1 [0x19]");
				break;
			case 29:
				listECCs.Add("x25519 [0x1d]");
				break;
			case 30:
				listECCs.Add("x448 [0x1e]");
				break;
			case 256:
				listECCs.Add("ffdhe2048 [0x0100]");
				break;
			case 257:
				listECCs.Add("ffdhe3072 [0x0101]");
				break;
			case 258:
				listECCs.Add("ffdhe4096 [0x0102]");
				break;
			case 259:
				listECCs.Add("ffdhe6144 [0x0103]");
				break;
			case 260:
				listECCs.Add("ffdhe8192 [0x0104]");
				break;
			case 2570:
			case 6682:
			case 10794:
			case 14906:
			case 19018:
			case 23130:
			case 27242:
			case 31354:
			case 35466:
			case 39578:
			case 43690:
			case 47802:
			case 51914:
			case 56026:
			case 60138:
			case 64250:
				listECCs.Add("grease [0x" + uShort.ToString("x") + "]");
				break;
			case 65281:
				listECCs.Add("arbitrary_explicit_prime_curves [0xff01]");
				break;
			case 65282:
				listECCs.Add("arbitrary_explicit_char2_curves [0xff02]");
				break;
			default:
				listECCs.Add($"unknown [0x{uShort:x}]");
				break;
			}
		}
		return string.Join(", ", listECCs.ToArray());
	}

	/// <summary>
	/// List defined ECC Point Formats from RFC4492
	/// </summary>
	/// <param name="eccPoints"></param>
	/// <returns></returns>
	internal static string GetECCPointFormatsAsString(byte[] eccPoints)
	{
		List<string> listFormats = new List<string>();
		if (eccPoints.Length < 1)
		{
			return string.Empty;
		}
		for (int iX = 1; iX < eccPoints.Length; iX++)
		{
			switch (eccPoints[iX])
			{
			case 0:
				listFormats.Add("uncompressed [0x0]");
				break;
			case 1:
				listFormats.Add("ansiX962_compressed_prime [0x1]");
				break;
			case 2:
				listFormats.Add("ansiX962_compressed_char2 [0x2]");
				break;
			default:
				listFormats.Add($"unknown [0x{eccPoints[iX]:X}]");
				break;
			}
		}
		return string.Join(", ", listFormats.ToArray());
	}

	internal static string GetSupportedVersions(byte[] arrSupported)
	{
		List<string> listVersions = new List<string>();
		if (arrSupported.Length < 2)
		{
			return string.Empty;
		}
		for (int iX = 1; iX < arrSupported.Length - 2; iX += 2)
		{
			ushort uShort = (ushort)((arrSupported[iX] << 8) | arrSupported[iX + 1]);
			switch (uShort)
			{
			case 768:
				listVersions.Add("Ssl3.0");
				continue;
			case 769:
				listVersions.Add("Tls1.0");
				continue;
			case 770:
				listVersions.Add("Tls1.1");
				continue;
			case 771:
				listVersions.Add("Tls1.2");
				continue;
			case 772:
				listVersions.Add("Tls1.3");
				continue;
			}
			string sDescription = "unknown";
			if ((uShort & 0xA0A) == 2570 && uShort >> 8 == (uShort & 0xFF))
			{
				sDescription = "grease";
			}
			else if ((uShort & 0x7F00) == 32512)
			{
				sDescription = "Tls1.3_draft" + (uShort & 0xFF);
			}
			listVersions.Add($"{sDescription} [0x{uShort:x}]");
		}
		return string.Join(", ", listVersions.ToArray());
	}

	/// <summary>
	/// Converts a HTTPS version to a "Major.Minor (Friendly)" string
	/// </summary>
	internal static string HTTPSVersionToString(int iMajor, int iMinor)
	{
		string sFriendly = "Unknown";
		if (iMajor == 127)
		{
			sFriendly = "TLS/1.3, Draft " + iMinor;
		}
		else if (iMajor == 3 && iMinor == 4)
		{
			sFriendly = "TLS/1.3";
		}
		else if (iMajor == 3 && iMinor == 3)
		{
			sFriendly = "TLS/1.2";
		}
		else if (iMajor == 3 && iMinor == 2)
		{
			sFriendly = "TLS/1.1";
		}
		else if (iMajor == 3 && iMinor == 1)
		{
			sFriendly = "TLS/1.0";
		}
		else if (iMajor == 3 && iMinor == 0)
		{
			sFriendly = "SSL/3.0";
		}
		else if (iMajor == 2 && iMinor == 0)
		{
			sFriendly = "SSL/2.0";
		}
		return $"{iMajor}.{iMinor} ({sFriendly})";
	}
}
