using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using FiddlerCore.Utilities;

namespace Fiddler;

internal class HTTPSServerHello
{
	private int _HandshakeVersion;

	private int _MessageLen;

	private int _MajorVersion;

	private int _MinorVersion;

	private byte[] _Random;

	private byte[] _SessionID;

	private uint _iCipherSuite;

	private int _iCompression;

	private List<string> _Extensions;

	/// <summary>
	/// Did client use ALPN to go to SPDY?
	/// http://tools.ietf.org/html/draft-ietf-tls-applayerprotoneg-01#section-3.1
	/// </summary>
	public bool bALPNToSPDY { get; set; }

	/// <summary>
	///  Did this ServerHello Handshake specify an upgrade to SPDY?
	/// </summary>
	public bool bNPNToSPDY { get; set; }

	/// <summary>
	///  Did this ServerHello Handshake specify an upgrade to SPDY?
	/// </summary>
	public bool bALPNToHTTP2 { get; set; }

	private bool isTLS1Dot3OrLater
	{
		get
		{
			if (_MajorVersion > 3)
			{
				return true;
			}
			if (_MajorVersion == 3 && _MinorVersion > 3)
			{
				return true;
			}
			return false;
		}
	}

	private string CompressionSuite
	{
		get
		{
			if (_iCompression < HTTPSClientHello.HTTPSCompressionSuites.Length)
			{
				return HTTPSClientHello.HTTPSCompressionSuites[_iCompression];
			}
			return $"Unrecognized compression format [0x{_iCompression:X2}]";
		}
	}

	internal string CipherSuite
	{
		get
		{
			if (_iCipherSuite < HTTPSClientHello.SSL3CipherSuites.Length)
			{
				return HTTPSClientHello.SSL3CipherSuites[_iCipherSuite];
			}
			if (HTTPSClientHello.dictTLSCipherSuites.TryGetValue(_iCipherSuite, out var sSuite))
			{
				return sSuite;
			}
			return $"Unrecognized cipher [0x{_iCipherSuite:X4}] - See http://www.iana.org/assignments/tls-parameters/";
		}
	}

	public string SessionID
	{
		get
		{
			if (_SessionID == null)
			{
				return string.Empty;
			}
			return Utilities.ByteArrayToString(_SessionID);
		}
	}

	public override string ToString()
	{
		StringBuilder sbOutput = new StringBuilder(512);
		if (_HandshakeVersion == 2)
		{
			sbOutput.Append("A SSLv2-compatible ServerHello handshake was found. In v2, the ~client~ selects the active cipher after the ServerHello, when sending the Client-Master-Key message. Fiddler only parses the handshake.\n\n");
		}
		else
		{
			sbOutput.Append("A SSLv3-compatible ServerHello handshake was found. Fiddler extracted the parameters below.\n\n");
		}
		sbOutput.AppendFormat("Version: {0}\n", HTTPSUtilities.HTTPSVersionToString(_MajorVersion, _MinorVersion));
		if (!isTLS1Dot3OrLater)
		{
			sbOutput.AppendFormat("SessionID:\t{0}\n", Utilities.ByteArrayToString(_SessionID));
		}
		if (_HandshakeVersion == 3)
		{
			sbOutput.AppendFormat("Random:\t\t{0}\n", Utilities.ByteArrayToString(_Random));
			sbOutput.AppendFormat("Cipher:\t\t{0} [0x{1:X4}]\n", CipherSuite, _iCipherSuite);
		}
		if (!isTLS1Dot3OrLater)
		{
			sbOutput.AppendFormat("CompressionSuite:\t{0} [0x{1:X2}]\n", CompressionSuite, _iCompression);
		}
		sbOutput.AppendFormat("Extensions:\n\t{0}\n", ExtensionListToString(_Extensions));
		return sbOutput.ToString();
	}

	private static string ExtensionListToString(List<string> slExts)
	{
		if (slExts == null || slExts.Count < 1)
		{
			return "\tnone";
		}
		return string.Join("\n\t", slExts.ToArray());
	}

	/// <summary>
	/// Parse a single extension using the list from http://tools.ietf.org/html/rfc6066
	/// </summary>
	/// <param name="iExtType"></param>
	/// <param name="arrData"></param>
	private void ParseServerHelloExtension(int iExtType, byte[] arrData)
	{
		if (_Extensions == null)
		{
			_Extensions = new List<string>();
		}
		switch (iExtType)
		{
		case 0:
			_Extensions.Add($"\tserver_name\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 1:
			_Extensions.Add($"\tmax_fragment_length\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 2:
			_Extensions.Add($"\tclient_certificate_url\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 3:
			_Extensions.Add($"\ttrusted_ca_keys\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 4:
			_Extensions.Add($"\ttruncated_hmac\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 5:
			_Extensions.Add($"\tstatus_request (OCSP-stapling)\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 6:
			_Extensions.Add($"\tuser_mapping\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 9:
			_Extensions.Add($"\tcert_type\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 10:
			_Extensions.Add($"\tsupported_groups\t{HTTPSUtilities.GetSupportedGroupsAsString(arrData)}");
			break;
		case 11:
			_Extensions.Add($"\tec_point_formats\t{HTTPSUtilities.GetECCPointFormatsAsString(arrData)}");
			break;
		case 12:
			_Extensions.Add($"\tsrp_rfc_5054\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 13:
			_Extensions.Add($"\tILLEGAL EXTENSION signature_algorithms\t{HTTPSUtilities.GetSignatureAndHashAlgsAsString(arrData)}");
			break;
		case 14:
			_Extensions.Add($"\tuse_srtp\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 15:
			_Extensions.Add($"\theartbeat_rfc_6520\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 16:
		{
			string sProtocolList = HTTPSUtilities.GetProtocolListAsString(arrData);
			_Extensions.Add($"\tALPN\t\t{sProtocolList}");
			if (sProtocolList.Contains("spdy/"))
			{
				bALPNToSPDY = true;
			}
			if (sProtocolList.Contains("h2-"))
			{
				bALPNToHTTP2 = true;
			}
			break;
		}
		case 17:
			_Extensions.Add($"\tstatus_request_v2 (RFC6961 OCSP-stapling v2)\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 18:
			_Extensions.Add($"\tSignedCertTimestamp (RFC6962)\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 19:
			_Extensions.Add($"\tClientCertificateType (RFC7250)\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 20:
			_Extensions.Add($"\tServerCertificateType (RFC7250)\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 22:
			_Extensions.Add($"\tencrypt_then_mac (RFC7366)\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 23:
			_Extensions.Add($"\textended_master_secret\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 24:
			_Extensions.Add($"\ttoken_binding\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 25:
			_Extensions.Add($"\tcached_info\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 35:
			_Extensions.Add($"\tSessionTicket\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 40:
			_Extensions.Add($"\tkey_share\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 41:
			_Extensions.Add($"\tpre_shared_key\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 42:
			_Extensions.Add($"\tearly_data\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 43:
			_Extensions.Add($"\tsupported_versions\t{HTTPSUtilities.GetSupportedVersions(arrData)}");
			break;
		case 44:
			_Extensions.Add($"\tcookie\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 46:
			_Extensions.Add($"\tticket_early_data_info\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 47:
			_Extensions.Add($"\tcertificate_authorities\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 48:
			_Extensions.Add($"\toid_filters\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 50:
			_Extensions.Add($"\tsignature_algorithms_cert\t{HTTPSUtilities.GetSignatureAndHashAlgsAsString(arrData)}");
			break;
		case 51:
			_Extensions.Add($"\tkey_share\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 13172:
		{
			string sNPN = HTTPSUtilities.GetExtensionString(arrData);
			_Extensions.Add($"\tNextProtocolNego\t{sNPN}");
			if (sNPN.Contains("spdy/"))
			{
				bNPNToSPDY = true;
			}
			break;
		}
		case 21760:
			_Extensions.Add($"\ttoken_binding(MSDraft)\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 30031:
		case 30032:
			_Extensions.Add($"\tchannel_id(GoogleDraft)\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 65281:
			_Extensions.Add($"\trenegotiation_info\t{Utilities.ByteArrayToString(arrData)}");
			break;
		default:
			_Extensions.Add($"\t0x{iExtType:x4}\t\t{Utilities.ByteArrayToString(arrData)}");
			break;
		}
	}

	private void ParseServerHelloExtensions(byte[] arrExtensionsData)
	{
		int iPtr = 0;
		try
		{
			int iExtDataLen;
			for (; iPtr < arrExtensionsData.Length; iPtr += 4 + iExtDataLen)
			{
				int iExtensionType = (arrExtensionsData[iPtr] << 8) + arrExtensionsData[iPtr + 1];
				iExtDataLen = (arrExtensionsData[iPtr + 2] << 8) + arrExtensionsData[iPtr + 3];
				byte[] arrExtData = new byte[iExtDataLen];
				Buffer.BlockCopy(arrExtensionsData, iPtr + 4, arrExtData, 0, arrExtData.Length);
				try
				{
					ParseServerHelloExtension(iExtensionType, arrExtData);
				}
				catch (Exception eX2)
				{
					FiddlerApplication.Log.LogFormat("Error parsing server TLS extension. {0}", FiddlerCore.Utilities.Utilities.DescribeException(eX2));
				}
			}
		}
		catch (Exception eX)
		{
			FiddlerApplication.Log.LogFormat("Error parsing server TLS extensions. {0}", FiddlerCore.Utilities.Utilities.DescribeException(eX));
		}
	}

	internal bool LoadFromStream(Stream oNS)
	{
		int cBytes = 0;
		int iProt = oNS.ReadByte();
		switch (iProt)
		{
		case 22:
		{
			_HandshakeVersion = 3;
			_MajorVersion = oNS.ReadByte();
			_MinorVersion = oNS.ReadByte();
			int iRecordLen = oNS.ReadByte() << 8;
			iRecordLen += oNS.ReadByte();
			int iMsgType = oNS.ReadByte();
			byte[] data = new byte[3];
			cBytes = oNS.Read(data, 0, data.Length);
			_MessageLen = (data[0] << 16) + (data[1] << 8) + data[2];
			_MajorVersion = oNS.ReadByte();
			_MinorVersion = oNS.ReadByte();
			_Random = new byte[32];
			cBytes = oNS.Read(_Random, 0, 32);
			if (!isTLS1Dot3OrLater)
			{
				int iSessionIDLen = oNS.ReadByte();
				_SessionID = new byte[iSessionIDLen];
				cBytes = oNS.Read(_SessionID, 0, _SessionID.Length);
			}
			_iCipherSuite = (uint)((oNS.ReadByte() << 8) + oNS.ReadByte());
			if (!isTLS1Dot3OrLater)
			{
				_iCompression = oNS.ReadByte();
			}
			if (_MajorVersion < 3 || (_MajorVersion == 3 && _MinorVersion < 1))
			{
				return true;
			}
			data = new byte[2];
			cBytes = oNS.Read(data, 0, data.Length);
			if (cBytes < 2)
			{
				return true;
			}
			int cExtensionsLen = (data[0] << 8) + data[1];
			if (cExtensionsLen < 1)
			{
				return true;
			}
			data = new byte[cExtensionsLen];
			cBytes = oNS.Read(data, 0, data.Length);
			if (cBytes == data.Length)
			{
				ParseServerHelloExtensions(data);
			}
			return true;
		}
		case 21:
		{
			byte[] arrBytes = new byte[7];
			oNS.Read(arrBytes, 0, 7);
			FiddlerApplication.Log.LogFormat("Got a TLS alert from the server!\n{0}", Utilities.ByteArrayToHexView(arrBytes, 8));
			return false;
		}
		default:
		{
			_HandshakeVersion = 2;
			int oJunk = oNS.ReadByte();
			if (128 != (iProt & 0x80))
			{
				oJunk = oNS.ReadByte();
			}
			iProt = oNS.ReadByte();
			if (iProt != 4)
			{
				return false;
			}
			_SessionID = new byte[1];
			oNS.Read(_SessionID, 0, 1);
			oNS.ReadByte();
			_MinorVersion = oNS.ReadByte();
			_MajorVersion = oNS.ReadByte();
			return true;
		}
		}
	}
}
