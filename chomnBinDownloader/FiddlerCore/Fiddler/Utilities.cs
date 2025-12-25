using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Runtime;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Serialization;
using FiddlerCore.PlatformExtensions;
using FiddlerCore.PlatformExtensions.API;
using FiddlerCore.Utilities;
using Microsoft.Win32;

namespace Fiddler;

/// <summary>
/// Holds a variety of useful functions used in Fiddler and its addons. 
/// </summary>
public static class Utilities
{
	private static Version thisAssemblyVersion = null;

	private static string rootDirectory = null;

	/// <summary>
	/// A static byte array containing 0 elements. Use to avoid having many copies of an empty byte[] floating around.
	/// </summary>
	public static readonly byte[] emptyByteArray = new byte[0];

	/// <summary>
	/// Set of encodings for which we'll attempt to sniff. (List order matters, I think)
	/// </summary>
	private static Encoding[] sniffableEncodings = new Encoding[4]
	{
		Encoding.UTF32,
		Encoding.BigEndianUnicode,
		Encoding.Unicode,
		Encoding.UTF8
	};

	private static string[] knownBrowsers;

	public const string sCommonRequestHeaders = "Cache-Control,If-None-Match,If-Modified-Since,Pragma,If-Unmodified-Since,If-Range,If-Match,Content-Length,Content-Type,Referer,Origin,SOAPAction,Expect,Content-Encoding,TE,Transfer-Encoding,Proxy-Connection,Connection,Accept,Accept-Charset,Accept-Encoding,Accept-Language,User-Agent,UA-Color,UA-CPU,UA-OS,UA-Pixels,Cookie,Cookie2,DNT,Authorization,Proxy-Authorization,X-Requested-With,X-Download-Initiator";

	public const string sCommonResponseHeaders = "Age,Cache-Control,Date,Expires,Pragma,Vary,Content-Length,ETag,Last-Modified,Content-Type,Content-Disposition,Content-Encoding,Transfer-encoding,Via,Keep-Alive,Location,Proxy-Connection,Connection,Set-Cookie,WWW-Authenticate,Proxy-Authenticate,P3P,X-UA-Compatible,X-Frame-options,X-Content-Type-Options,X-XSS-Protection,Strict-Transport-Security,Content-Security-Policy,Access-Control-Allow-Origin";

	public static Version ThisAssemblyVersion
	{
		get
		{
			if (thisAssemblyVersion == null)
			{
				Type objType = typeof(Proxy);
				string currentAssemblyFullName = objType.Assembly.FullName;
				AssemblyName assembly = new AssemblyName(currentAssemblyFullName);
				thisAssemblyVersion = assembly.Version;
			}
			return thisAssemblyVersion;
		}
	}

	/// <summary>
	/// Create a Session Archive Zip file containing the specified sessions
	/// </summary>
	/// <param name="sFilename">The filename of the SAZ file to store</param>
	/// <param name="arrSessions">Array of sessions to store</param>
	/// <param name="sPassword">Password to encrypt the file with, or null</param>
	/// <param name="bVerboseDialogs">TRUE if verbose error dialogs should be shown.</param>
	/// <returns></returns>
	[CodeDescription("Save the specified .SAZ session archive")]
	public static bool WriteSessionArchive(string sFilename, Session[] arrSessions, string sPassword)
	{
		if (arrSessions == null || arrSessions.Length < 1)
		{
			string title = "WriteSessionArchive - No Input";
			string message = "No sessions were provided to save to the archive.";
			FiddlerApplication.Log.LogFormat("{0}: {1}", title, message);
			return false;
		}
		if (FiddlerApplication.oSAZProvider == null)
		{
			throw new NotSupportedException("This application was compiled without .SAZ support.");
		}
		try
		{
			if (File.Exists(sFilename))
			{
				File.Delete(sFilename);
			}
			ISAZWriter oZip = FiddlerApplication.oSAZProvider.CreateSAZ(sFilename);
			if (!string.IsNullOrEmpty(sPassword))
			{
				oZip.SetPassword(sPassword);
			}
			oZip.Comment = "Fiddler (v" + ThisAssemblyVersion.ToString() + ") Session Archive. See https://fiddler2.com";
			int iFileNumber = 1;
			string sFileNumberFormatter = "D" + arrSessions.Length.ToString().Length;
			foreach (Session oSession in arrSessions)
			{
				try
				{
					WriteSessionToSAZ(oSession, oZip, iFileNumber, sFileNumberFormatter, null);
				}
				catch (Exception eX2)
				{
					FiddlerApplication.Log.LogFormat("Warning: Failed to add Session to SAZ: {0}", FiddlerCore.Utilities.Utilities.DescribeException(eX2));
				}
				iFileNumber++;
			}
			oZip.CompleteArchive();
			return true;
		}
		catch (Exception eX)
		{
			string title2 = "Save Failed";
			string message2 = "Failed to save Session Archive.\n\n" + eX.Message;
			FiddlerApplication.Log.LogFormat("{0}: {1}", title2, message2);
			return false;
		}
	}

	/// <summary>
	/// This is a refactored helper function which writes a single session to an open SAZ file.
	/// </summary>
	/// <param name="oSession">The session to write to the file</param>
	/// <param name="oISW">The ZIP File</param>
	/// <param name="iFileNumber">The number of this file</param>
	/// <param name="sFileNumberFormat">The format string (e.g. "D3") to use when formatting the file number</param>
	/// <param name="sbHTML">The HTML String builder to write index information</param>
	/// <param name="bVerboseDialogs">TRUE to show verbose error dialog information</param>
	internal static void WriteSessionToSAZ(Session oSession, ISAZWriter oISW, int iFileNumber, string sFileNumberFormat, StringBuilder sbHTML)
	{
		string sBaseFilename = "raw\\" + iFileNumber.ToString(sFileNumberFormat);
		string sRequestFilename = sBaseFilename + "_c.txt";
		string sResponseFilename = sBaseFilename + "_s.txt";
		string sMetadataFilename = sBaseFilename + "_m.xml";
		try
		{
			oISW.AddFile(sRequestFilename, delegate(Stream oS)
			{
				oSession.WriteRequestToStream(bHeadersOnly: false, bIncludeProtocolAndHostWithPath: true, oS);
			});
		}
		catch (Exception eX4)
		{
			string title4 = "Archive Failure";
			string message4 = "Unable to add " + sRequestFilename + "\n\n" + DescribeExceptionWithStack(eX4);
			FiddlerApplication.Log.LogFormat("{0}: {1}", title4, message4);
		}
		try
		{
			oISW.AddFile(sResponseFilename, delegate(Stream oS)
			{
				oSession.WriteResponseToStream(oS, bHeadersOnly: false);
			});
		}
		catch (Exception eX3)
		{
			string title3 = "Archive Failure";
			string message3 = "Unable to add " + sResponseFilename + "\n\n" + DescribeExceptionWithStack(eX3);
			FiddlerApplication.Log.LogFormat("{0}: {1}", title3, message3);
		}
		try
		{
			oISW.AddFile(sMetadataFilename, delegate(Stream oS)
			{
				oSession.WriteMetadataToStream(oS);
			});
		}
		catch (Exception eX2)
		{
			string title2 = "Archive Failure";
			string message2 = "Unable to add " + sMetadataFilename + "\n\n" + DescribeExceptionWithStack(eX2);
			FiddlerApplication.Log.LogFormat("{0}: {1}", title2, message2);
		}
		if (oSession.bHasWebSocketMessages)
		{
			string sWebSocketDataFilename = sBaseFilename + "_w.txt";
			try
			{
				oISW.AddFile(sWebSocketDataFilename, delegate(Stream oS)
				{
					oSession.WriteWebSocketMessagesToStream(oS);
				});
			}
			catch (Exception eX)
			{
				string title = "Archive Failure";
				string message = "Unable to add " + sWebSocketDataFilename + "\n\n" + DescribeExceptionWithStack(eX);
				FiddlerApplication.Log.LogFormat("{0}: {1}", title, message);
			}
		}
		if (sbHTML != null)
		{
			sbHTML.Append("<tr>");
			sbHTML.AppendFormat("<td><a href='{0}'>C</a>&nbsp;", sRequestFilename);
			sbHTML.AppendFormat("<a href='{0}'>S</a>&nbsp;", sResponseFilename);
			sbHTML.AppendFormat("<a href='{0}'>M</a>", sMetadataFilename);
			if (oSession.bHasWebSocketMessages)
			{
				sbHTML.AppendFormat("&nbsp;<a href='{0}_w.txt'>W</a>", sBaseFilename);
			}
			sbHTML.AppendFormat("</td>");
			sbHTML.Append("</tr>");
		}
	}

	public static Session[] ReadSessionArchive(string sFilename)
	{
		return ReadSessionArchive(sFilename, string.Empty);
	}

	/// <summary>
	/// Reads a Session Archive Zip file into an array of Session objects
	/// </summary>
	/// <param name="sFilename">Filename to load</param>
	/// <param name="bVerboseDialogs"></param>
	/// <returns>Loaded array of sessions or null, in case of failure</returns>
	public static Session[] ReadSessionArchive(string sFilename, string sContext)
	{
		return ReadSessionArchive(sFilename, sContext, null);
	}

	/// <summary>
	/// Reads a Session Archive Zip file into an array of Session objects
	/// </summary>
	/// <param name="sFilename">Filename to load</param>
	/// <param name="bVerboseDialogs"></param>
	/// <returns>Loaded array of sessions or null, in case of failure</returns>
	[CodeDescription("Load the specified .SAZ or .ZIP session archive")]
	public static Session[] ReadSessionArchive(string sFilename, string sContext, GetPasswordDelegate fnPasswordCallback)
	{
		if (!File.Exists(sFilename))
		{
			return null;
		}
		if (FiddlerApplication.oSAZProvider == null)
		{
			throw new NotSupportedException("This application was compiled without .SAZ support.");
		}
		List<Session> outSessions = new List<Session>();
		try
		{
			using (FileStream oSniff = File.Open(sFilename, FileMode.Open, FileAccess.Read, FileShare.Read))
			{
				if (oSniff.Length < 64 || oSniff.ReadByte() != 80 || oSniff.ReadByte() != 75)
				{
					string sExtra = null;
					return null;
				}
			}
			ISAZReader oSAZFile = FiddlerApplication.oSAZProvider.LoadSAZ(sFilename);
			if (fnPasswordCallback != null && oSAZFile is ISAZReader2 IReader2)
			{
				IReader2.PasswordCallback = fnPasswordCallback;
			}
			string[] arrClientFiles = oSAZFile.GetRequestFileList();
			if (arrClientFiles.Length < 1)
			{
				oSAZFile.Close();
				return null;
			}
			string[] array = arrClientFiles;
			foreach (string sRequestFile in array)
			{
				try
				{
					byte[] arrRequest;
					try
					{
						arrRequest = oSAZFile.GetFileBytes(sRequestFile);
					}
					catch (OperationCanceledException)
					{
						oSAZFile.Close();
						return null;
					}
					string sResponseFile = sRequestFile.Replace("_c.txt", "_s.txt");
					byte[] arrResponse = oSAZFile.GetFileBytes(sResponseFile);
					string sMetadataFile = sRequestFile.Replace("_c.txt", "_m.xml");
					Stream strmMetadata = oSAZFile.GetFileStream(sMetadataFile);
					Session oNewSession = new Session(arrRequest, arrResponse);
					if (strmMetadata != null)
					{
						oNewSession.LoadMetadata(strmMetadata);
					}
					oNewSession.oFlags["x-LoadedFrom"] = sRequestFile.Replace("_c.txt", "_s.txt");
					oNewSession.SetBitFlag(SessionFlags.LoadedFromSAZ, b: true);
					if (oNewSession.isAnyFlagSet(SessionFlags.IsWebSocketTunnel) && !oNewSession.HTTPMethodIs("CONNECT"))
					{
						string sWSMessagesFile = sRequestFile.Replace("_c.txt", "_w.txt");
						Stream strmWSMessages = oSAZFile.GetFileStream(sWSMessagesFile);
						if (strmWSMessages != null)
						{
							WebSocket.LoadWebSocketMessagesFromStream(oNewSession, strmWSMessages);
						}
						else
						{
							oNewSession.oFlags["X-WS-SAZ"] = "SAZ File did not contain any WebSocket messages.";
						}
					}
					oNewSession.RaiseSessionFieldChanged();
					outSessions.Add(oNewSession);
				}
				catch (Exception)
				{
				}
			}
			oSAZFile.Close();
		}
		catch (Exception eX)
		{
			string sError = "Fiddler was unable to load the specified archive";
			sError = (string.IsNullOrEmpty(sContext) ? (sError + ".") : (sError + " for " + sContext + "."));
			if (sFilename.StartsWith("\\\\"))
			{
				sError += "\n\nThis may be an indication of a connectivity problem or storage corruption on your network file share.";
			}
			string title = "Unable to load Archive";
			FiddlerApplication.Log.LogFormat("{0}: {1}" + Environment.NewLine + "{2}", title, sError, eX.ToString());
			return null;
		}
		return outSessions.ToArray();
	}

	/// <summary>
	/// Ensures a value is within a specified range.
	/// </summary>
	/// <typeparam name="T">Type of the value</typeparam>
	/// <param name="current">Current value</param>
	/// <param name="min">Min value</param>
	/// <param name="max">Max value</param>
	/// <returns>Returns the provided value, unless it is outside of the specified range, in which case the nearest "fencepost" is returned.</returns>
	public static T EnsureInRange<T>(T current, T min, T max)
	{
		if (Comparer<T>.Default.Compare(current, min) < 0)
		{
			return min;
		}
		if (Comparer<T>.Default.Compare(current, max) > 0)
		{
			return max;
		}
		return current;
	}

	public static string UNSTABLE_DescribeClientHello(MemoryStream msHello)
	{
		HTTPSClientHello oHello = new HTTPSClientHello();
		if (oHello.LoadFromStream(msHello))
		{
			return oHello.ToString();
		}
		return string.Empty;
	}

	public static string UNSTABLE_DescribeServerHello(MemoryStream msHello)
	{
		HTTPSServerHello oHello = new HTTPSServerHello();
		if (oHello.LoadFromStream(msHello))
		{
			return oHello.ToString();
		}
		return string.Empty;
	}

	/// <summary>
	/// Check to see that the target assembly defines a RequiredVersionAttribute and that the current Fiddler instance meets that requirement
	/// </summary>
	/// <param name="assemblyInput">The assembly to test</param>
	/// <param name="sWhatType">The "type" of extension for display in error message</param>
	/// <returns>TRUE if the assembly includes a requirement and Fiddler meets it.</returns>
	internal static bool FiddlerMeetsVersionRequirement(Assembly assemblyInput, string sWhatType)
	{
		if (!assemblyInput.IsDefined(typeof(RequiredVersionAttribute), inherit: false))
		{
			return false;
		}
		RequiredVersionAttribute oRequires = (RequiredVersionAttribute)Attribute.GetCustomAttribute(assemblyInput, typeof(RequiredVersionAttribute));
		int iDiff = CompareVersions(oRequires.RequiredVersion, CONFIG.FiddlerVersionInfo);
		if (iDiff > 0)
		{
			string title = "Extension Not Loaded";
			string message = $"The {sWhatType} in {assemblyInput.CodeBase} require Fiddler v{oRequires.RequiredVersion} or later. (You have v{CONFIG.FiddlerVersionInfo})\n\nPlease install the latest version of Fiddler from http://getfiddler.com.\n\nCode: {iDiff}";
			FiddlerApplication.Log.LogFormat("{0}: {1}", title, message);
			return false;
		}
		return true;
	}

	/// <summary>
	/// Typically, a version number is displayed as "major number.minor number.build number.private part number". 
	/// </summary>
	/// <param name="sRequiredVersion">Version required</param>
	/// <param name="verTest">Version of the binary being tested</param>
	/// <returns>Returns 0 if exact match, else greater than 0 if Required version greater than verTest</returns>
	public static int CompareVersions(string sRequiredVersion, Version verTest)
	{
		string[] sVersions = sRequiredVersion.Split(new char[1] { '.' });
		if (sVersions.Length != 4)
		{
			return 5;
		}
		VersionStruct verRequired = new VersionStruct();
		if (!int.TryParse(sVersions[0], NumberStyles.Integer, NumberFormatInfo.InvariantInfo, out verRequired.Major) || !int.TryParse(sVersions[1], NumberStyles.Integer, NumberFormatInfo.InvariantInfo, out verRequired.Minor) || !int.TryParse(sVersions[2], NumberStyles.Integer, NumberFormatInfo.InvariantInfo, out verRequired.Build) || !int.TryParse(sVersions[3], NumberStyles.Integer, NumberFormatInfo.InvariantInfo, out verRequired.Private))
		{
			return 6;
		}
		if (verRequired.Major > verTest.Major)
		{
			return 4;
		}
		if (verTest.Major > verRequired.Major)
		{
			return -4;
		}
		if (verRequired.Minor > verTest.Minor)
		{
			return 3;
		}
		if (verTest.Minor > verRequired.Minor)
		{
			return -3;
		}
		if (verRequired.Build > verTest.Build)
		{
			return 2;
		}
		if (verTest.Build > verRequired.Build)
		{
			return -2;
		}
		if (verRequired.Private > verTest.Revision)
		{
			return 1;
		}
		if (verTest.Revision > verRequired.Private)
		{
			return -1;
		}
		return 0;
	}

	/// <summary>
	/// Address the problem where the target "PATH" calls for a directoryname is already a filename
	/// </summary>
	/// <param name="sTargetFolder"></param>
	/// <returns></returns>
	public static string EnsureValidAsPath(string sTargetFolder)
	{
		try
		{
			if (Directory.Exists(sTargetFolder))
			{
				return sTargetFolder;
			}
			string sPathRoot = Path.GetPathRoot(sTargetFolder);
			if (!Directory.Exists(sPathRoot))
			{
				return sTargetFolder;
			}
			if (sPathRoot[sPathRoot.Length - 1] != Path.DirectorySeparatorChar)
			{
				string text = sPathRoot;
				char directorySeparatorChar = Path.DirectorySeparatorChar;
				sPathRoot = text + directorySeparatorChar;
			}
			sTargetFolder = sTargetFolder.Substring(sPathRoot.Length);
			string[] sPathSegments = sTargetFolder.Split(new char[1] { Path.DirectorySeparatorChar }, StringSplitOptions.RemoveEmptyEntries);
			string sPathSoFar = sPathRoot;
			for (int iX = 0; iX < sPathSegments.Length; iX++)
			{
				if (File.Exists(sPathSoFar + sPathSegments[iX]))
				{
					int iDisambig = 1;
					string sStartWith = sPathSegments[iX];
					do
					{
						sPathSegments[iX] = $"{sStartWith}[{iDisambig}]";
						iDisambig++;
					}
					while (File.Exists(sPathSoFar + sPathSegments[iX]));
					break;
				}
				if (!Directory.Exists(sPathSoFar + sPathSegments[iX]))
				{
					break;
				}
				sPathSoFar = string.Format("{0}{1}{2}{1}", sPathSoFar, Path.DirectorySeparatorChar, sPathSegments[iX]);
			}
			return $"{sPathRoot}{string.Join(new string(Path.DirectorySeparatorChar, 1), sPathSegments)}";
		}
		catch (Exception)
		{
			return sTargetFolder;
		}
	}

	/// <summary>
	/// Ensure that the target file does not yet exist. If it does, generates a new filename with an embedded identifier, e.g. out[1].txt instead.
	/// Attempts to ensure filename is creatable; e.g. if a path component needs to be a directory but is a file already, injects [#] into that 
	/// path component.
	/// </summary>
	/// <param name="sFilename">Candidate filename</param>
	/// <returns>New filename which does not yet exist</returns>
	public static string EnsureUniqueFilename(string sFilename)
	{
		string sResult = sFilename;
		try
		{
			string sTargetFolder = Path.GetDirectoryName(sFilename);
			string sValidFolder = EnsureValidAsPath(sTargetFolder);
			if (sTargetFolder != sValidFolder)
			{
				sResult = $"{sValidFolder}{Path.DirectorySeparatorChar}{Path.GetFileName(sFilename)}";
			}
			if (FileOrFolderExists(sResult))
			{
				string sBaseFilename = Path.GetFileNameWithoutExtension(sResult);
				string sExt = Path.GetExtension(sResult);
				int iX = 1;
				do
				{
					sResult = $"{sTargetFolder}{Path.DirectorySeparatorChar}{sBaseFilename}[{iX.ToString()}]{sExt}";
					iX++;
				}
				while (FileOrFolderExists(sResult) || iX > 16384);
			}
		}
		catch (Exception)
		{
		}
		return sResult;
	}

	internal static bool FileOrFolderExists(string sResult)
	{
		try
		{
			return File.Exists(sResult) || Directory.Exists(sResult);
		}
		catch (Exception)
		{
			return true;
		}
	}

	/// <summary>
	/// Ensure that the target path exists and if a file exists there, it is not readonly or hidden.
	/// WARNING: Can throw if target "Filename" calls for a parent directoryname that is already used as a filename by a non-directory.
	/// E.g. EnsureOverwriteable(C:\io.sys\filename.txt); would throw.
	/// </summary>
	/// <param name="sFilename">The candidate filename</param>
	public static void EnsureOverwritable(string sFilename)
	{
		if (!Directory.Exists(Path.GetDirectoryName(sFilename)))
		{
			Directory.CreateDirectory(Path.GetDirectoryName(sFilename));
		}
		if (File.Exists(sFilename))
		{
			FileAttributes oFA = File.GetAttributes(sFilename);
			File.SetAttributes(sFilename, oFA & ~(FileAttributes.ReadOnly | FileAttributes.Hidden | FileAttributes.System));
		}
	}

	/// <summary>
	/// Writes arrBytes to a file, creating the target directory and overwriting if the file exists.
	/// </summary>
	/// <param name="sFilename">Path to File to write.</param>
	/// <param name="arrBytes">Bytes to write.</param>
	[CodeDescription("Writes arrBytes to a file, creating the target directory and overwriting if the file exists.")]
	public static void WriteArrayToFile(string sFilename, byte[] arrBytes)
	{
		if (arrBytes == null)
		{
			arrBytes = emptyByteArray;
		}
		EnsureOverwritable(sFilename);
		File.WriteAllBytes(sFilename, arrBytes);
	}

	/// <summary>
	/// Fills an array completely using the provided stream. Unlike a normal .Read(), this one will always fully fill the array unless the Stream throws.
	/// </summary>
	/// <param name="oStream">The stream from which to read.</param>
	/// <param name="arrBytes">The byte array into which the data should be stored.</param>
	/// <returns>The count of bytes read.</returns>
	[CodeDescription("Reads oStream until arrBytes is filled.")]
	public static int ReadEntireStream(Stream oStream, byte[] arrBytes)
	{
		int iPtr;
		for (iPtr = 0; iPtr < arrBytes.LongLength; iPtr += oStream.Read(arrBytes, iPtr, arrBytes.Length - iPtr))
		{
		}
		return iPtr;
	}

	public static byte[] ReadEntireStream(Stream oS)
	{
		MemoryStream oMS = new MemoryStream();
		byte[] buffer = new byte[32768];
		int bytesRead = 0;
		while ((bytesRead = oS.Read(buffer, 0, buffer.Length)) > 0)
		{
			oMS.Write(buffer, 0, bytesRead);
		}
		return oMS.ToArray();
	}

	/// <summary>
	/// Create a new byte[] containing the contents of two other byte arrays.
	/// </summary>
	/// <param name="arr1"></param>
	/// <param name="arr2"></param>
	/// <returns></returns>
	public static byte[] JoinByteArrays(byte[] arr1, byte[] arr2)
	{
		byte[] arrResult = new byte[arr1.Length + arr2.Length];
		Buffer.BlockCopy(arr1, 0, arrResult, 0, arr1.Length);
		Buffer.BlockCopy(arr2, 0, arrResult, arr1.Length, arr2.Length);
		return arrResult;
	}

	public static int IndexOfNth(string sString, int n, char chSeek)
	{
		if (string.IsNullOrEmpty(sString))
		{
			return -1;
		}
		if (n < 1)
		{
			throw new ArgumentException("index must be greater than 0");
		}
		for (int i = 0; i < sString.Length; i++)
		{
			if (sString[i] == chSeek)
			{
				n--;
				if (n == 0)
				{
					return i;
				}
			}
		}
		return -1;
	}

	internal static string ConvertCRAndLFToSpaces(string sIn)
	{
		sIn = sIn.Replace("\r\n", " ");
		sIn = sIn.Replace('\r', ' ');
		sIn = sIn.Replace('\n', ' ');
		return sIn;
	}

	/// <summary>
	/// Returns the Value from a (case-insensitive) token in the header string. Correctly handles double-quoted strings.
	/// Allows comma and semicolon as delimiter. Trailing whitespace may be present.
	/// </summary>
	/// <param name="sString">Name of the header</param>
	/// <param name="sTokenName">Name of the token</param>
	/// <returns>Value of the token if present; otherwise, null</returns>
	public static string GetCommaTokenValue(string sString, string sTokenName)
	{
		if (sString == null)
		{
			return null;
		}
		if (string.IsNullOrEmpty(sTokenName))
		{
			return null;
		}
		if (sString.Length < sTokenName.Length)
		{
			return null;
		}
		string sResult = null;
		if (!string.IsNullOrEmpty(sString))
		{
			Regex r = new Regex("(?:^" + sTokenName + "|[^\\w-=\"]" + sTokenName + ")(?:\\s?=\\s?[\"]?(?<TokenValue>[^\";,]*)|[\\s,;])", RegexOptions.IgnoreCase);
			Match i = r.Match(sString);
			if (i.Success && i.Groups["TokenValue"] != null)
			{
				sResult = i.Groups["TokenValue"].Value;
			}
		}
		return sResult;
	}

	/// <summary>
	/// Ensures that the target string is iMaxLength or fewer characters
	/// </summary>
	/// <param name="sString">The string to trim from</param>
	/// <param name="iMaxLength">The maximum number of characters to return</param>
	/// <returns>Up to iMaxLength characters from the "Head" of the string.</returns>
	[CodeDescription("Returns the first iMaxLength or fewer characters from the target string.")]
	public static string TrimTo(string sString, int iMaxLength)
	{
		if (string.IsNullOrEmpty(sString))
		{
			return string.Empty;
		}
		if (iMaxLength >= sString.Length)
		{
			return sString;
		}
		return sString.Substring(0, iMaxLength);
	}

	/// <summary>
	/// Ensures that the target string is iMaxLength or fewer characters, appending ... if truncation occurred
	/// </summary>
	/// <param name="sString">The string to trim from</param>
	/// <param name="iMaxLength">The maximum number of characters to return</param>
	/// <returns>The string, or up to iMaxLength-1 characters from the "Head" of the string, with \u2026 appeneded.</returns>
	public static string EllipsizeIfNeeded(string sString, int iMaxLength)
	{
		if (string.IsNullOrEmpty(sString))
		{
			return string.Empty;
		}
		if (iMaxLength >= sString.Length)
		{
			return sString;
		}
		return sString.Substring(0, iMaxLength - 1) + "…";
	}

	public static string PrefixEllipsizeIfNeeded(string sString, int iMaxLength)
	{
		if (string.IsNullOrEmpty(sString))
		{
			return string.Empty;
		}
		if (iMaxLength >= sString.Length)
		{
			return sString;
		}
		return "…" + sString.Substring(sString.Length - iMaxLength - 1);
	}

	/// <summary>
	/// Returns the "Head" of a string, before and not including a specified search string.
	/// </summary>
	/// <param name="sString">The string to trim from</param>
	/// <param name="sDelim">The delimiting string at which the trim should end.</param>
	/// <returns>Part of a string up to (but not including) sDelim, or the full string if sDelim was not found.</returns>
	[CodeDescription("Returns the part of a string up to (but NOT including) the first instance of specified substring. If delim not found, returns entire string.")]
	public static string TrimAfter(string sString, string sDelim)
	{
		if (sString == null)
		{
			return string.Empty;
		}
		if (sDelim == null)
		{
			return sString;
		}
		int ixToken = sString.IndexOf(sDelim);
		if (ixToken < 0)
		{
			return sString;
		}
		return sString.Substring(0, ixToken);
	}

	/// <summary>
	/// Returns the "Head" of a string, before and not including the first instance of specified delimiter.
	/// </summary>
	/// <param name="sString">The string to trim from.</param>
	/// <param name="chDelim">The delimiting character at which the trim should end.</param>	
	/// <returns>Part of a string up to (but not including) chDelim, or the full string if chDelim was not found.</returns>
	[CodeDescription("Returns the part of a string up to (but NOT including) the first instance of specified delimiter. If delim not found, returns entire string.")]
	public static string TrimAfter(string sString, char chDelim)
	{
		if (sString == null)
		{
			return string.Empty;
		}
		int ixToken = sString.IndexOf(chDelim);
		if (ixToken < 0)
		{
			return sString;
		}
		return sString.Substring(0, ixToken);
	}

	/// <summary>
	/// [Deprecated] Ensures that the target string is iMaxLength or fewer characters
	/// </summary>
	/// <param name="sString">The string to trim from</param>
	/// <param name="iMaxLength">The maximum number of characters to return</param>
	/// <remarks>Identical to the <see cref="M:Fiddler.Utilities.TrimTo(System.String,System.Int32)" /> method.</remarks>
	/// <returns>Up to iMaxLength characters from the "Head" of the string.</returns>
	public static string TrimAfter(string sString, int iMaxLength)
	{
		return TrimTo(sString, iMaxLength);
	}

	/// <summary>
	/// Returns the "Tail" of a string, after (but NOT including) the First instance of specified delimiter.
	/// See also <seealso cref="M:Fiddler.Utilities.TrimBeforeLast(System.String,System.Char)" />
	/// </summary>
	/// <param name="sString">The string to trim from.</param>
	/// <param name="chDelim">The delimiting character after which the text should be returned.</param>
	/// <returns>Part of a string after (but not including) chDelim, or the full string if chDelim was not found.</returns>
	[CodeDescription("Returns the part of a string after (but NOT including) the first instance of specified delimiter. If delim not found, returns entire string.")]
	public static string TrimBefore(string sString, char chDelim)
	{
		if (sString == null)
		{
			return string.Empty;
		}
		int ixToken = sString.IndexOf(chDelim);
		if (ixToken < 0)
		{
			return sString;
		}
		return sString.Substring(ixToken + 1);
	}

	/// <summary>
	/// Returns the "Tail" of a string, after (but NOT including) the First instance of specified search string.     
	/// <seealso cref="M:Fiddler.Utilities.TrimBeforeLast(System.String,System.String)" />
	/// </summary>
	/// <param name="sString">The string to trim from.</param>
	/// <param name="sDelim">The delimiting string after which the text should be returned.</param>
	/// <returns>Part of a string after (but not including) sDelim, or the full string if sDelim was not found.</returns>
	[CodeDescription("Returns the part of a string after (but NOT including) the first instance of specified substring. If delim not found, returns entire string.")]
	public static string TrimBefore(string sString, string sDelim)
	{
		if (sString == null)
		{
			return string.Empty;
		}
		if (sDelim == null)
		{
			return sString;
		}
		int ixToken = sString.IndexOf(sDelim);
		if (ixToken < 0)
		{
			return sString;
		}
		return sString.Substring(ixToken + sDelim.Length);
	}

	/// <summary>
	/// Returns the "Tail" of a string, after (and including) the first instance of specified search string.      
	/// </summary>
	/// <param name="sString">The string to trim from.</param>
	/// <param name="sDelim">The delimiting string at which the text should be returned.</param>
	/// <returns>Part of the string starting with sDelim, or the entire string if sDelim not found.</returns>
	[CodeDescription("Returns the part of a string after (and including) the first instance of specified substring. If delim not found, returns entire string.")]
	public static string TrimUpTo(string sString, string sDelim)
	{
		if (sString == null)
		{
			return string.Empty;
		}
		if (sDelim == null)
		{
			return sString;
		}
		int ixToken = sString.IndexOf(sDelim);
		if (ixToken < 0)
		{
			return sString;
		}
		return sString.Substring(ixToken);
	}

	/// <summary>
	/// Returns the "Tail" of a string, after (but not including) the Last instance of specified delimiter.
	/// <seealso cref="M:Fiddler.Utilities.TrimBefore(System.String,System.Char)" />
	/// </summary>
	/// <param name="sString">The string to trim from.</param>
	/// <param name="chDelim">The delimiting character after which text should be returned.</param>
	/// <returns>Part of a string after (but not including) the final chDelim, or the full string if chDelim was not found.</returns>
	[CodeDescription("Returns the part of a string after (but not including) the last instance of specified delimiter. If delim not found, returns entire string.")]
	public static string TrimBeforeLast(string sString, char chDelim)
	{
		return StringHelper.TrimBeforeLast(sString, chDelim);
	}

	/// <summary>
	/// Returns the "Tail" of a string, after (but not including) the Last instance of specified substring.
	/// <seealso cref="M:Fiddler.Utilities.TrimBefore(System.String,System.String)" />
	/// </summary>
	/// <param name="sString">The string to trim from.</param>
	/// <param name="sDelim">The delimiting string after which text should be returned.</param>
	/// <returns>Part of a string after (but not including) the final sDelim, or the full string if sDelim was not found.</returns>     
	[CodeDescription("Returns the part of a string after (but not including) the last instance of specified substring. If delim not found, returns entire string.")]
	public static string TrimBeforeLast(string sString, string sDelim)
	{
		if (sString == null)
		{
			return string.Empty;
		}
		if (sDelim == null)
		{
			return sString;
		}
		int ixToken = sString.LastIndexOf(sDelim);
		if (ixToken < 0)
		{
			return sString;
		}
		return sString.Substring(ixToken + sDelim.Length);
	}

	/// <summary>
	/// Strip any IPv6-Literal brackets, needed when creating a Certificate
	/// </summary>
	/// <param name="sHost"></param>
	/// <returns></returns>
	internal static string StripIPv6LiteralBrackets(string sHost)
	{
		if (sHost.Length > 2 && sHost.StartsWith("[") && sHost.EndsWith("]"))
		{
			sHost = sHost.Substring(1, sHost.Length - 2);
		}
		return sHost;
	}

	/// <summary>
	/// Determines true if a request with the specified HTTP Method/Verb MUST contain a entity body
	/// </summary>
	/// <param name="sMethod">The Method/Verb</param>
	/// <returns>TRUE if the HTTP Method MUST contain a request body.</returns>
	[CodeDescription("Returns TRUE if the HTTP Method MUST have a body.")]
	public static bool HTTPMethodRequiresBody(string sMethod)
	{
		return "PROPPATCH" == sMethod || "PATCH" == sMethod;
	}

	/// <summary>
	/// http://tools.ietf.org/html/draft-ietf-httpbis-p2-semantics-26#section-4.2.2
	/// </summary>
	/// <param name="sMethod">HTTPMethod</param>
	/// <returns>TRUE if the method is deemed idempotent</returns>
	public static bool HTTPMethodIsIdempotent(string sMethod)
	{
		return "GET" == sMethod || "HEAD" == sMethod || "OPTIONS" == sMethod || "TRACE" == sMethod || "PUT" == sMethod || "DELETE" == sMethod;
	}

	/// <summary>
	/// Returns true if a request with the specified HTTP Method/Verb may contain a entity body
	/// </summary>
	/// <param name="sMethod">The Method/Verb</param>
	/// <returns>TRUE if the HTTP Method MAY contain a request body.</returns>
	[CodeDescription("Returns TRUE if the HTTP Method MAY have a body.")]
	public static bool HTTPMethodAllowsBody(string sMethod)
	{
		return "POST" == sMethod || "PUT" == sMethod || "PROPPATCH" == sMethod || "PATCH" == sMethod || "LOCK" == sMethod || "PROPFIND" == sMethod || "SEARCH" == sMethod;
	}

	[CodeDescription("Returns TRUE if a response body is allowed for this responseCode.")]
	public static bool HTTPStatusAllowsBody(int iResponseCode)
	{
		return 204 != iResponseCode && 205 != iResponseCode && 304 != iResponseCode && (iResponseCode <= 99 || iResponseCode >= 200);
	}

	public static bool IsRedirectStatus(int iResponseCode)
	{
		return iResponseCode == 301 || iResponseCode == 302 || iResponseCode == 303 || iResponseCode == 307 || iResponseCode == 308;
	}

	/// <summary>
	/// Detects whether string ends in a file extension generally recognized as an image file extension.
	/// Pass lowercase into this function.
	/// </summary>
	/// <param name="sExt">*Lowercase* string</param>
	/// <returns>TRUE if string ends with common image file extension</returns>
	internal static bool HasImageFileExtension(string sExt)
	{
		return sExt.EndsWith(".gif") || sExt.EndsWith(".jpg") || sExt.EndsWith(".jpeg") || sExt.EndsWith(".png") || sExt.EndsWith(".webp") || sExt.EndsWith(".ico");
	}

	/// <summary>
	/// Determines if the specified MIME type is "binary" in nature.
	/// </summary>
	/// <param name="sContentType">The MIME type</param>
	/// <returns>TRUE if the MIME type is likely binary in nature</returns>
	public static bool IsBinaryMIME(string sContentType)
	{
		if (string.IsNullOrEmpty(sContentType))
		{
			return false;
		}
		if (sContentType.OICStartsWith("image/"))
		{
			return !sContentType.OICStartsWith("image/svg+xml");
		}
		if (sContentType.OICStartsWith("audio/"))
		{
			return true;
		}
		if (sContentType.OICStartsWith("video/"))
		{
			return true;
		}
		if (sContentType.OICStartsWith("text/"))
		{
			return false;
		}
		if (sContentType.OICContains("msbin1"))
		{
			return true;
		}
		if (sContentType.OICStartsWith("application/octet"))
		{
			return true;
		}
		if (sContentType.OICStartsWith("application/x-shockwave"))
		{
			return true;
		}
		return false;
	}

	/// <summary>
	/// Gets a string from a byte-array, stripping a Byte Order Marker preamble if present.
	/// </summary>
	/// <remarks>
	/// This function really shouldn't need to exist. Why doesn't calling .GetString on a string with a preamble remove the preamble???
	/// </remarks>
	/// <param name="arrInput">The byte array</param>
	/// <param name="oDefaultEncoding">The encoding to convert from *if* there's no Byte-order-marker</param>
	/// <returns>The string</returns>
	[CodeDescription("Gets a string from a byte-array, stripping a BOM if present.")]
	public static string GetStringFromArrayRemovingBOM(byte[] arrInput, Encoding oDefaultEncoding)
	{
		if (arrInput == null)
		{
			return string.Empty;
		}
		if (arrInput.Length < 2)
		{
			return oDefaultEncoding.GetString(arrInput);
		}
		Encoding[] array = sniffableEncodings;
		foreach (Encoding candidateEncoding in array)
		{
			byte[] arrPreamble = candidateEncoding.GetPreamble();
			if (arrInput.Length < arrPreamble.Length)
			{
				continue;
			}
			bool match = arrPreamble.Length != 0;
			for (int i = 0; i < arrPreamble.Length; i++)
			{
				if (arrPreamble[i] != arrInput[i])
				{
					match = false;
					break;
				}
			}
			if (match)
			{
				int iBOMLen = candidateEncoding.GetPreamble().Length;
				return candidateEncoding.GetString(arrInput, iBOMLen, arrInput.Length - iBOMLen);
			}
		}
		return oDefaultEncoding.GetString(arrInput);
	}

	/// <summary>
	/// WARNING: May throw.
	/// Gets an encoding, with proper respect for "utf8" as an alias for "utf-8"; Microsoft products don't support
	/// this prior to 2015-era, but it turns out to be common. We do have a linter elsewhere that reports a warning
	/// if it sees the dashless form.
	/// https://github.com/telerik/fiddler/issues/38
	/// </summary>
	/// <param name="sEncoding">Textual name of the encoding</param>
	public static Encoding GetTextEncoding(string sEncoding)
	{
		if (sEncoding.OICEquals("utf8"))
		{
			sEncoding = "utf-8";
		}
		return Encoding.GetEncoding(sEncoding);
	}

	/// <summary>
	/// WARNING: Potentially slow.
	/// WARNING: Does not decode the HTTP Response body; if compressed, embedded META or _charset_ will not be checked
	/// Gets (via Headers or Sniff) the provided body's text Encoding. If not found, returns CONFIG.oHeaderEncoding (usually UTF-8).
	/// </summary>
	/// <param name="oHeaders">HTTP Headers, ideally containing a Content-Type header with a charset attribute.</param>
	/// <param name="oBody">byte[] containing the entity body.</param>
	/// <returns>A character encoding, if one could be determined</returns>
	[CodeDescription("Gets (via Headers or Sniff) the provided body's text Encoding. Returns CONFIG.oHeaderEncoding (usually UTF-8) if unknown. Potentially slow.")]
	public static Encoding getEntityBodyEncoding(HTTPHeaders oHeaders, byte[] oBody)
	{
		if (oHeaders != null)
		{
			string sEncoding = oHeaders.GetTokenValue("Content-Type", "charset");
			if (sEncoding != null)
			{
				try
				{
					return GetTextEncoding(sEncoding);
				}
				catch (Exception)
				{
				}
			}
		}
		Encoding sniffedEncoding = CONFIG.oHeaderEncoding;
		if (oBody == null || oBody.Length < 2)
		{
			return sniffedEncoding;
		}
		Encoding[] array = sniffableEncodings;
		foreach (Encoding candidateEncoding in array)
		{
			byte[] arrPreamble = candidateEncoding.GetPreamble();
			if (oBody.Length < arrPreamble.Length)
			{
				continue;
			}
			bool match = arrPreamble.Length != 0;
			for (int i = 0; i < arrPreamble.Length; i++)
			{
				if (arrPreamble[i] != oBody[i])
				{
					match = false;
					break;
				}
			}
			if (match)
			{
				sniffedEncoding = candidateEncoding;
				break;
			}
		}
		if (oHeaders != null && oHeaders.Exists("Content-Type"))
		{
			if (oHeaders.ExistsAndContains("Content-Type", "multipart/form-data"))
			{
				string sSniffArea3 = sniffedEncoding.GetString(oBody, 0, Math.Min(8192, oBody.Length));
				Regex r3 = new Regex(".*Content-Disposition: form-data; name=\"_charset_\"\\s+(?<thecharset>[^\\s'&>\\\"]*)", RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture);
				MatchCollection mc3 = r3.Matches(sSniffArea3);
				if (mc3.Count > 0 && mc3[0].Groups.Count > 0)
				{
					string sEncoding4 = null;
					try
					{
						sEncoding4 = mc3[0].Groups[1].Value;
						Encoding oEnc3 = GetTextEncoding(sEncoding4);
						sniffedEncoding = oEnc3;
					}
					catch (Exception)
					{
					}
				}
			}
			if (oHeaders.ExistsAndContains("Content-Type", "application/x-www-form-urlencoded"))
			{
				string sSniffArea2 = sniffedEncoding.GetString(oBody, 0, Math.Min(4096, oBody.Length));
				Regex r2 = new Regex(".*_charset_=(?<thecharset>[^'&>\\\"]*)", RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture);
				MatchCollection mc2 = r2.Matches(sSniffArea2);
				if (mc2.Count > 0 && mc2[0].Groups.Count > 0)
				{
					string sEncoding3 = null;
					try
					{
						sEncoding3 = mc2[0].Groups[1].Value;
						Encoding oEnc2 = GetTextEncoding(sEncoding3);
						sniffedEncoding = oEnc2;
					}
					catch (Exception)
					{
					}
				}
			}
			if (oHeaders.ExistsAndContains("Content-Type", "html"))
			{
				string sSniffArea = sniffedEncoding.GetString(oBody, 0, Math.Min(4096, oBody.Length));
				Regex r = new Regex("<meta\\s.*charset\\s*=\\s*['\\\"]?(?<thecharset>[^'>\\\"]*)", RegexOptions.IgnoreCase | RegexOptions.ExplicitCapture);
				MatchCollection mc1 = r.Matches(sSniffArea);
				if (mc1.Count > 0 && mc1[0].Groups.Count > 0)
				{
					string sEncoding2 = null;
					try
					{
						sEncoding2 = mc1[0].Groups[1].Value;
						Encoding oEnc = GetTextEncoding(sEncoding2);
						if (oEnc != sniffedEncoding && (sniffedEncoding != Encoding.UTF8 || (oEnc != Encoding.BigEndianUnicode && oEnc != Encoding.Unicode && oEnc != Encoding.UTF32)) && (oEnc != Encoding.UTF8 || (sniffedEncoding != Encoding.BigEndianUnicode && sniffedEncoding != Encoding.Unicode && sniffedEncoding != Encoding.UTF32)))
						{
							sniffedEncoding = oEnc;
						}
					}
					catch (Exception)
					{
					}
				}
			}
		}
		return sniffedEncoding;
	}

	/// <summary>
	/// Gets (via Headers or Sniff) the Response Text Encoding. Returns CONFIG.oHeaderEncoding (usually UTF-8) if unknown.
	/// Perf: May be quite slow; cache the response
	/// </summary>
	/// <param name="oSession">The session</param>
	/// <returns>The encoding of the response body</returns>
	[CodeDescription("Gets (via Headers or Sniff) the Response Text Encoding. Returns CONFIG.oHeaderEncoding (usually UTF-8) if unknown. Potentially slow.")]
	public static Encoding getResponseBodyEncoding(Session oSession)
	{
		if (oSession == null)
		{
			return CONFIG.oHeaderEncoding;
		}
		if (!oSession.bHasResponse)
		{
			return CONFIG.oHeaderEncoding;
		}
		return getEntityBodyEncoding(oSession.oResponse.headers, oSession.responseBodyBytes);
	}

	/// <summary>
	/// HtmlEncode a string.
	/// In Fiddler itself, this is a simple wrapper for the System.Web.HtmlEncode function.
	/// The .NET3.5/4.0 Client Profile doesn't include System.Web, so we must provide our
	/// own implementation of HtmlEncode for FiddlerCore's use.
	/// </summary>
	/// <param name="sInput">String to encode</param>
	/// <returns>String encoded according to the rules of HTML Encoding, or null.</returns>
	public static string HtmlEncode(string sInput)
	{
		if (sInput == null)
		{
			return null;
		}
		return WebUtility.HtmlEncode(sInput);
	}

	private static int HexToByte(char h)
	{
		if (h >= '0' && h <= '9')
		{
			return h - 48;
		}
		if (h >= 'a' && h <= 'f')
		{
			return h - 97 + 10;
		}
		if (h >= 'A' && h <= 'F')
		{
			return h - 65 + 10;
		}
		return -1;
	}

	private static bool IsHexDigit(char ch)
	{
		if ((ch < '0' || ch > '9') && (ch < 'A' || ch > 'F'))
		{
			return ch >= 'a' && ch <= 'f';
		}
		return true;
	}

	/// <summary>
	/// This function accepts a string and an offset into the string. It reads one or more %XX sequences from the
	/// string converting them into a UTF-8 string based on the input text
	/// </summary>
	/// <param name="sInput"></param>
	/// <param name="iX"></param>
	/// <returns></returns>
	private static string GetUTF8HexString(string sInput, ref int iX)
	{
		MemoryStream oMS = new MemoryStream();
		do
		{
			if (iX > sInput.Length - 2)
			{
				oMS.WriteByte(37);
				iX += 2;
			}
			else if (IsHexDigit(sInput[iX + 1]) && IsHexDigit(sInput[iX + 2]))
			{
				byte oByte = (byte)((HexToByte(sInput[iX + 1]) << 4) + HexToByte(sInput[iX + 2]));
				oMS.WriteByte(oByte);
				iX += 3;
			}
			else
			{
				oMS.WriteByte(37);
				iX++;
			}
		}
		while (iX < sInput.Length && '%' == sInput[iX]);
		iX--;
		return Encoding.UTF8.GetString(oMS.ToArray());
	}

	/// <summary>
	/// Convert the %-encoded string into a string, interpreting %-escape sequences as UTF-8 characters
	/// </summary>
	/// <param name="sInput">%-encoded string</param>
	/// <returns>Unencoded string</returns>
	public static string UrlDecode(string sInput)
	{
		if (string.IsNullOrEmpty(sInput))
		{
			return string.Empty;
		}
		if (sInput.IndexOf('%') < 0)
		{
			return sInput;
		}
		StringBuilder sbOutput = new StringBuilder(sInput.Length);
		for (int iX = 0; iX < sInput.Length; iX++)
		{
			if ('%' == sInput[iX])
			{
				sbOutput.Append(GetUTF8HexString(sInput, ref iX));
			}
			else
			{
				sbOutput.Append(sInput[iX]);
			}
		}
		return sbOutput.ToString();
	}

	private static string UrlEncodeChars(string str, Encoding oEnc)
	{
		if (string.IsNullOrEmpty(str))
		{
			return str;
		}
		StringBuilder sbURI = new StringBuilder();
		foreach (char c in str)
		{
			if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '(' || c == ')' || c == '*' || c == '\'' || c == '_' || c == '!')
			{
				sbURI.Append(c);
				continue;
			}
			if (c == ' ')
			{
				sbURI.Append("+");
				continue;
			}
			byte[] oArr = oEnc.GetBytes(new char[1] { c });
			byte[] array = oArr;
			foreach (byte b in array)
			{
				sbURI.Append("%");
				sbURI.Append(b.ToString("X2"));
			}
		}
		return sbURI.ToString();
	}

	public static string UrlEncode(string sInput)
	{
		return UrlEncodeChars(sInput, Encoding.UTF8);
	}

	public static string UrlEncode(string sInput, Encoding oEnc)
	{
		return UrlEncodeChars(sInput, oEnc);
	}

	private static string UrlPathEncodeChars(string str)
	{
		if (string.IsNullOrEmpty(str))
		{
			return str;
		}
		StringBuilder sbURI = new StringBuilder();
		foreach (char c in str)
		{
			if (c > ' ' && c < '\u007f')
			{
				sbURI.Append(c);
				continue;
			}
			if (c < '!')
			{
				sbURI.Append("%");
				sbURI.Append(((byte)c).ToString("X2"));
				continue;
			}
			byte[] oArr = Encoding.UTF8.GetBytes(new char[1] { c });
			byte[] array = oArr;
			foreach (byte b in array)
			{
				sbURI.Append("%");
				sbURI.Append(b.ToString("X2"));
			}
		}
		return sbURI.ToString();
	}

	/// <summary>
	/// Replaces System.Web.HttpUtility.UrlPathEncode(str).
	/// </summary>
	/// <param name="str">String to encode as a URL Path</param>
	/// <returns>Encoded string</returns>
	public static string UrlPathEncode(string str)
	{
		if (string.IsNullOrEmpty(str))
		{
			return str;
		}
		int iX = str.IndexOf('?');
		if (iX >= 0)
		{
			return UrlPathEncode(str.Substring(0, iX)) + str.Substring(iX);
		}
		return UrlPathEncodeChars(str);
	}

	[CodeDescription("Tokenize a string into tokens. Delimits on whitespace; \" marks are dropped unless preceded by \\ characters.")]
	public static string[] Parameterize(string sInput)
	{
		return Parameterize(sInput, bAllowSQuote: false);
	}

	/// <summary>
	/// Tokenize a string into tokens. Delimits on unquoted whitespace ; quote marks are dropped unless preceded by \ characters.
	/// Some special hackery to allow trailing slash not escape the final character of the entire input, so that:
	///       prefs set fiddler.config.path.vsplugins "F:\users\ericlaw\VSWebTest\"
	/// ...doesn't end up with a trailing quote.
	/// </summary>
	/// <param name="sInput">The string to tokenize</param>
	/// <param name="bAllowSQuote">Are single-quotes allowed to as escapes?</param>
	/// <returns>An array of strings</returns>
	[CodeDescription("Tokenize a string into tokens. Delimits on whitespace; \" marks are dropped unless preceded by \\ characters.")]
	public static string[] Parameterize(string sInput, bool bAllowSQuote)
	{
		List<string> oTokens = new List<string>();
		bool bInDQuotes = false;
		bool bInSQuotes = false;
		StringBuilder sbCurrentToken = new StringBuilder();
		for (int ix = 0; ix < sInput.Length; ix++)
		{
			switch (sInput[ix])
			{
			case '\'':
				if (!bAllowSQuote || bInDQuotes)
				{
					sbCurrentToken.Append(sInput[ix]);
				}
				else if (ix > 0 && sInput[ix - 1] == '\\')
				{
					sbCurrentToken.Length--;
					sbCurrentToken.Append('\'');
				}
				else
				{
					bInSQuotes = !bInSQuotes;
				}
				break;
			case '"':
				if (bInSQuotes)
				{
					sbCurrentToken.Append(sInput[ix]);
				}
				else if (ix > 0 && sInput[ix - 1] == '\\' && (!bInDQuotes || ix != sInput.Length - 1))
				{
					sbCurrentToken.Length--;
					sbCurrentToken.Append('"');
				}
				else
				{
					bInDQuotes = !bInDQuotes;
				}
				break;
			case '\t':
			case ' ':
				if (!bInDQuotes && !bInSQuotes)
				{
					if (sbCurrentToken.Length > 0 || (ix > 0 && sInput[ix - 1] == '"'))
					{
						oTokens.Add(sbCurrentToken.ToString());
						sbCurrentToken.Length = 0;
					}
				}
				else
				{
					sbCurrentToken.Append(sInput[ix]);
				}
				break;
			default:
				sbCurrentToken.Append(sInput[ix]);
				break;
			}
		}
		if (sbCurrentToken.Length > 0)
		{
			oTokens.Add(sbCurrentToken.ToString());
		}
		return oTokens.ToArray();
	}

	internal static string ExtractAttributeValue(string sFullValue, string sAttribute)
	{
		string sResult = null;
		sAttribute = Regex.Escape(sAttribute);
		Regex r = new Regex("(?:^" + sAttribute + "|[^\\w-=\"]" + sAttribute + ")\\s?=\\s?[\"]?(?<TokenValue>[^\";]*)", RegexOptions.IgnoreCase);
		Match i = r.Match(sFullValue);
		if (i.Success && i.Groups["TokenValue"] != null)
		{
			sResult = i.Groups["TokenValue"].Value;
		}
		return sResult;
	}

	internal static long ExtractAttributeValue(string sFullValue, string sAttribute, long lngDefault)
	{
		long lngResult = lngDefault;
		string sResult = null;
		sAttribute = Regex.Escape(sAttribute);
		Regex r = new Regex("(?:^" + sAttribute + "|[^\\w-=\"]" + sAttribute + ")\\s?=\\s?[\"]?(?<TokenValue>[\\d]*)", RegexOptions.IgnoreCase);
		Match i = r.Match(sFullValue);
		if (i.Success && i.Groups["TokenValue"] != null)
		{
			sResult = i.Groups["TokenValue"].Value;
			if (!long.TryParse(sResult, out lngResult))
			{
				lngResult = lngDefault;
			}
		}
		return lngResult;
	}

	/// <summary>
	/// Pretty-print a Hex view of a byte array. Slow.
	/// </summary>
	/// <param name="inArr">The byte array</param>
	/// <param name="iBytesPerLine">Number of bytes per line</param>
	/// <returns>String containing a pretty-printed array</returns>
	[CodeDescription("Returns a string representing a Hex view of a byte array. Slow.")]
	public static string ByteArrayToHexView(byte[] inArr, int iBytesPerLine)
	{
		return HexViewHelper.ByteArrayToHexView(inArr, iBytesPerLine);
	}

	/// <summary>
	/// Pretty-print a Hex view of a byte array. Slow.
	/// </summary>
	/// <param name="inArr">The byte array</param>
	/// <param name="iBytesPerLine">Number of bytes per line</param>
	/// <param name="iMaxByteCount">The maximum number of bytes to pretty-print</param>
	/// <returns>String containing a pretty-printed array</returns>
	[CodeDescription("Returns a string representing a Hex view of a byte array. PERF: Slow.")]
	public static string ByteArrayToHexView(byte[] inArr, int iBytesPerLine, int iMaxByteCount)
	{
		return HexViewHelper.ByteArrayToHexView(inArr, iBytesPerLine, iMaxByteCount);
	}

	/// <summary>
	/// Pretty-print a Hex view of a byte array. Slow.
	/// </summary>
	/// <param name="inArr">The byte array</param>
	/// <param name="iBytesPerLine">Number of bytes per line</param>
	/// <param name="iMaxByteCount">The maximum number of bytes to pretty-print</param>
	/// <param name="bShowASCII">Show ASCII text at the end of each line</param>
	/// <returns>String containing a pretty-printed array</returns>
	[CodeDescription("Returns a string representing a Hex view of a byte array. PERF: Slow.")]
	public static string ByteArrayToHexView(byte[] inArr, int iBytesPerLine, int iMaxByteCount, bool bShowASCII)
	{
		return HexViewHelper.ByteArrayToHexView(inArr, iBytesPerLine, iMaxByteCount, bShowASCII);
	}

	[CodeDescription("Returns a string representing a Hex view of a byte array. PERF: Slow.")]
	public static string ByteArrayToHexView(byte[] inArr, int iStartAt, int iBytesPerLine, int iMaxByteCount, bool bShowASCII)
	{
		return HexViewHelper.ByteArrayToHexView(inArr, iStartAt, iBytesPerLine, iMaxByteCount, bShowASCII);
	}

	/// <summary>
	/// Print an byte array to a hex string.
	/// Slow.
	/// </summary>
	/// <param name="inArr">Byte array</param>
	/// <returns>String of hex bytes, or "null"/"empty" if no bytes provided</returns>
	[CodeDescription("Returns a string representing a Hex stream of a byte array. Slow.")]
	public static string ByteArrayToString(byte[] inArr)
	{
		if (inArr == null)
		{
			return "null";
		}
		if (inArr.Length == 0)
		{
			return "empty";
		}
		return BitConverter.ToString(inArr).Replace('-', ' ');
	}

	/// <summary>
	/// Create a string in CF_HTML format
	/// </summary>
	/// <param name="inStr">The HTML string</param>
	/// <returns>The HTML string wrapped with a CF_HTML prelude</returns>
	internal static string StringToCF_HTML(string inStr)
	{
		string sHTML = "<HTML><HEAD><STYLE>.REQUEST { font: 8pt Courier New; color: blue;} .RESPONSE { font: 8pt Courier New; color: green;}</STYLE></HEAD><BODY>" + inStr + "</BODY></HTML>";
		string sWrapper = "Version:1.0\r\nStartHTML:{0:00000000}\r\nEndHTML:{1:00000000}\r\nStartFragment:{0:00000000}\r\nEndFragment:{1:00000000}\r\n";
		return string.Format(sWrapper, sWrapper.Length - 16, sHTML.Length + sWrapper.Length - 16) + sHTML;
	}

	/// <summary>
	/// Returns an integer from the registry, or a default.
	/// </summary>
	/// <param name="oReg">The Registry key in which to find the value.</param>
	/// <param name="sName">The registry value name.</param>
	/// <param name="iDefault">Default to return if the registry key is missing or cannot be used as an integer</param>
	/// <returns>The retrieved integer, or the default.</returns>
	[CodeDescription("Returns an integer from the registry, or iDefault if the registry key is missing or cannot be used as an integer.")]
	public static int GetRegistryInt(RegistryKey oReg, string sName, int iDefault)
	{
		int retVal = iDefault;
		object o = oReg.GetValue(sName);
		if (o is int)
		{
			retVal = (int)o;
		}
		else if (o is string strVal && !int.TryParse(strVal, out retVal))
		{
			return iDefault;
		}
		return retVal;
	}

	/// <summary>
	/// Save a string to the registry. Correctly handles null Value, saving as String.Empty
	/// </summary>
	/// <param name="oReg">The registry key into which the value will be written.</param>
	/// <param name="sName">The name of the value.</param>
	/// <param name="sValue">The value to write.</param>
	[CodeDescription("Save a string to the registry. Correctly handles null Value, saving as String.Empty.")]
	public static void SetRegistryString(RegistryKey oReg, string sName, string sValue)
	{
		if (sName != null)
		{
			if (sValue == null)
			{
				sValue = string.Empty;
			}
			oReg.SetValue(sName, sValue);
		}
	}

	/// <summary>
	/// Returns an Float from the registry, or a default.
	/// </summary>
	/// <param name="oReg">Registry key in which to find the value.</param>
	/// <param name="sName">The value name.</param>
	/// <param name="flDefault">The default float value if the registry key is missing or cannot be used as a float.</param>
	/// <returns>Float representing the value, or the default.</returns>
	[CodeDescription("Returns an float from the registry, or flDefault if the registry key is missing or cannot be used as an float.")]
	public static float GetRegistryFloat(RegistryKey oReg, string sName, float flDefault)
	{
		float retVal = flDefault;
		object o = oReg.GetValue(sName);
		if (o is int)
		{
			retVal = (float)o;
		}
		else if (o is string strVal && !float.TryParse(strVal, NumberStyles.Float, CultureInfo.InvariantCulture, out retVal))
		{
			retVal = flDefault;
		}
		return retVal;
	}

	/// <summary>
	/// Get a bool from the registry
	/// </summary>
	/// <param name="oReg">The RegistryKey</param>
	/// <param name="sName">The Value name</param>
	/// <param name="bDefault">The default value</param>
	/// <returns>Returns an bool from the registry, or bDefault if the registry key is missing or cannot be used as an bool.</returns>
	[CodeDescription("Returns an bool from the registry, or bDefault if the registry key is missing or cannot be used as an bool.")]
	public static bool GetRegistryBool(RegistryKey oReg, string sName, bool bDefault)
	{
		bool retVal = bDefault;
		object o = oReg.GetValue(sName);
		if (o is int)
		{
			retVal = 1 == (int)o;
		}
		else if (o is string strVal)
		{
			retVal = "true".OICEquals(strVal);
		}
		return retVal;
	}

	/// <summary>
	/// Maps a MIMEType to a file extension.
	/// Pass only the TYPE (e.g. use oResponse.MIMEType), to ensure no charset info in the string. 
	/// </summary>
	/// <param name="mime">The MIME Type</param>
	/// <returns>A file extension for the type, or .TXT</returns>
	internal static string FileExtensionForMIMEType(string mime)
	{
		string fileExtension = MimeMappingsProvider.Instance.GetFileExtension(mime);
		if (string.IsNullOrWhiteSpace(fileExtension))
		{
			fileExtension = ((!mime.EndsWith("+xml")) ? ".txt" : ".xml");
		}
		return fileExtension;
	}

	internal static string GetFirstPathComponent(string sPath)
	{
		int iXPathComp2 = IndexOfNth(sPath, 2, '/');
		if (iXPathComp2 > 1)
		{
			sPath = "/" + TrimBefore(TrimTo(sPath, iXPathComp2 + 1), "/");
		}
		else
		{
			iXPathComp2 = sPath.IndexOf('?');
			if (iXPathComp2 > 0)
			{
				sPath = "/" + TrimBefore(TrimTo(sPath, iXPathComp2), "/");
			}
			else if (!sPath.StartsWith("/"))
			{
				sPath = string.Empty;
			}
		}
		return sPath;
	}

	/// <summary>
	/// Return the content type of a target file, or application/octet-stream if unknown.
	/// </summary>
	/// <param name="sFilename">A filename, including the extension</param>
	/// <returns></returns>
	public static string ContentTypeForFilename(string sFilename)
	{
		string sFileExt = string.Empty;
		try
		{
			sFileExt = Path.GetExtension(sFilename);
		}
		catch (Exception)
		{
			return "application/octet-stream";
		}
		string sResult = MimeMappingsProvider.Instance.GetMimeType(sFileExt);
		if (string.IsNullOrEmpty(sResult))
		{
			return "application/octet-stream";
		}
		return sResult;
	}

	internal static bool IsChunkedBodyComplete(Session m_session, byte[] oRawBuffer, long iStartAtOffset, long iEndAtOffset, out long outStartOfLatestChunk, out long outEndOfEntity)
	{
		int iPtr = (int)iStartAtOffset;
		outStartOfLatestChunk = iPtr;
		outEndOfEntity = -1L;
		while (iPtr < iEndAtOffset)
		{
			outStartOfLatestChunk = iPtr;
			string sChunkSize = Encoding.ASCII.GetString(oRawBuffer, iPtr, Math.Min(64, (int)(iEndAtOffset - iPtr)));
			int iTrim = sChunkSize.IndexOf("\r\n", StringComparison.Ordinal);
			if (iTrim > -1)
			{
				iPtr += iTrim + 2;
				sChunkSize = sChunkSize.Substring(0, iTrim);
				sChunkSize = TrimAfter(sChunkSize, ';');
				int iChunkSize = 0;
				if (!TryHexParse(sChunkSize, out iChunkSize))
				{
					if (m_session != null)
					{
						SessionFlags oErrorFlag = ((m_session.state <= SessionStates.ReadingRequest) ? SessionFlags.ProtocolViolationInRequest : SessionFlags.ProtocolViolationInResponse);
						FiddlerApplication.HandleHTTPError(m_session, oErrorFlag, bPoisonClientConnection: true, bPoisonServerConnection: true, "Illegal chunked encoding. '" + sChunkSize + "' is not a hexadecimal number.");
					}
					return true;
				}
				if (iChunkSize == 0)
				{
					bool bLastSequenceWasCRLF = true;
					bool bLastCharWasCR = false;
					if (iEndAtOffset < iPtr + 2)
					{
						return false;
					}
					while (iPtr < iEndAtOffset)
					{
						switch (oRawBuffer[iPtr++])
						{
						case 13:
							bLastCharWasCR = true;
							break;
						case 10:
							if (bLastCharWasCR)
							{
								if (bLastSequenceWasCRLF)
								{
									outEndOfEntity = iPtr;
									return true;
								}
								bLastSequenceWasCRLF = true;
								bLastCharWasCR = false;
							}
							else
							{
								bLastCharWasCR = false;
								bLastSequenceWasCRLF = false;
							}
							break;
						default:
							bLastCharWasCR = false;
							bLastSequenceWasCRLF = false;
							break;
						}
					}
					return false;
				}
				iPtr += iChunkSize + 2;
				continue;
			}
			return false;
		}
		return false;
	}

	/// <summary>
	/// Determines if we have a complete chunked response body (RFC2616 Section 3.6.1)
	/// </summary>
	/// <param name="m_session">The session object, used for error reporting</param>
	/// <param name="oData">The response data stream. Note: We do not touch the POSITION property.</param>
	/// <param name="iStartAtOffset">The start of the HTTP body to scan for chunk size info</param>
	/// <param name="outStartOfLatestChunk">Returns the start of the final received/partial chunk</param>
	/// <param name="outEndOfEntity">End of byte data in stream representing this chunked content, or -1 if error</param>
	/// <returns>True, if we've found the complete last chunk, false otherwise.</returns>
	internal static bool IsChunkedBodyComplete(Session m_session, MemoryStream oData, long iStartAtOffset, out long outStartOfLatestChunk, out long outEndOfEntity)
	{
		return IsChunkedBodyComplete(m_session, oData.GetBuffer(), iStartAtOffset, oData.Length, out outStartOfLatestChunk, out outEndOfEntity);
	}

	private static void _WriteChunkSizeToStream(MemoryStream oMS, int iLen)
	{
		byte[] theSizeArr = Encoding.ASCII.GetBytes(iLen.ToString("x"));
		oMS.Write(theSizeArr, 0, theSizeArr.Length);
	}

	private static void _WriteCRLFToStream(MemoryStream oMS)
	{
		oMS.WriteByte(13);
		oMS.WriteByte(10);
	}

	/// <summary>
	/// Takes a byte array and applies HTTP Chunked Transfer Encoding to it
	/// </summary>
	/// <param name="writeData">The byte array to convert</param>
	/// <param name="iSuggestedChunkCount">The number of chunks to try to create</param>
	/// <returns>The byte array with Chunked Transfer Encoding applied</returns>
	public static byte[] doChunk(byte[] writeData, int iSuggestedChunkCount)
	{
		if (writeData == null || writeData.Length < 1)
		{
			return Encoding.ASCII.GetBytes("0\r\n\r\n");
		}
		if (iSuggestedChunkCount < 1)
		{
			iSuggestedChunkCount = 1;
		}
		if (iSuggestedChunkCount > writeData.Length)
		{
			iSuggestedChunkCount = writeData.Length;
		}
		MemoryStream oMS = new MemoryStream(writeData.Length + 10 * iSuggestedChunkCount);
		int iPtr = 0;
		do
		{
			int iBytesRemaining = writeData.Length - iPtr;
			int iNextChunkSize = iBytesRemaining / iSuggestedChunkCount;
			iNextChunkSize = Math.Max(1, iNextChunkSize);
			iNextChunkSize = Math.Min(iBytesRemaining, iNextChunkSize);
			_WriteChunkSizeToStream(oMS, iNextChunkSize);
			_WriteCRLFToStream(oMS);
			oMS.Write(writeData, iPtr, iNextChunkSize);
			_WriteCRLFToStream(oMS);
			iPtr += iNextChunkSize;
			iSuggestedChunkCount--;
			if (iSuggestedChunkCount < 1)
			{
				iSuggestedChunkCount = 1;
			}
		}
		while (iPtr < writeData.Length);
		_WriteChunkSizeToStream(oMS, 0);
		_WriteCRLFToStream(oMS);
		_WriteCRLFToStream(oMS);
		return oMS.ToArray();
	}

	/// <summary>
	/// Removes HTTP chunked encoding from the data in writeData and returns the resulting array.
	/// </summary>
	/// <param name="writeData">Some chunked data</param>
	/// <returns>Unchunked data. Throws InvalidDataException on data format errors.</returns>
	public static byte[] doUnchunk(byte[] writeData)
	{
		return doUnchunk(writeData, null, bNoUI: true);
	}

	/// <summary>
	/// Removes HTTP chunked encoding from the data in writeData and returns the resulting array.
	/// </summary>
	/// <param name="writeData">Array to unchunk</param>
	/// <param name="oS">Optional Session (for UI error messages)</param>
	/// <param name="bNoUI">TRUE to suppress error messages, FALSE to show alert boxes</param>
	/// <returns>Unchunked data. Throws InvalidDataException on data format errors.</returns>
	internal static byte[] doUnchunk(byte[] writeData, Session oS, bool bNoUI)
	{
		if (writeData == null || writeData.Length == 0)
		{
			return emptyByteArray;
		}
		MemoryStream oUnchunked = new MemoryStream(writeData.Length);
		int iPtr = 0;
		bool bDone = false;
		while (!bDone && iPtr <= writeData.Length - 3)
		{
			int ixCRLF;
			for (ixCRLF = iPtr; ixCRLF < writeData.Length - 1 && 13 != writeData[ixCRLF] && 10 != writeData[ixCRLF + 1]; ixCRLF++)
			{
			}
			if (ixCRLF > writeData.Length - 2)
			{
				throw new InvalidDataException("HTTP Error: The chunked content is corrupt. Cannot find Chunk-Length in expected location. Offset: " + iPtr);
			}
			string sChunkSize = Encoding.ASCII.GetString(writeData, iPtr, ixCRLF - iPtr);
			iPtr = ixCRLF + 2;
			sChunkSize = TrimAfter(sChunkSize, ';');
			if (!TryHexParse(sChunkSize, out var iChunkSize))
			{
				throw new InvalidDataException("HTTP Error: The chunked content is corrupt. Chunk Length was malformed. Offset: " + iPtr);
			}
			if (iChunkSize == 0)
			{
				bDone = true;
				continue;
			}
			if (writeData.Length < iChunkSize + iPtr)
			{
				throw new InvalidDataException("HTTP Error: The chunked entity body is corrupt. The final chunk length is greater than the number of bytes remaining.");
			}
			oUnchunked.Write(writeData, iPtr, iChunkSize);
			iPtr += iChunkSize + 2;
		}
		if (!bDone)
		{
			FiddlerApplication.Log.LogFormat("{0}Chunked body did not terminate properly with 0-sized chunk.", (oS != null) ? $"Session #{oS.id} -" : string.Empty);
		}
		byte[] result = new byte[oUnchunked.Length];
		Buffer.BlockCopy(oUnchunked.GetBuffer(), 0, result, 0, result.Length);
		return result;
	}

	/// <summary>
	/// Returns TRUE if the Array contains nulls. TODO: Extend to check for other chars which are clearly non-Unicode
	/// </summary>
	/// <param name="arrIn"></param>
	/// <returns></returns>
	internal static bool arrayContainsNonText(byte[] arrIn)
	{
		if (arrIn == null)
		{
			return false;
		}
		for (int i = 0; i < arrIn.Length; i++)
		{
			if (arrIn[i] == 0)
			{
				return true;
			}
		}
		return false;
	}

	/// <summary>
	/// Implements a BlockList for "unknown" encodings that the utilDecode* functions cannot handle
	/// </summary>
	/// <param name="sTE">Transfer-Encoding</param>
	/// <param name="sCE">Content-Encoding</param>
	/// <returns>TRUE if any encoding is known to be unsupported</returns>
	public static bool isUnsupportedEncoding(string sTE, string sCE)
	{
		if (!string.IsNullOrEmpty(sTE))
		{
			if (sTE.OICContains("xpress"))
			{
				return !FiddlerApplication.Supports("xpress");
			}
			if (sTE.OICContains("sdch"))
			{
				return true;
			}
		}
		if (!string.IsNullOrEmpty(sCE))
		{
			if (sCE.OICContains("xpress"))
			{
				return !FiddlerApplication.Supports("xpress");
			}
			if (sCE.OICContains("sdch"))
			{
				return true;
			}
		}
		return false;
	}

	/// <summary>
	/// Removes one or more encodings in the proper order to reconstruct the unencoded body.
	/// If removing Transfer-Encoding and Content-Encoding, ALWAYS remove Transfer-Encoding first.
	/// </summary>
	/// <param name="sEncodingsInOrder">The list of encodings in the order that they were applied 
	/// RFC2616: If multiple encodings have been applied to an entity, the content codings MUST be listed in the order in which they were applied.</param>
	/// <param name="bAllowChunks">Should unchunking be permitted (TRUE for Transfer-Encoding, FALSE for Content-Encoding)</param>
	/// <param name="arrBody">The bytes of the body</param>
	private static void _DecodeInOrder(string sEncodingsInOrder, bool bAllowChunks, ref byte[] arrBody, bool bNoUI)
	{
		if (string.IsNullOrEmpty(sEncodingsInOrder))
		{
			return;
		}
		string[] sEncs = sEncodingsInOrder.ToLower().Split(new char[1] { ',' }, StringSplitOptions.RemoveEmptyEntries);
		for (int iEnc = sEncs.Length - 1; iEnc >= 0; iEnc--)
		{
			string sEnc = sEncs[iEnc].Trim();
			switch (sEnc)
			{
			case "gzip":
				arrBody = GzipExpand(arrBody, bNoUI);
				continue;
			case "deflate":
				arrBody = DeflaterExpand(arrBody, bNoUI);
				continue;
			case "bzip2":
				arrBody = bzip2Expand(arrBody, bNoUI);
				continue;
			case "br":
				if (!FiddlerApplication.Supports("br"))
				{
					break;
				}
				try
				{
					arrBody = BrotliExpand(arrBody);
				}
				catch (Exception eX)
				{
					FiddlerApplication.Log.LogFormat("!Cannot decode HTTP response using Encoding: {0}; error: {1}", sEnc, FiddlerCore.Utilities.Utilities.DescribeException(eX));
					break;
				}
				continue;
			case "xpress":
				if (!FiddlerApplication.Supports("xpress"))
				{
					break;
				}
				try
				{
					arrBody = XpressExpand(arrBody);
				}
				catch (Exception eX2)
				{
					FiddlerApplication.Log.LogFormat("!Cannot decode HTTP response using Encoding: {0}; error: {1}", sEnc, FiddlerCore.Utilities.Utilities.DescribeException(eX2));
				}
				continue;
			case "chunked":
				if (bAllowChunks)
				{
					if (iEnc != sEncs.Length - 1)
					{
						FiddlerApplication.Log.LogFormat("!Chunked Encoding must be the LAST Transfer-Encoding applied!", sEncodingsInOrder);
					}
					arrBody = doUnchunk(arrBody, null, bNoUI);
				}
				else
				{
					FiddlerApplication.Log.LogFormat("!Chunked encoding is permitted only in the Transfer-Encoding header. Content-Encoding: {0}", sEnc);
				}
				continue;
			case "none":
			case "identity":
				continue;
			}
			FiddlerApplication.Log.LogFormat("!Cannot decode HTTP response using Encoding: {0}", sEnc);
		}
	}

	/// <summary>
	/// Content-Encodings
	/// </summary>
	/// <param name="sEncodingsInOrder"></param>
	/// <param name="sRemainingEncodings"></param>
	/// <param name="arrBody"></param>
	/// <param name="bNoUI"></param>
	/// <returns></returns>
	private static bool _TryContentDecode(string sEncodingsInOrder, out string sRemainingEncodings, ref byte[] arrBody, bool bNoUI)
	{
		if (string.IsNullOrEmpty(sEncodingsInOrder))
		{
			sRemainingEncodings = null;
			return false;
		}
		string[] sEncs = sEncodingsInOrder.ToLower().Split(new char[1] { ',' }, StringSplitOptions.RemoveEmptyEntries);
		for (int iEnc = sEncs.Length - 1; iEnc >= 0; iEnc--)
		{
			string sEnc = sEncs[iEnc].Trim();
			switch (sEnc)
			{
			case "gzip":
				arrBody = GzipExpand(arrBody, bNoUI);
				continue;
			case "deflate":
				arrBody = DeflaterExpand(arrBody, bNoUI);
				continue;
			case "br":
				if (!FiddlerApplication.Supports("br"))
				{
					break;
				}
				try
				{
					arrBody = BrotliExpand(arrBody);
				}
				catch (Exception eX)
				{
					FiddlerApplication.Log.LogFormat("!Cannot decode HTTP response using Encoding: {0}; error: {1}", sEnc, FiddlerCore.Utilities.Utilities.DescribeException(eX));
					break;
				}
				continue;
			case "bzip2":
				arrBody = bzip2Expand(arrBody, bNoUI);
				continue;
			case "xpress":
				if (!FiddlerApplication.Supports("xpress"))
				{
					break;
				}
				try
				{
					arrBody = XpressExpand(arrBody);
				}
				catch (Exception eX2)
				{
					FiddlerApplication.Log.LogFormat("!Cannot decode HTTP response using Encoding: {0}; error: {1}", sEnc, FiddlerCore.Utilities.Utilities.DescribeException(eX2));
					break;
				}
				continue;
			case "chunked":
				FiddlerApplication.Log.LogFormat("!Chunked encoding is permitted only in the Transfer-Encoding header. Content-Encoding: {0}", sEnc);
				break;
			case "none":
			case "identity":
				continue;
			}
			FiddlerApplication.Log.LogFormat("!Cannot decode HTTP response using Content-Encoding: {0}", sEnc);
			sRemainingEncodings = string.Join(",", sEncs, 0, iEnc + 1);
			return false;
		}
		sRemainingEncodings = null;
		return true;
	}

	/// <summary>
	/// Remove all encodings from arrBody, based on those specified in the supplied HTTP headers; DOES NOT MODIFY HEADERS.
	/// Throws on errors.
	/// </summary>
	/// <param name="oHeaders">*Readonly* headers specifying what encodings are applied</param>
	/// <param name="arrBody">In/Out array to be modified</param>
	public static void utilDecodeHTTPBody(HTTPHeaders oHeaders, ref byte[] arrBody)
	{
		utilDecodeHTTPBody(oHeaders, ref arrBody, bSilent: false);
	}

	/// <summary>
	/// Remove all encodings from arrBody, based on those specified in the supplied HTTP headers; 
	/// DOES NOT MODIFY HEADERS. DOES NOT HANDLE UNSUPPORTED ENCODINGS WELL.
	/// Throws on errors.
	/// </summary>
	/// <param name="oHeaders">*Readonly* headers specifying what encodings are applied</param>
	/// <param name="arrBody">In/Out array to be modified</param>
	/// <param name="bSilent">FALSE to show dialog boxes on errors, TRUE to remain silent</param>
	public static void utilDecodeHTTPBody(HTTPHeaders oHeaders, ref byte[] arrBody, bool bSilent)
	{
		if (!IsNullOrEmpty(arrBody))
		{
			_DecodeInOrder(oHeaders["Transfer-Encoding"], bAllowChunks: true, ref arrBody, bSilent);
			_DecodeInOrder(oHeaders["Content-Encoding"], bAllowChunks: false, ref arrBody, bSilent);
		}
	}

	/// <summary>
	/// Attempts to remove all Content-Encodings from a HTTP body. May throw if content is malformed.
	/// MODIFIES HEADERS.
	/// </summary>
	/// <param name="oHeaders">Headers for the body; Content-Encoding and Content-Length will be modified</param>
	/// <param name="arrBody">Reference to the body array</param>
	/// <param name="bSilent">FALSE if error dialog boxes should be shown</param>
	/// <returns>TRUE if the body was decoded completely.</returns>
	internal static bool utilTryDecode(HTTPHeaders oHeaders, ref byte[] arrBody, bool bSilent)
	{
		string sRemainingCE = null;
		if (!IsNullOrEmpty(arrBody))
		{
			_DecodeInOrder(oHeaders.AllValues("Transfer-Encoding"), bAllowChunks: true, ref arrBody, bSilent);
			_TryContentDecode(oHeaders.AllValues("Content-Encoding"), out sRemainingCE, ref arrBody, bSilent);
		}
		oHeaders.RemoveRange(new string[2] { "Transfer-Encoding", "Content-Encoding" });
		if (!string.IsNullOrEmpty(sRemainingCE))
		{
			oHeaders["Content-Encoding"] = sRemainingCE;
		}
		oHeaders["Content-Length"] = ((arrBody == null) ? "0" : arrBody.LongLength.ToString());
		return string.IsNullOrEmpty(sRemainingCE);
	}

	/// <summary>
	/// Decompress an array compressed using an Zlib DEFLATE stream. Not a HTTP Encoding; it's used internally in the PNG format.
	/// </summary>
	/// <param name="compressedData">The array to expand</param>
	/// <returns>byte[] of decompressed data</returns>
	public static byte[] ZLibExpand(byte[] compressedData)
	{
		if (compressedData == null || compressedData.Length == 0)
		{
			return emptyByteArray;
		}
		return DeflaterExpandInternal(bUseXceed: false, compressedData);
	}

	public static byte[] BrotliExpand(byte[] arrIn)
	{
		string sTempFile = CONFIG.GetPath("Root") + "tmpToCompress" + Guid.NewGuid().ToString() + ".br";
		string sOutFile = sTempFile + ".dat";
		File.WriteAllBytes(sTempFile, arrIn);
		string sParams = $"-d --in \"{sTempFile}\" --out \"{sOutFile}\"";
		int iExitCode = 0;
		GetExecutableOutput(CONFIG.GetPath("Tools") + "brotli.exe", sParams, out iExitCode);
		if (iExitCode != 0)
		{
			throw new Exception("Brotli conversion failed");
		}
		byte[] arrOut = File.ReadAllBytes(sOutFile);
		try
		{
			File.Delete(sTempFile);
		}
		catch
		{
			FiddlerApplication.LogLeakedFile(sTempFile);
		}
		try
		{
			File.Delete(sOutFile);
		}
		catch
		{
			FiddlerApplication.LogLeakedFile(sOutFile);
		}
		return arrOut;
	}

	public static byte[] BrotliCompress(byte[] arrIn, out long elapsedMilliseconds)
	{
		string sTempFile = CONFIG.GetPath("Root") + "tmpToCompress" + DateTime.Now.ToString("h-m-s");
		string sOutFile = sTempFile + ".br";
		File.WriteAllBytes(sTempFile, arrIn);
		string sParams = string.Format("--in \"{0}\" --out \"{1}\" {2}", sTempFile, sOutFile, FiddlerApplication.Prefs.GetStringPref("fiddler.transformer.Brotli.ExtraArguments", null));
		int iExitCode = 0;
		Stopwatch oSW = Stopwatch.StartNew();
		GetExecutableOutput(CONFIG.GetPath("Tools") + "brotli.exe", sParams, out iExitCode);
		elapsedMilliseconds = oSW.ElapsedMilliseconds;
		if (iExitCode != 0)
		{
			throw new Exception("Brotli conversion failed");
		}
		byte[] arrOut = File.ReadAllBytes(sOutFile);
		try
		{
			File.Delete(sTempFile);
		}
		catch
		{
			FiddlerApplication.LogLeakedFile(sTempFile);
		}
		try
		{
			File.Delete(sOutFile);
		}
		catch
		{
			FiddlerApplication.LogLeakedFile(sOutFile);
		}
		return arrOut;
	}

	/// <summary>
	/// GZIPs a byte-array
	/// </summary>
	/// <param name="writeData">Input byte array</param>
	/// <returns>byte[] containing a gzip-compressed copy of writeData[]</returns>
	[CodeDescription("Returns a byte[] containing a gzip-compressed copy of writeData[]")]
	public static byte[] GzipCompress(byte[] writeData)
	{
		try
		{
			MemoryStream destinationStream = new MemoryStream();
			using (GZipStream gzipStream = new GZipStream(destinationStream, CompressionMode.Compress))
			{
				gzipStream.Write(writeData, 0, writeData.Length);
			}
			return destinationStream.ToArray();
		}
		catch (Exception e)
		{
			string title = "Fiddler: GZip failed";
			string message = "The content could not be compressed.\n\n" + e.Message;
			FiddlerApplication.Log.LogFormat("{0} - {1}", title, message);
			return writeData;
		}
	}

	/// <summary>
	/// GZIP-Expand function which shows no UI and will throw on error
	/// </summary>
	/// <param name="bUseXceed">TRUE if you want to use Xceed to decompress; false if you want to use System.IO</param>
	/// <param name="compressedData">byte[] to decompress</param>
	/// <returns>A decompressed byte array, or byte[0]. Throws on errors.</returns>
	public static byte[] GzipExpandInternal(bool bUseXceed, byte[] compressedData)
	{
		if (compressedData == null || compressedData.Length < 4)
		{
			return emptyByteArray;
		}
		MemoryStream sourceStream = new MemoryStream(compressedData, writable: false);
		int uiReportedOriginalSize = compressedData[^4] + (compressedData[^3] << 8) + (compressedData[^2] << 16) + (compressedData[^1] << 24);
		if (uiReportedOriginalSize < 0 || uiReportedOriginalSize > 40 * compressedData.Length)
		{
			uiReportedOriginalSize = compressedData.Length;
		}
		MemoryStream destinationStream = new MemoryStream(uiReportedOriginalSize);
		if (bUseXceed)
		{
			throw new NotSupportedException("This application was compiled without Xceed support.");
		}
		using (GZipStream gzip = new GZipStream(sourceStream, CompressionMode.Decompress))
		{
			byte[] buffer = new byte[32768];
			int bytesRead = 0;
			while ((bytesRead = gzip.Read(buffer, 0, buffer.Length)) > 0)
			{
				destinationStream.Write(buffer, 0, bytesRead);
			}
		}
		if (destinationStream.Length == 0L && compressedData.Length > 2 && compressedData[0] == 31 && compressedData[1] == 139 && compressedData[3] == 0 && (compressedData[^4] != 0 || compressedData[^3] != 0 || compressedData[^2] != 0 || compressedData[^1] != 0))
		{
			FiddlerApplication.Log.LogString("!ERROR: \"Content-Encoding: gzip\" body was missing required footer bytes.");
			byte[] arrBareDeflate = new byte[compressedData.Length - 10];
			Buffer.BlockCopy(compressedData, 10, arrBareDeflate, 0, arrBareDeflate.Length);
			return DeflaterExpand(arrBareDeflate, bThrowErrors: false);
		}
		if (destinationStream.Length == destinationStream.Capacity)
		{
			return destinationStream.GetBuffer();
		}
		return destinationStream.ToArray();
	}

	/// <summary>
	/// Expands a GZIP-compressed byte array
	/// </summary>
	/// <param name="compressedData">The array to decompress</param>
	/// <returns>byte[] containing an un-gzipped copy of compressedData[]</returns>
	[CodeDescription("Returns a byte[] containing an un-gzipped copy of compressedData[]")]
	public static byte[] GzipExpand(byte[] compressedData)
	{
		return GzipExpand(compressedData, bThrowErrors: false);
	}

	public static byte[] GzipExpand(byte[] compressedData, bool bThrowErrors)
	{
		try
		{
			return GzipExpandInternal(CONFIG.bUseXceedDecompressForGZIP, compressedData);
		}
		catch (Exception eX)
		{
			if (bThrowErrors)
			{
				throw new InvalidDataException("The content could not be ungzipped", eX);
			}
			string title = "Fiddler: UnGZip failed";
			string message = "The content could not be decompressed.\n\n" + eX.Message;
			FiddlerApplication.Log.LogFormat("{0} - {1}", title, message);
			return emptyByteArray;
		}
	}

	/// <summary>
	/// Compress a byte array using RFC1951 DEFLATE
	/// </summary>
	/// <param name="writeData">Array to compress</param>
	/// <returns>byte[] containing a DEFLATE'd copy of writeData[]</returns>
	[CodeDescription("Returns a byte[] containing a DEFLATE'd copy of writeData[]")]
	public static byte[] DeflaterCompress(byte[] writeData)
	{
		if (writeData == null || writeData.Length == 0)
		{
			return emptyByteArray;
		}
		try
		{
			MemoryStream destinationStream = new MemoryStream();
			using (DeflateStream deflateStream = new DeflateStream(destinationStream, CompressionMode.Compress))
			{
				deflateStream.Write(writeData, 0, writeData.Length);
			}
			return destinationStream.ToArray();
		}
		catch (Exception e)
		{
			string title = "Fiddler: Deflation failed";
			string message = "The content could not be compressed.\n\n" + e.Message;
			FiddlerApplication.Log.LogFormat("{0} - {1}", title, message);
			return writeData;
		}
	}

	/// <summary>
	/// UnDeflate function which shows no UI and will throw on error
	/// </summary>
	/// <param name="bUseXceed">TRUE if you want to use Xceed to decompress; false if you want to use System.IO</param>
	/// <param name="compressedData">byte[] to decompress</param>
	/// <returns>A decompressed byte array, or byte[0]. Throws on errors.</returns>
	public static byte[] DeflaterExpandInternal(bool bUseXceed, byte[] compressedData)
	{
		if (compressedData == null || compressedData.Length == 0)
		{
			return emptyByteArray;
		}
		int iStartOffset = 0;
		if (compressedData.Length > 2 && (compressedData[0] & 0xF) == 8 && (compressedData[0] & 0x80) == 0 && ((compressedData[0] << 8) + compressedData[1]) % 31 == 0)
		{
			iStartOffset = 2;
		}
		if (bUseXceed)
		{
			throw new NotSupportedException("This application was compiled without Xceed support.");
		}
		MemoryStream sourceStream = new MemoryStream(compressedData, iStartOffset, compressedData.Length - iStartOffset, writable: false);
		MemoryStream destinationStream = new MemoryStream(compressedData.Length);
		using (DeflateStream deflate = new DeflateStream(sourceStream, CompressionMode.Decompress))
		{
			byte[] buffer = new byte[32768];
			int bytesRead = 0;
			while ((bytesRead = deflate.Read(buffer, 0, buffer.Length)) > 0)
			{
				destinationStream.Write(buffer, 0, bytesRead);
			}
		}
		return destinationStream.ToArray();
	}

	/// <summary>
	/// Decompress a byte array that was compressed using Microsoft's Xpress Raw format.
	/// Available only on Windows 8+
	/// </summary>
	/// <param name="arrBlock">Array to decompress</param>
	/// <returns>byte[] of decompressed data</returns>
	public static byte[] XpressExpand(byte[] arrBlock)
	{
		IPlatformExtensions extensions = PlatformExtensionsFactory.Instance.CreatePlatformExtensions();
		return extensions.DecompressXpress(arrBlock);
	}

	/// <summary>
	/// Decompress a byte array that was compressed using RFC1951 DEFLATE 
	/// </summary>
	/// <param name="compressedData">Array to decompress</param>
	/// <returns>byte[] of decompressed data</returns>
	[CodeDescription("Returns a byte[] representing the INFLATE'd representation of compressedData[]")]
	public static byte[] DeflaterExpand(byte[] compressedData)
	{
		return DeflaterExpand(compressedData, bThrowErrors: false);
	}

	public static byte[] DeflaterExpand(byte[] compressedData, bool bThrowErrors)
	{
		try
		{
			return DeflaterExpandInternal(CONFIG.bUseXceedDecompressForDeflate, compressedData);
		}
		catch (Exception eX)
		{
			if (bThrowErrors)
			{
				throw new InvalidDataException("The content could not be inFlated", eX);
			}
			string title = "Fiddler: Inflation failed";
			string message = "The content could not be decompressed.\n\n" + eX.Message;
			FiddlerApplication.Log.LogFormat("{0} - {1}", title, message);
			return emptyByteArray;
		}
	}

	/// <summary>
	/// Compress a byte[] using the bzip2 algorithm
	/// </summary>
	/// <param name="writeData">Array to compress</param>
	/// <returns>byte[] of data compressed using bzip2</returns>
	[CodeDescription("Returns a byte[] representing the bzip2'd representation of writeData[]")]
	public static byte[] bzip2Compress(byte[] writeData)
	{
		if (writeData == null || writeData.Length == 0)
		{
			return emptyByteArray;
		}
		throw new NotSupportedException("This application was compiled without BZIP2 support.");
	}

	/// <summary>
	/// Decompress an array compressed using bzip2
	/// </summary>
	/// <param name="compressedData">The array to expand</param>
	/// <returns>byte[] of decompressed data</returns>
	public static byte[] bzip2Expand(byte[] compressedData)
	{
		return bzip2Expand(compressedData, bThrowErrors: false);
	}

	/// <summary>
	/// Decompress an array compressed using bzip2
	/// </summary>
	/// <param name="compressedData">The array to expand</param>
	/// <returns>byte[] of decompressed data</returns>
	public static byte[] bzip2Expand(byte[] compressedData, bool bThrowErrors)
	{
		if (compressedData == null || compressedData.Length == 0)
		{
			return emptyByteArray;
		}
		throw new NotSupportedException("This application was compiled without BZIP2 support.");
	}

	/// <summary>
	/// Try parsing the string for a Hex-formatted int. If it fails, return false and 0 in iOutput.
	/// </summary>
	/// <param name="sInput">The hex number</param>
	/// <param name="iOutput">The int value</param>
	/// <returns>TRUE if the parsing succeeded</returns>
	[CodeDescription("Try parsing the string for a Hex-formatted int. If it fails, return false and 0 in iOutput.")]
	public static bool TryHexParse(string sInput, out int iOutput)
	{
		return int.TryParse(sInput, NumberStyles.HexNumber, NumberFormatInfo.InvariantInfo, out iOutput);
	}

	/// <summary>
	/// Returns TRUE if two ORIGIN (scheme+host+port) values are functionally equivalent.
	/// </summary>
	/// <param name="sOrigin1">The first ORIGIN</param>
	/// <param name="sOrigin2">The second ORIGIN</param>
	/// <param name="iDefaultPort">The default port, if a port is not specified</param>
	/// <returns>TRUE if the two origins are equivalent</returns>
	public static bool areOriginsEquivalent(string sOrigin1, string sOrigin2, int iDefaultPort)
	{
		if (sOrigin1.OICEquals(sOrigin2))
		{
			return true;
		}
		int iPort = iDefaultPort;
		CrackHostAndPort(sOrigin1, out var sHostname, ref iPort);
		string sCanonicalHost1 = $"{sHostname}:{iPort}";
		iPort = iDefaultPort;
		CrackHostAndPort(sOrigin2, out sHostname, ref iPort);
		string sCanonicalHost2 = $"{sHostname}:{iPort}";
		return sCanonicalHost1.OICEquals(sCanonicalHost2);
	}

	/// <summary>
	/// This function cracks a sHostPort string to determine if the address
	/// refers to a "local" site
	/// </summary>
	/// <param name="sHostAndPort">The string to evaluate, potentially containing a port</param>
	/// <returns>True if the address is local</returns>
	[CodeDescription("Returns false if Hostname contains any dots or colons.")]
	public static bool isPlainHostName(string sHostAndPort)
	{
		int iDontCare = 0;
		CrackHostAndPort(sHostAndPort, out var sHost, ref iDontCare);
		char[] dots = new char[2] { '.', ':' };
		return sHost.IndexOfAny(dots) < 0;
	}

	/// <summary>
	/// This function cracks a sHostPort string to determine if the address
	/// refers to the local computer
	/// </summary>
	/// <param name="sHostAndPort">The string to evaluate, potentially containing a port</param>
	/// <returns>True if the address is 127.0.0.1, 'localhost', or ::1</returns>
	[CodeDescription("Returns true if True if the sHostAndPort's host is 127.0.0.1, 'localhost', or ::1. Note that list is not complete.")]
	public static bool isLocalhost(string sHostAndPort)
	{
		int iDontCare = 0;
		CrackHostAndPort(sHostAndPort, out var sHost, ref iDontCare);
		return isLocalhostname(sHost);
	}

	/// <summary>
	/// Determines if the specified Hostname is a either 'localhost' or an IPv4 or IPv6 loopback literal
	/// </summary>
	/// <param name="sHostname">Hostname (no port)</param>
	/// <returns>TRUE if the hostname is equivalent to localhost</returns>
	[CodeDescription("Returns true if True if the sHostname is 127.0.0.1, 'localhost', or ::1. Note that list is not complete.")]
	public static bool isLocalhostname(string sHostname)
	{
		return "localhost".OICEquals(sHostname) || "127.0.0.1".Equals(sHostname) || "localhost.".OICEquals(sHostname) || "::1".Equals(sHostname);
	}

	/// <summary>
	/// This function cracks the Hostname/Port combo, removing IPV6 brackets if needed
	/// </summary>
	/// <param name="sHostPort">Hostname/port combo, like www.foo.com or www.example.com:8888 or [::1]:80</param>
	/// <param name="sHostname">The hostname, minus any IPv6 literal brackets, if present</param>
	/// <param name="iPort">Port #, 80 if not specified, -1 if corrupt</param>
	[CodeDescription("This function cracks the Host/Port combo, removing IPV6 brackets if needed.")]
	public static void CrackHostAndPort(string sHostPort, out string sHostname, ref int iPort)
	{
		int ixToken = sHostPort.LastIndexOf(':');
		if (ixToken > -1 && ixToken > sHostPort.LastIndexOf(']'))
		{
			if (!int.TryParse(sHostPort.Substring(ixToken + 1), NumberStyles.Integer, NumberFormatInfo.InvariantInfo, out iPort))
			{
				iPort = -1;
			}
			sHostname = sHostPort.Substring(0, ixToken);
		}
		else
		{
			sHostname = sHostPort;
		}
		if (sHostname.StartsWith("[", StringComparison.Ordinal) && sHostname.EndsWith("]", StringComparison.Ordinal))
		{
			sHostname = sHostname.Substring(1, sHostname.Length - 2);
		}
	}

	/// <summary>
	/// Given a string/list in the form HOSTNAME:PORT#;HOSTNAME2:PORT2#, this function returns the FIRST IPEndPoint. Defaults to port 80 if not specified.
	/// Warning: DNS resolution is slow, so use this function wisely.
	/// </summary>
	/// <param name="sHostAndPort">HOSTNAME:PORT#;OPTHOST2:PORT2#</param>
	/// <returns>An IPEndPoint or null</returns>
	public static IPEndPoint IPEndPointFromHostPortString(string sHostAndPort)
	{
		if (IsNullOrWhiteSpace(sHostAndPort))
		{
			return null;
		}
		sHostAndPort = TrimAfter(sHostAndPort, ';');
		try
		{
			int iPort = 80;
			CrackHostAndPort(sHostAndPort, out var sHost, ref iPort);
			IPAddress ipTarget = DNSResolver.GetIPAddress(sHost, bCheckCache: true);
			return new IPEndPoint(ipTarget, iPort);
		}
		catch (Exception)
		{
			return null;
		}
	}

	/// <summary>
	/// Given a string/list in the form HOSTNAME:PORT#;HOSTNAME2:PORT2#, this function returns all IPEndPoints for ALL listed hosts. Defaults to port 80 if not specified.
	/// Warning: DNS resolution is slow, so use this function wisely.
	/// </summary>
	/// <param name="sAllHostAndPorts">HOSTNAME:PORT#;OPTHOST2:PORT2#</param>
	/// <returns>An array of IPEndPoints or null if no results were obtained</returns>
	public static IPEndPoint[] IPEndPointListFromHostPortString(string sAllHostAndPorts)
	{
		if (IsNullOrWhiteSpace(sAllHostAndPorts))
		{
			return null;
		}
		string[] arrHostsAndPorts = sAllHostAndPorts.Split(new char[1] { ';' }, StringSplitOptions.RemoveEmptyEntries);
		List<IPEndPoint> listResults = new List<IPEndPoint>();
		string[] array = arrHostsAndPorts;
		foreach (string sHostAndPort in array)
		{
			try
			{
				int iPort = 80;
				CrackHostAndPort(sHostAndPort, out var sHost, ref iPort);
				IPAddress[] ipsTarget = DNSResolver.GetIPAddressList(sHost, bCheckCache: true, null);
				IPAddress[] array2 = ipsTarget;
				foreach (IPAddress ipAddr in array2)
				{
					listResults.Add(new IPEndPoint(ipAddr, iPort));
				}
			}
			catch (Exception)
			{
			}
		}
		if (listResults.Count < 1)
		{
			return null;
		}
		return listResults.ToArray();
	}

	/// <summary>
	/// This function attempts to be a ~fast~ way to return an IP from a hoststring that contains an IPv4/6-Literal.
	/// </summary>
	/// <param name="sHost">Hostname</param>
	/// <returns>IPAddress, or null, if the sHost wasn't an IP-Literal</returns>
	[CodeDescription("This function attempts to be a ~fast~ way to return an IP from a hoststring that contains an IP-Literal. ")]
	public static IPAddress IPFromString(string sHost)
	{
		for (int i = 0; i < sHost.Length; i++)
		{
			if (sHost[i] != '.' && sHost[i] != ':' && (sHost[i] < '0' || sHost[i] > '9') && (sHost[i] < 'A' || sHost[i] > 'F') && (sHost[i] < 'a' || sHost[i] > 'f'))
			{
				return null;
			}
		}
		if (sHost.EndsWith("."))
		{
			sHost = TrimBeforeLast(sHost, '.');
		}
		try
		{
			return IPAddress.Parse(sHost);
		}
		catch
		{
			return null;
		}
	}

	/// <summary>
	/// Launch the user's browser to a hyperlink. This function traps exceptions and notifies the user via UI dialog.
	/// </summary>
	/// <param name="sURL">The URL to ShellExecute.</param>
	/// <returns>TRUE if the ShellExecute call succeeded.</returns>
	[CodeDescription("ShellExecutes the sURL.")]
	public static bool LaunchHyperlink(string sURL)
	{
		try
		{
			using (Process.Start(sURL))
			{
			}
			return true;
		}
		catch (Exception)
		{
		}
		return false;
	}

	internal static bool LaunchBrowser(string sExe, string sParams, string sURL)
	{
		sParams = (string.IsNullOrEmpty(sParams) ? sURL : sParams.Replace("%U", sURL));
		return RunExecutable(sExe, sParams);
	}

	/// <summary>
	/// Wrapper for Process.Start that shows error messages in the event of failure.
	/// </summary>
	/// <param name="sExecute">Fully-qualified filename to execute.</param>
	/// <param name="sParams">Command line parameters to pass.</param>
	/// <returns>TRUE if the execution succeeded. FALSE if the execution failed. An error message will be shown for any error except the user declining UAC.</returns>
	public static bool RunExecutable(string sExecute, string sParams)
	{
		try
		{
			using (Process.Start(sExecute, sParams))
			{
			}
			return true;
		}
		catch (Exception eX)
		{
			if (!(eX is Win32Exception) || 1223 != (eX as Win32Exception).NativeErrorCode)
			{
				string title = "ShellExecute Failed";
				string message = string.Format("Failed to execute: {0}\r\n{1}\r\n\r\n{2}\r\n{3}", sExecute, string.IsNullOrEmpty(sParams) ? string.Empty : ("with parameters: " + sParams), eX.Message, eX.StackTrace.ToString());
				FiddlerApplication.Log.LogFormat("{0}: {1}", title, message);
			}
		}
		return false;
	}

	/// <summary>
	/// Run an executable and wait for it to exit, notifying the user of any exceptions.
	/// </summary>
	/// <param name="sExecute">Fully-qualified filename of file to execute.</param>
	/// <param name="sParams">Command-line parameters to pass.</param>
	/// <returns>TRUE if the execution succeeded. FALSE if the error message was shown.</returns>
	[CodeDescription("Run an executable and wait for it to exit.")]
	public static bool RunExecutableAndWait(string sExecute, string sParams)
	{
		string errorMessage;
		bool isSuccessful = FiddlerCore.Utilities.Utilities.RunExecutableAndWait(sExecute, sParams, out errorMessage);
		if (!isSuccessful && errorMessage != null)
		{
			string title = "ShellExecute Failed";
			FiddlerApplication.Log.LogFormat("{0}: {1}", title, errorMessage);
		}
		return isSuccessful;
	}

	/// <summary>
	/// Run an executable, wait for it to exit, and return its output as a string.
	/// NOTE: Uses CreateProcess, so you cannot launch applications which require Elevation.
	/// </summary>
	/// <param name="sExecute">Fully-qualified filename of file to Execute</param>
	/// <param name="sParams">Command-line parameters to pass</param>
	/// <param name="iExitCode">Exit code returned by the executable</param>
	/// <returns>String containing the standard-output of the executable</returns>
	[CodeDescription("Run an executable, wait for it to exit, and return its output as a string.")]
	public static string GetExecutableOutput(string sExecute, string sParams, out int iExitCode)
	{
		iExitCode = -999;
		StringBuilder sbResult = new StringBuilder();
		sbResult.Append("Results from " + sExecute + " " + sParams + "\r\n\r\n");
		try
		{
			Process oProc = new Process();
			oProc.StartInfo.UseShellExecute = false;
			oProc.StartInfo.RedirectStandardOutput = true;
			oProc.StartInfo.RedirectStandardError = false;
			oProc.StartInfo.CreateNoWindow = true;
			oProc.StartInfo.FileName = sExecute;
			oProc.StartInfo.Arguments = sParams;
			oProc.Start();
			string str;
			while ((str = oProc.StandardOutput.ReadLine()) != null)
			{
				str = str.TrimEnd(Array.Empty<char>());
				if (str.Length > 0)
				{
					sbResult.AppendLine(str);
				}
			}
			iExitCode = oProc.ExitCode;
			oProc.Dispose();
		}
		catch (Exception eX)
		{
			sbResult.Append("Exception thrown: " + eX.ToString() + "\r\n" + eX.StackTrace.ToString());
		}
		sbResult.Append("-------------------------------------------\r\n");
		return sbResult.ToString();
	}

	/// <summary>
	/// This method prepares a string to be converted into a regular expression by escaping special characters and CONVERTING WILDCARDS.
	/// This method was originally meant for parsing WPAD proxy script strings. 
	///
	/// You typically should use the Static RegEx.Escape method for most purposes, as it doesn't convert "*" into ".*"
	/// </summary>
	/// <param name="sString"></param>
	/// <param name="bAddPrefixCaret"></param>
	/// <param name="bAddSuffixDollarSign"></param>
	/// <returns></returns>
	internal static string RegExEscape(string sString, bool bAddPrefixCaret, bool bAddSuffixDollarSign)
	{
		StringBuilder builder = new StringBuilder();
		if (bAddPrefixCaret)
		{
			builder.Append("^");
		}
		foreach (char ch in sString)
		{
			switch (ch)
			{
			case '#':
			case '$':
			case '(':
			case ')':
			case '+':
			case '.':
			case '?':
			case '[':
			case '\\':
			case '^':
			case '{':
			case '|':
				builder.Append('\\');
				break;
			case '*':
				builder.Append('.');
				break;
			}
			builder.Append(ch);
		}
		if (bAddSuffixDollarSign)
		{
			builder.Append('$');
		}
		return builder.ToString();
	}

	/// <summary>
	/// Determines whether the arrData array STARTS WITH with the supplied arrMagics bytes. Used for Content-Type sniffing.
	/// </summary>
	/// <param name="arrData">The data, or null</param>
	/// <param name="arrMagics">The MagicBytes to look for</param>
	/// <returns>TRUE if arrData begins with arrMagics</returns>
	public static bool HasMagicBytes(byte[] arrData, byte[] arrMagics)
	{
		return HasMagicBytes(arrData, 0, arrMagics);
	}

	public static bool HasMagicBytes(byte[] arrData, int iXOffset, byte[] arrMagics)
	{
		if (arrData == null)
		{
			return false;
		}
		if (arrData.Length < iXOffset + arrMagics.Length)
		{
			return false;
		}
		for (int i = 0; i < arrMagics.Length; i++)
		{
			if (arrData[i + iXOffset] != arrMagics[i])
			{
				return false;
			}
		}
		return true;
	}

	/// <summary>
	/// Determines whether the arrData array begins with the supplied sMagics ASCII text. Used for Content-Type sniffing.
	/// </summary>
	/// <param name="arrData">The data, or null</param>
	/// <param name="sMagics">The ASCII text to look for</param>
	/// <returns>TRUE if arrData begins with sMagics (encoded as ASCII octets)</returns>
	public static bool HasMagicBytes(byte[] arrData, string sMagics)
	{
		return HasMagicBytes(arrData, Encoding.ASCII.GetBytes(sMagics));
	}

	/// <summary>
	/// Is this HTTPMethod used for RPC-over-HTTPS?
	/// </summary>
	internal static bool isRPCOverHTTPSMethod(string sMethod)
	{
		return sMethod == "RPC_IN_DATA" || sMethod == "RPC_OUT_DATA";
	}

	/// <summary>
	/// Determine if a given byte array has the start of a HTTP/1.* 200 response.
	/// Useful primarily to determine if a CONNECT request to a proxy returned success.
	/// </summary>
	/// <param name="arrData"></param>
	/// <returns></returns>
	internal static bool isHTTP200Array(byte[] arrData)
	{
		return arrData.Length > 12 && arrData[9] == 50 && arrData[10] == 48 && arrData[11] == 48 && arrData[0] == 72 && arrData[1] == 84 && arrData[2] == 84 && arrData[3] == 80 && arrData[4] == 47 && arrData[5] == 49 && arrData[6] == 46;
	}

	/// <summary>
	/// Determine if a given byte array has the start of a HTTP/1.* 407 response.
	/// Useful primarily to determine if a CONNECT request to a proxy returned an auth challenge
	/// </summary>
	/// <param name="arrData"></param>
	/// <returns></returns>
	internal static bool isHTTP407Array(byte[] arrData)
	{
		return arrData.Length > 12 && arrData[9] == 52 && arrData[10] == 48 && arrData[11] == 55 && arrData[0] == 72 && arrData[1] == 84 && arrData[2] == 84 && arrData[3] == 80 && arrData[4] == 47 && arrData[5] == 49 && arrData[6] == 46;
	}

	/// <summary>
	/// For a given process name, returns a bool indicating whether this is a known browser process name.
	/// </summary>
	/// <param name="sProcessName">The Process name (e.g. "abrowser.exe")</param>
	/// <returns>Returns true if the process name starts with a common browser process name (e.g. ie, firefox, etc)</returns>
	public static bool IsBrowserProcessName(string sProcessName)
	{
		if (string.IsNullOrEmpty(sProcessName))
		{
			return false;
		}
		if (knownBrowsers == null)
		{
			knownBrowsers = FiddlerApplication.Prefs.GetStringPref("fiddler.knownbrowsers", "ie,chrom,firefox,microsoftedge,browser_broker,ttb-,opera,webkit,safari,msedge,brave").Split(new char[1] { ',' });
		}
		return sProcessName.OICStartsWithAny(knownBrowsers);
	}

	/// <summary>
	/// Ensure that a given path is absolute, if not, applying the root path.
	/// WARNING: This function only works as well as Path.IsPathRooted, which returns "True" for things like "/NoDriveSpecified/fuzzle.txt"
	/// A better approach would be to look at the internal Path.IsRelative method
	/// </summary>
	/// <param name="sRootPath"></param>
	/// <param name="sFilename"></param>
	/// <returns></returns>
	public static string EnsurePathIsAbsolute(string sRootPath, string sFilename)
	{
		try
		{
			if (!Path.IsPathRooted(sFilename))
			{
				sFilename = sRootPath + sFilename;
			}
		}
		catch (Exception)
		{
		}
		return sFilename;
	}

	/// <summary>
	/// If sFilename is absolute, returns it, otherwise, combines the leaf filename with local response folders hunting for a match.
	/// Trims at the first ? character, if any
	/// </summary>
	/// <param name="sFilename">Either a fully-qualified path, or a leaf filename</param>
	/// <returns>File path</returns>
	internal static string GetFirstLocalResponse(string sFilename)
	{
		sFilename = TrimAfter(sFilename, '?');
		try
		{
			if (!Path.IsPathRooted(sFilename))
			{
				string sLeaf = sFilename;
				sFilename = CONFIG.GetPath("TemplateResponses") + sLeaf;
				if (!File.Exists(sFilename))
				{
					sFilename = CONFIG.GetPath("Responses") + sLeaf;
				}
			}
		}
		catch (Exception)
		{
		}
		return sFilename;
	}

	internal static string DescribeExceptionWithStack(Exception eX)
	{
		StringBuilder oSB = new StringBuilder(512);
		oSB.AppendLine(eX.Message);
		oSB.AppendLine(eX.StackTrace);
		if (eX.InnerException != null)
		{
			oSB.AppendFormat(" < {0}", eX.InnerException.Message);
		}
		return oSB.ToString();
	}

	/// <summary>
	/// Get a TickCount (milliseconds since system start) as an unsigned 64bit value. On Windows Vista+, uses the GetTickCount64 API that
	/// won't rollover, but on any other platform, this unsigned wrapper moves the rollover point to 49 days of uptime.
	/// </summary>
	/// <returns>Number of ms since the system started</returns>
	public static ulong GetTickCount()
	{
		IPlatformExtensions extensions = PlatformExtensionsFactory.Instance.CreatePlatformExtensions();
		if (extensions.TryGetUptimeInMilliseconds(out var milliseconds))
		{
			return milliseconds;
		}
		int iRet = Environment.TickCount;
		if (iRet > 0)
		{
			return (ulong)iRet;
		}
		return (ulong)(4294967294u - -iRet);
	}

	/// <summary>
	/// Returns a succinct version of Environment.OSVersion.VersionString
	/// </summary>
	/// <returns></returns>
	internal static string GetOSVerString()
	{
		if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
		{
			return "Windows";
		}
		if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
		{
			return "Linux";
		}
		if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
		{
			return "Mac";
		}
		return "Unknown";
	}

	internal static string GetProcessorString()
	{
		int processorCount = Environment.ProcessorCount;
		string processorArchitecture = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE");
		return $"{processorCount}x{processorArchitecture}";
	}

	/// <summary>
	/// Returns TRUE on *Windows* (not Mono) when OS Version is Win8+ (NT6.2+)
	/// </summary>
	/// <returns></returns>
	internal static bool IsWin8OrLater()
	{
		if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
		{
			return false;
		}
		if (Environment.OSVersion.Version.Major > 6)
		{
			return true;
		}
		return Environment.OSVersion.Version.Major == 6 && Environment.OSVersion.Version.Minor > 1;
	}

	internal static bool IsNullOrWhiteSpace(string sInput)
	{
		return string.IsNullOrWhiteSpace(sInput);
	}

	internal static string SslProtocolsToString(SslProtocols sslProts)
	{
		List<string> slTokens = new List<string>();
		if ((sslProts & SslProtocols.Ssl2) != 0)
		{
			slTokens.Add("ssl2");
		}
		if ((sslProts & SslProtocols.Ssl3) != 0)
		{
			slTokens.Add("ssl3");
		}
		if ((sslProts & SslProtocols.Tls) != 0)
		{
			slTokens.Add("tls1.0");
		}
		if ((sslProts & SslProtocols.Tls11) != 0)
		{
			slTokens.Add("tls1.1");
		}
		if ((sslProts & SslProtocols.Tls12) != 0)
		{
			slTokens.Add("tls1.2");
		}
		return string.Join(";", slTokens.ToArray());
	}

	/// <summary>
	/// Turns a string into a SslProtocol Flags enum. Ignores our magic &lt;client&gt; token.
	/// </summary>
	/// <param name="sList">e.g. tls1.0;ssl3.0</param>
	/// <returns></returns>
	internal static SslProtocols ParseSSLProtocolString(string sList)
	{
		SslProtocols oResult = SslProtocols.None;
		if (sList.OICContains("ssl2"))
		{
			oResult |= SslProtocols.Ssl2;
		}
		if (sList.OICContains("ssl3"))
		{
			oResult |= SslProtocols.Ssl3;
		}
		if (sList.OICContains("tls1.0"))
		{
			oResult |= SslProtocols.Tls;
		}
		if (sList.OICContains("tls1.1"))
		{
			oResult |= SslProtocols.Tls11;
		}
		if (sList.OICContains("tls1.2"))
		{
			oResult |= SslProtocols.Tls12;
		}
		return oResult;
	}

	/// <summary>
	/// Duplicate a byte array, replacing null with byte[0].
	/// Doing this instead of .Clone() because it better handles nulls and it may be faster.
	/// </summary>
	/// <param name="bIn">The array to copy</param>
	/// <returns>The new array.</returns>
	public static byte[] Dupe(byte[] bIn)
	{
		if (bIn == null)
		{
			return emptyByteArray;
		}
		byte[] bOut = new byte[bIn.Length];
		Buffer.BlockCopy(bIn, 0, bOut, 0, bIn.Length);
		return bOut;
	}

	public static string GetSHA256Hash(byte[] bIn)
	{
		using SHA256 oHasher = SHA256.Create();
		return BitConverter.ToString(oHasher.ComputeHash(bIn));
	}

	public static string GetSHA384Hash(byte[] bIn)
	{
		using SHA384 oHasher = SHA384.Create();
		return BitConverter.ToString(oHasher.ComputeHash(bIn));
	}

	public static string GetSHA512Hash(byte[] bIn)
	{
		using SHA512 oHasher = SHA512.Create();
		return BitConverter.ToString(oHasher.ComputeHash(bIn));
	}

	public static string GetSHA1Hash(byte[] bIn)
	{
		using SHA1 oHasher = SHA1.Create();
		return BitConverter.ToString(oHasher.ComputeHash(bIn));
	}

	public static string GetHashAsBase64(string sHashAlgorithm, byte[] bIn)
	{
		HashAlgorithm oH = sHashAlgorithm.ToLower() switch
		{
			"md5" => MD5.Create(), 
			"sha1" => SHA1.Create(), 
			"sha256" => SHA256.Create(), 
			"sha384" => SHA384.Create(), 
			"sha512" => SHA512.Create(), 
			_ => throw new NotImplementedException("Unrecognized algorithm: " + sHashAlgorithm), 
		};
		string sResult = Convert.ToBase64String(oH.ComputeHash(bIn));
		oH.Clear();
		return sResult;
	}

	/// <summary>
	/// Warning: This will throw if FIPS mode is enabled
	/// </summary>
	/// <param name="bIn"></param>
	/// <returns></returns>
	public static string GetMD5Hash(byte[] bIn)
	{
		using MD5 oHasher = MD5.Create();
		return BitConverter.ToString(oHasher.ComputeHash(bIn));
	}

	/// <summary>
	/// Returns TRUE if the array is null or contains 0 bytes
	/// </summary>
	/// <param name="bIn">byte[] to test</param>
	/// <returns></returns>
	public static bool IsNullOrEmpty(byte[] bIn)
	{
		if (bIn == null)
		{
			return true;
		}
		if (bIn.Length == 0)
		{
			return true;
		}
		return false;
	}

	/// <summary>
	/// Returns TRUE if the string is non-empty and not of the pattern "[#123]"
	/// Necessary because SAZ-saving logic autogenerates comments of that form
	/// </summary>
	/// <param name="strComment"></param>
	/// <returns></returns>
	public static bool IsCommentUserSupplied(string strComment)
	{
		if (string.IsNullOrEmpty(strComment))
		{
			return false;
		}
		if (strComment.StartsWith("[#") && strComment.EndsWith("]"))
		{
			return false;
		}
		return true;
	}

	/// <summary>
	///
	/// </summary>
	/// <param name="oSC"></param>
	/// <returns>True if ClientChatter is non-null and its headers are non-null</returns>
	internal static bool HasHeaders(ServerChatter oSC)
	{
		return oSC != null && oSC.headers != null;
	}

	/// <summary>
	/// True if ClientChatter is non-null and its headers are non-null
	/// </summary>
	/// <param name="oCC"></param>
	/// <returns>True if ClientChatter is non-null and its headers are non-null</returns>
	internal static bool HasHeaders(ClientChatter oCC)
	{
		return oCC != null && oCC.headers != null;
	}

	internal static string GetLocalIPList(bool bLeadingTab)
	{
		IPAddress[] ipAddrs = Dns.GetHostAddresses(string.Empty);
		StringBuilder sbIP = new StringBuilder();
		IPAddress[] array = ipAddrs;
		foreach (IPAddress anIP in array)
		{
			sbIP.AppendFormat("{0}{1}\n", bLeadingTab ? "\t" : string.Empty, anIP.ToString());
		}
		return sbIP.ToString();
	}

	/// <summary>
	/// Return a multi-line string describing the NetworkInterfaces[]
	/// </summary>
	/// <returns></returns>
	internal static string GetNetworkInfo()
	{
		try
		{
			StringBuilder sbInfo = new StringBuilder();
			long cbReceived = 0L;
			NetworkInterface[] arrNI = NetworkInterface.GetAllNetworkInterfaces();
			Array.Sort(arrNI, (NetworkInterface x, NetworkInterface y) => string.Compare(y.OperationalStatus.ToString(), x.OperationalStatus.ToString()));
			NetworkInterface[] array = arrNI;
			foreach (NetworkInterface NI in array)
			{
				sbInfo.AppendFormat("{0,32}\t '{1}' Type: {2} @ {3:N0}/sec. Status: {4}\n", NI.Name, NI.Description, NI.NetworkInterfaceType, NI.Speed, NI.OperationalStatus.ToString().ToUpperInvariant());
				if (NI.OperationalStatus == OperationalStatus.Up && NI.NetworkInterfaceType != NetworkInterfaceType.Loopback && NI.NetworkInterfaceType != NetworkInterfaceType.Tunnel && NI.NetworkInterfaceType != NetworkInterfaceType.Unknown && !NI.IsReceiveOnly)
				{
					cbReceived += NI.GetIPv4Statistics().BytesReceived;
				}
			}
			sbInfo.AppendFormat("\nTotal bytes received (IPv4): {0:N0}\n", cbReceived);
			sbInfo.AppendFormat("\nLocal Addresses:\n{0}", GetLocalIPList(bLeadingTab: true));
			return sbInfo.ToString();
		}
		catch (Exception eX)
		{
			return "Failed to obtain NetworkInterfaces information. " + FiddlerCore.Utilities.Utilities.DescribeException(eX);
		}
	}

	internal static void PingTarget(string sTarget)
	{
		FiddlerApplication.Log.LogFormat("Pinging: {0}...", sTarget);
		Ping oPing = new Ping();
		oPing.PingCompleted += delegate(object oS, PingCompletedEventArgs pcea)
		{
			StringBuilder stringBuilder = new StringBuilder();
			if (pcea.Reply == null)
			{
				stringBuilder.AppendFormat("Pinging '{0}' failed: {1}\n", pcea.UserState, pcea.Error.InnerException.ToString());
			}
			else
			{
				stringBuilder.AppendFormat("Pinged '{0}'.\n\tFinal Result:\t{1}\n", pcea.UserState as string, pcea.Reply.Status.ToString());
				if (pcea.Reply.Status == IPStatus.Success)
				{
					stringBuilder.AppendFormat("\tTarget Address:\t{0}\n", pcea.Reply.Address);
					stringBuilder.AppendFormat("\tRoundTrip time:\t{0}", pcea.Reply.RoundtripTime);
				}
			}
			FiddlerApplication.Log.LogString(stringBuilder.ToString());
		};
		oPing.SendAsync(sTarget, 60000, new byte[0], new PingOptions(128, dontFragment: true), sTarget);
	}

	/// <summary>
	/// Checks a DLL's filename for signals that it doesn't contain extensions.
	/// This hack is only needed because I wasn't smart enough to require that the assembly be named something like Fiddler.* in the original design. 
	/// </summary>
	/// <param name="sFilename">DLL filename</param>
	/// <returns>TRUE if we should skip this assembly during enumeration</returns>
	internal static bool IsNotExtension(string sFilename)
	{
		if (sFilename.StartsWith("_"))
		{
			return true;
		}
		if (sFilename.OICStartsWithAny("qwhale.", "Be.Windows.Forms.", "Telerik.WinControls.", "netstandard.dll"))
		{
			return true;
		}
		return false;
	}

	internal static T DeserializeObjectFromXmlFile<T>(string path)
	{
		if (!File.Exists(path))
		{
			return default(T);
		}
		try
		{
			using Stream stream = new FileStream(path, FileMode.Open, FileAccess.Read);
			XmlSerializer xmlSerializer = new XmlSerializer(typeof(T));
			return (T)xmlSerializer.Deserialize(stream);
		}
		catch (Exception ex)
		{
			FiddlerApplication.Log.LogString(ex.ToString());
		}
		return default(T);
	}

	internal static void SerializeObjectToXmlFile<T>(T obj, string path)
	{
		try
		{
			using Stream stream = new FileStream(path, FileMode.Create, FileAccess.Write);
			XmlSerializer xmlSerializer = new XmlSerializer(typeof(T));
			xmlSerializer.Serialize(stream, obj);
		}
		catch (Exception ex)
		{
			FiddlerApplication.Log.LogString(ex.ToString());
		}
	}

	/// <summary>
	/// Garbage collect and, if possible, compact the Large Object heap
	/// </summary>
	public static void RecoverMemory()
	{
		GC.Collect();
		GC.WaitForPendingFinalizers();
		GC.Collect();
		CompactLOHIfPossible();
	}

	internal static void CompactLOHIfPossible()
	{
		try
		{
			Type tGCSettings = typeof(GCSettings);
			PropertyInfo piLOHCM = tGCSettings.GetProperty("LargeObjectHeapCompactionMode", BindingFlags.Static | BindingFlags.Public);
			if (null != piLOHCM)
			{
				MethodInfo miSetter = piLOHCM.GetSetMethod();
				miSetter.Invoke(null, new object[1] { 2 });
				GC.Collect();
			}
		}
		catch (Exception eX)
		{
			FiddlerApplication.Log.LogString(FiddlerCore.Utilities.Utilities.DescribeException(eX));
		}
	}
}
