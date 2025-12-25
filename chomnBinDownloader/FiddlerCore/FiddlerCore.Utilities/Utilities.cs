using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace FiddlerCore.Utilities;

internal static class Utilities
{
	/// <summary>
	/// Format an Exception message, including InnerException message if present.
	/// </summary>
	/// <param name="eX"></param>
	/// <returns></returns>
	public static string DescribeException(Exception eX)
	{
		StringBuilder oSB = new StringBuilder(512);
		oSB.AppendFormat("{0} {1}", eX.GetType(), eX.Message);
		if (eX.InnerException != null)
		{
			oSB.AppendFormat(" < {0}", eX.InnerException.Message);
		}
		return oSB.ToString();
	}

	public static bool RunExecutableAndWait(string sExecute, string sParams, out string errorMessage)
	{
		errorMessage = null;
		try
		{
			Process oProc = new Process();
			oProc.StartInfo.FileName = sExecute;
			oProc.StartInfo.Arguments = sParams;
			oProc.Start();
			oProc.WaitForExit();
			bool isSuccessful = true;
			if (oProc.ExitCode != 0)
			{
				isSuccessful = false;
			}
			oProc.Dispose();
			return isSuccessful;
		}
		catch (Exception eX)
		{
			if (!(eX is Win32Exception) || 1223 != (eX as Win32Exception).NativeErrorCode)
			{
				errorMessage = "Fiddler Exception thrown: " + eX.ToString() + "\r\n" + eX.StackTrace.ToString();
			}
			return false;
		}
	}

	public static bool CheckIfFileHasBOM(string filename)
	{
		UTF8Encoding encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: true);
		byte[] preamble = encoding.GetPreamble();
		int preambleLenght = preamble.Length;
		byte[] buffer = new byte[preambleLenght];
		using (FileStream fileStream = new FileStream(filename, FileMode.Open, FileAccess.Read))
		{
			fileStream.Read(buffer, 0, buffer.Length);
			fileStream.Close();
		}
		for (int i = 0; i < preambleLenght; i++)
		{
			if (preamble[i] != buffer[i])
			{
				return false;
			}
		}
		return true;
	}

	public static bool IsVaraibleIsInFile(string pattern, string path)
	{
		bool isVariableIsInFile = false;
		using (StreamReader file = new StreamReader(path))
		{
			string line = string.Empty;
			while ((line = file.ReadLine()) != null)
			{
				Regex regex = new Regex(pattern);
				if (regex.Match(line).Success)
				{
					isVariableIsInFile = true;
					break;
				}
			}
		}
		return isVariableIsInFile;
	}

	public static string[] SplitHostAndPort(string hostAndPort)
	{
		string[] result = null;
		if (!string.IsNullOrEmpty(hostAndPort))
		{
			result = hostAndPort.Split(new char[1] { ':' }, StringSplitOptions.RemoveEmptyEntries);
		}
		if (result != null && result.Length != 2)
		{
			result = CreateArrayWithTwoZeros();
		}
		if (result == null)
		{
			result = CreateArrayWithTwoZeros();
		}
		return result;
	}

	private static string[] CreateArrayWithTwoZeros()
	{
		return new string[2] { "0", "0" };
	}
}
