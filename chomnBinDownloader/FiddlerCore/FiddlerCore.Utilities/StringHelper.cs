using System;

namespace FiddlerCore.Utilities;

internal static class StringHelper
{
	public static bool OICContains(this string inStr, string toMatch)
	{
		return inStr.IndexOf(toMatch, StringComparison.OrdinalIgnoreCase) > -1;
	}

	public static bool OICEquals(this string inStr, string toMatch)
	{
		return string.Equals(inStr, toMatch, StringComparison.OrdinalIgnoreCase);
	}

	public static bool OICStartsWith(this string inStr, string toMatch)
	{
		return inStr.StartsWith(toMatch, StringComparison.OrdinalIgnoreCase);
	}

	public static bool OICStartsWithAny(this string inStr, params string[] toMatch)
	{
		for (int i = 0; i < toMatch.Length; i++)
		{
			if (inStr.StartsWith(toMatch[i], StringComparison.OrdinalIgnoreCase))
			{
				return true;
			}
		}
		return false;
	}

	public static bool OICEndsWithAny(this string inStr, params string[] toMatch)
	{
		for (int i = 0; i < toMatch.Length; i++)
		{
			if (inStr.EndsWith(toMatch[i], StringComparison.OrdinalIgnoreCase))
			{
				return true;
			}
		}
		return false;
	}

	public static bool OICEndsWith(this string inStr, string toMatch)
	{
		return inStr.EndsWith(toMatch, StringComparison.OrdinalIgnoreCase);
	}

	/// <summary>
	/// Returns the "Tail" of a string, after (but not including) the Last instance of specified delimiter.
	/// <seealso cref="!:TrimBefore(string, char)" />
	/// </summary>
	/// <param name="sString">The string to trim from.</param>
	/// <param name="chDelim">The delimiting character after which text should be returned.</param>
	/// <returns>Part of a string after (but not including) the final chDelim, or the full string if chDelim was not found.</returns>
	public static string TrimBeforeLast(string sString, char chDelim)
	{
		if (sString == null)
		{
			return string.Empty;
		}
		int ixToken = sString.LastIndexOf(chDelim);
		if (ixToken < 0)
		{
			return sString;
		}
		return sString.Substring(ixToken + 1);
	}
}
