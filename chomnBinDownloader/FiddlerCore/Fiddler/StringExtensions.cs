using FiddlerCore.Utilities;

namespace Fiddler;

/// <summary>
/// Common functions we'll want to use on Strings. Fiddler makes extensive use of strings which 
/// should be interpreted in a case-insensitive manner.
///
/// WARNING: Methods assume that the calling object is not null, which is lame for reliability but arguably good for performance.
/// </summary>
public static class StringExtensions
{
	public static bool OICContains(this string inStr, string toMatch)
	{
		return StringHelper.OICContains(inStr, toMatch);
	}

	public static bool OICEquals(this string inStr, string toMatch)
	{
		return StringHelper.OICEquals(inStr, toMatch);
	}

	public static bool OICStartsWith(this string inStr, string toMatch)
	{
		return StringHelper.OICStartsWith(inStr, toMatch);
	}

	public static bool OICStartsWithAny(this string inStr, params string[] toMatch)
	{
		return StringHelper.OICStartsWithAny(inStr, toMatch);
	}

	public static bool OICEndsWithAny(this string inStr, params string[] toMatch)
	{
		return StringHelper.OICEndsWithAny(inStr, toMatch);
	}

	public static bool OICEndsWith(this string inStr, string toMatch)
	{
		return StringHelper.OICEndsWith(inStr, toMatch);
	}

	internal static int StrLen(this string s)
	{
		if (string.IsNullOrEmpty(s))
		{
			return 0;
		}
		return s.Length;
	}
}
