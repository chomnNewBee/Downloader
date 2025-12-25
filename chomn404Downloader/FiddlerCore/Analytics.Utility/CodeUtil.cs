using System;

namespace Analytics.Utility;

internal static class CodeUtil
{
	public static void SafeAction(Action action)
	{
		try
		{
			action();
		}
		catch
		{
		}
	}

	public static T SafeExpr<T>(Func<T> func, T defaultValue)
	{
		try
		{
			return func();
		}
		catch
		{
			return defaultValue;
		}
	}
}
