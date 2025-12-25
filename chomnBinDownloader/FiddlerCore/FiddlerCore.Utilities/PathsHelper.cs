using System.IO;
using System.Reflection;

namespace FiddlerCore.Utilities;

internal static class PathsHelper
{
	private static string rootDirectory = null;

	public static string RootDirectory
	{
		get
		{
			if (rootDirectory == null)
			{
				Assembly assembly = Assembly.GetEntryAssembly();
				if (assembly == null)
				{
					assembly = typeof(PathsHelper).Assembly;
				}
				rootDirectory = Path.GetDirectoryName(assembly.Location);
			}
			return rootDirectory;
		}
	}
}
