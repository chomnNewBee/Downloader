using System;
using System.Reflection;
using System.Runtime;
using Fiddler;

namespace FiddlerCore.Utilities;

/// <summary>
/// Provides methods which recognize the .NET Frameworks on the user machine.
/// </summary>
internal static class DotNetVersionRecognizer
{
	private static string recognizedDotNetVersion = null;

	/// <summary>
	/// This method tries to get the highest installed .NET Framework version for the current CLR. If it succeeds, it returns it.
	/// Otherwise it returns the version which the Environment.Version property returns.
	/// </summary>
	/// <returns>The highest .NET Framework installed for the current CLR if found. If any framework was found the method returns the environment version.</returns>
	public static string GetHighestVersionInstalledForCurrentClr()
	{
		if (recognizedDotNetVersion == null && !TryGetHighestVersionInstalledForCurrentClr(out recognizedDotNetVersion))
		{
			recognizedDotNetVersion = Environment.Version.ToString();
		}
		return recognizedDotNetVersion;
	}

	/// <summary>
	/// This method tries to detect which CLR is running the application and then finds the highest framework version installed for that CLR.
	/// If it succeeds it returns true and the version is assigned to the <paramref name="version" />.
	/// Otherwise the method returns false and assigns null to <paramref name="version" />.
	/// <para>If there are exceptions, they will be caught and reported to the Telerik.Analytics.</para>
	/// </summary>
	/// <param name="version">out: The version of the .NET Framework</param>
	/// <returns>Returns true if a .NET Framework version is assigned to <paramref name="version" />
	/// and false when the <paramref name="version" /> is assigned null.</returns>
	private static bool TryGetHighestVersionInstalledForCurrentClr(out string version)
	{
		try
		{
			return GetNetCoreVersion(out version);
		}
		catch (Exception ex)
		{
			FiddlerApplication.oTelemetry.TrackException(ex);
		}
		version = null;
		return false;
	}

	private static bool GetNetCoreVersion(out string version)
	{
		Assembly assembly = typeof(GCSettings).GetTypeInfo().Assembly;
		string[] assemblyPath = assembly.CodeBase.Split(new char[2] { '/', '\\' }, StringSplitOptions.RemoveEmptyEntries);
		int netCoreAppIndex = Array.IndexOf(assemblyPath, "Microsoft.NETCore.App");
		if (netCoreAppIndex > 0 && netCoreAppIndex < assemblyPath.Length - 2)
		{
			version = assemblyPath[netCoreAppIndex + 1];
			return true;
		}
		version = null;
		return false;
	}
}
