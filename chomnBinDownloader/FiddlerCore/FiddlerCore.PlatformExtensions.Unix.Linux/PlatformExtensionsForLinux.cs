using FiddlerCore.PlatformExtensions.API;

namespace FiddlerCore.PlatformExtensions.Unix.Linux;

internal class PlatformExtensionsForLinux : PlatformExtensionsForUnix, IPlatformExtensions
{
	private static PlatformExtensionsForLinux instance;

	public static PlatformExtensionsForLinux Instance
	{
		get
		{
			if (instance == null)
			{
				instance = new PlatformExtensionsForLinux();
			}
			return instance;
		}
	}

	private PlatformExtensionsForLinux()
	{
	}
}
