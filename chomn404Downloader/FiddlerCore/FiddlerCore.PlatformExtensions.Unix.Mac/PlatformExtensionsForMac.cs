using FiddlerCore.PlatformExtensions.API;

namespace FiddlerCore.PlatformExtensions.Unix.Mac;

internal class PlatformExtensionsForMac : PlatformExtensionsForUnix, IPlatformExtensions
{
	private static PlatformExtensionsForMac instance;

	public static PlatformExtensionsForMac Instance
	{
		get
		{
			if (instance == null)
			{
				instance = new PlatformExtensionsForMac();
			}
			return instance;
		}
	}

	private PlatformExtensionsForMac()
	{
	}
}
