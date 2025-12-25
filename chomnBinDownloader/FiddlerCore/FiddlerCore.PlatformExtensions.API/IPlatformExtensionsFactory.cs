namespace FiddlerCore.PlatformExtensions.API;

/// <summary>
/// Implement this interface in order to implement a factory, which is used to create <see cref="T:FiddlerCore.PlatformExtensions.API.IPlatformExtensions" /> objects.
/// </summary>
internal interface IPlatformExtensionsFactory
{
	/// <summary>
	/// Creates new <see cref="T:FiddlerCore.PlatformExtensions.API.IPlatformExtensions" /> object.
	/// </summary>
	/// <returns>The platform extensions object.</returns>
	IPlatformExtensions CreatePlatformExtensions();
}
