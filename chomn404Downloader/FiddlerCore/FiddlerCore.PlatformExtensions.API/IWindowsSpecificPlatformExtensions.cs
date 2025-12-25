namespace FiddlerCore.PlatformExtensions.API;

/// <summary>
/// Implement this interface in order to provide FiddlerCore with Windows-specific functionality.
/// </summary>
internal interface IWindowsSpecificPlatformExtensions : IPlatformExtensions
{
	/// <summary>
	/// Gets a WinINet helper, which can be used to access WinINet native API.
	/// </summary>
	IWinINetHelper WinINetHelper { get; }
}
