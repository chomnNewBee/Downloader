namespace GoogleAnalytics;

/// <summary>
/// Dimensions in pixels.
/// </summary>
internal struct Dimensions
{
	/// <summary>
	/// Gets the width in pixels.
	/// </summary>
	public int Width { get; private set; }

	/// <summary>
	/// Gets the height in pixels.
	/// </summary>
	public int Height { get; private set; }

	/// <summary>
	/// Creates a new object to store dimensions.
	/// </summary>
	/// <param name="width">The width in pixels.</param>
	/// <param name="height">The height in pixels.</param>
	public Dimensions(int width, int height)
	{
		Width = width;
		Height = height;
	}
}
