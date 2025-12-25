namespace FiddlerCore.Analytics;

internal sealed class AnalyticsFactory
{
	private static readonly AnalyticsFactory instance = new AnalyticsFactory();

	private readonly IAnalytics analytics;

	internal static AnalyticsFactory Instance => instance;

	private AnalyticsFactory()
	{
		analytics = FiddlerAnalytics.Instance;
	}

	internal IAnalytics GetAnalytics()
	{
		return analytics;
	}
}
