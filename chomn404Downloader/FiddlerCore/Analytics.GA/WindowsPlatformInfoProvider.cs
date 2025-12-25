using System;
using GoogleAnalytics;

namespace Analytics.GA;

internal class WindowsPlatformInfoProvider : IPlatformInfoProvider
{
	private string anonymousClientId;

	private int? screenColors;

	private Dimensions? screenResolution;

	private string userAgent;

	private string userLanguage;

	private Dimensions? viewPortResolution;

	public string AnonymousClientId
	{
		get
		{
			return anonymousClientId;
		}
		private set
		{
			anonymousClientId = value;
		}
	}

	public int? ScreenColors
	{
		get
		{
			return screenColors;
		}
		private set
		{
			screenColors = value;
		}
	}

	public Dimensions? ScreenResolution
	{
		get
		{
			return screenResolution;
		}
		private set
		{
			screenResolution = value;
			if (this.ScreenResolutionChanged != null)
			{
				this.ScreenResolutionChanged(this, EventArgs.Empty);
			}
		}
	}

	public string UserLanguage
	{
		get
		{
			return userLanguage;
		}
		private set
		{
			userLanguage = value;
		}
	}

	public Dimensions? ViewPortResolution
	{
		get
		{
			return viewPortResolution;
		}
		private set
		{
			viewPortResolution = value;
			if (this.ViewPortResolutionChanged != null)
			{
				this.ViewPortResolutionChanged(this, EventArgs.Empty);
			}
		}
	}

	public string UserAgent
	{
		get
		{
			return userAgent;
		}
		private set
		{
			userAgent = value;
		}
	}

	public event EventHandler ViewPortResolutionChanged;

	public event EventHandler ScreenResolutionChanged;

	public WindowsPlatformInfoProvider()
	{
		InitializeWindow();
	}

	public void OnTracking()
	{
	}

	private void InitializeWindow()
	{
		AnonymousClientId = UniqueClientIdGenerator.Generate();
		ScreenResolution = WindowsSystemInformation.ScreenResolution;
		UserLanguage = WindowsSystemInformation.SystemLanguage;
	}
}
