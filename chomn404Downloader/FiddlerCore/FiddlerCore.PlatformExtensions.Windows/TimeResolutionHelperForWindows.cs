using System.Runtime.InteropServices;

namespace FiddlerCore.PlatformExtensions.Windows;

internal static class TimeResolutionHelperForWindows
{
	private static bool _EnabledHighResTimers = false;

	public static bool EnableHighResolutionTimers
	{
		get
		{
			return _EnabledHighResTimers;
		}
		set
		{
			if (value != _EnabledHighResTimers)
			{
				if (value)
				{
					uint iRes2 = MM_timeBeginPeriod(1u);
					_EnabledHighResTimers = iRes2 == 0;
				}
				else
				{
					uint iRes = MM_timeEndPeriod(1u);
					_EnabledHighResTimers = iRes != 0;
				}
			}
		}
	}

	[DllImport("winmm.dll", EntryPoint = "timeBeginPeriod")]
	private static extern uint MM_timeBeginPeriod(uint iMS);

	[DllImport("winmm.dll", EntryPoint = "timeEndPeriod")]
	private static extern uint MM_timeEndPeriod(uint iMS);
}
