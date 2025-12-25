using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Analytics.Utility;

namespace Analytics;

internal class WindowsNativeMethods
{
	public class DisplayInfo
	{
		public int BitDepth { get; internal set; }

		public int DesktopHorzRes { get; internal set; }

		public int DesktopVertRes { get; internal set; }

		public int Dpi { get; internal set; }

		public int HorzRes { get; internal set; }

		public bool IsPrimary { get; internal set; }

		public int VertRes { get; internal set; }
	}

	private static class DeviceCap
	{
		public const int DRIVERVERSION = 0;

		public const int TECHNOLOGY = 2;

		public const int HORZSIZE = 4;

		public const int VERTSIZE = 6;

		public const int HORZRES = 8;

		public const int VERTRES = 10;

		public const int BITSPIXEL = 12;

		public const int PLANES = 14;

		public const int NUMBRUSHES = 16;

		public const int NUMPENS = 18;

		public const int NUMMARKERS = 20;

		public const int NUMFONTS = 22;

		public const int NUMCOLORS = 24;

		public const int PDEVICESIZE = 26;

		public const int CURVECAPS = 28;

		public const int LINECAPS = 30;

		public const int POLYGONALCAPS = 32;

		public const int TEXTCAPS = 34;

		public const int CLIPCAPS = 36;

		public const int RASTERCAPS = 38;

		public const int ASPECTX = 40;

		public const int ASPECTY = 42;

		public const int ASPECTXY = 44;

		public const int SHADEBLENDCAPS = 45;

		public const int LOGPIXELSX = 88;

		public const int LOGPIXELSY = 90;

		public const int SIZEPALETTE = 104;

		public const int NUMRESERVED = 106;

		public const int COLORRES = 108;

		public const int PHYSICALWIDTH = 110;

		public const int PHYSICALHEIGHT = 111;

		public const int PHYSICALOFFSETX = 112;

		public const int PHYSICALOFFSETY = 113;

		public const int SCALINGFACTORX = 114;

		public const int SCALINGFACTORY = 115;

		public const int VREFRESH = 116;

		public const int DESKTOPVERTRES = 117;

		public const int DESKTOPHORZRES = 118;

		public const int BLTALIGNMENT = 119;
	}

	private delegate bool MonitorEnumDelegate(IntPtr hMonitor, IntPtr hdcMonitor, ref Rect lprcMonitor, IntPtr dwData);

	[StructLayout(LayoutKind.Sequential)]
	private class MonitorInfoEx
	{
		public uint Size;

		public Rect Monitor;

		public Rect WorkArea;

		public uint Flags;

		public static uint FlagMaskPrimary = 1u;

		[MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
		public string DeviceName;

		public MonitorInfoEx()
		{
			Size = (uint)Marshal.SizeOf(this);
			DeviceName = string.Empty;
		}
	}

	private struct Rect
	{
		public int Left;

		public int Top;

		public int Right;

		public int Bottom;
	}

	private const int CCHDEVICENAME = 32;

	public static List<DisplayInfo> GetDisplays()
	{
		List<DisplayInfo> displays = new List<DisplayInfo>();
		EnumDisplayMonitors(IntPtr.Zero, IntPtr.Zero, delegate(IntPtr hMonitor, IntPtr hdcMonitor, ref Rect lprcMonitor, IntPtr dwData)
		{
			MonitorInfoEx mi = new MonitorInfoEx();
			if (GetMonitorInfo(hMonitor, mi))
			{
				DisplayInfo di = new DisplayInfo
				{
					IsPrimary = ((mi.Flags & MonitorInfoEx.FlagMaskPrimary) != 0)
				};
				if (di.IsPrimary)
				{
					IntPtr ptr = hdcMonitor;
					CodeUtil.SafeAction(delegate
					{
						if (hdcMonitor == IntPtr.Zero)
						{
							ptr = CreateDC(mi.DeviceName, null, null, IntPtr.Zero);
						}
						di.BitDepth = GetDeviceCaps(ptr, 12) * GetDeviceCaps(ptr, 14);
						di.Dpi = GetDeviceCaps(ptr, 88);
						di.HorzRes = GetDeviceCaps(ptr, 8);
						di.VertRes = GetDeviceCaps(ptr, 10);
						di.DesktopHorzRes = GetDeviceCaps(ptr, 118);
						di.DesktopVertRes = GetDeviceCaps(ptr, 117);
					});
					if (ptr != hdcMonitor)
					{
						DeleteDC(ptr);
					}
				}
				displays.Add(di);
			}
			return true;
		}, IntPtr.Zero);
		return displays;
	}

	[DllImport("gdi32.dll", CharSet = CharSet.Unicode)]
	private static extern IntPtr CreateDC(string lpszDriver, string lpszDevice, string lpszOutput, IntPtr lpInitData);

	[DllImport("gdi32.dll")]
	private static extern bool DeleteDC(IntPtr hdc);

	[DllImport("user32.dll")]
	private static extern bool EnumDisplayMonitors(IntPtr hdc, IntPtr lprcClip, MonitorEnumDelegate lpfnEnum, IntPtr dwData);

	[DllImport("gdi32.dll")]
	private static extern int GetDeviceCaps(IntPtr hdc, int nIndex);

	[DllImport("user32.dll")]
	private static extern bool GetMonitorInfo(IntPtr hMonitor, [In][Out] MonitorInfoEx lpmi);
}
