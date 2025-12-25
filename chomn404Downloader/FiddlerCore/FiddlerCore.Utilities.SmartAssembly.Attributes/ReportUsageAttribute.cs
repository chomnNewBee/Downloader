using System;

namespace FiddlerCore.Utilities.SmartAssembly.Attributes;

[AttributeUsage(AttributeTargets.Constructor | AttributeTargets.Method)]
public class ReportUsageAttribute : Attribute
{
	public ReportUsageAttribute()
	{
	}

	public ReportUsageAttribute(string featureName)
	{
	}
}
