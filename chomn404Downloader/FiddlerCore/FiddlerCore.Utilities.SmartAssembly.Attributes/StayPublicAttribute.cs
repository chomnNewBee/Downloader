using System;

namespace FiddlerCore.Utilities.SmartAssembly.Attributes;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Struct | AttributeTargets.Enum | AttributeTargets.Interface | AttributeTargets.Delegate)]
public sealed class StayPublicAttribute : Attribute
{
}
