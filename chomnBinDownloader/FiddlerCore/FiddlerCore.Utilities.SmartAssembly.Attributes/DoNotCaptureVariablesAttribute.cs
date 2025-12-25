using System;

namespace FiddlerCore.Utilities.SmartAssembly.Attributes;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Struct | AttributeTargets.Constructor | AttributeTargets.Method)]
public sealed class DoNotCaptureVariablesAttribute : Attribute
{
}
