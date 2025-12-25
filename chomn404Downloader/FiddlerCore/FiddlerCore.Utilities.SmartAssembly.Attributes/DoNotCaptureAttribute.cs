using System;

namespace FiddlerCore.Utilities.SmartAssembly.Attributes;

[DoNotPrune]
[DoNotObfuscate]
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Struct | AttributeTargets.Field, Inherited = true)]
public sealed class DoNotCaptureAttribute : Attribute
{
}
