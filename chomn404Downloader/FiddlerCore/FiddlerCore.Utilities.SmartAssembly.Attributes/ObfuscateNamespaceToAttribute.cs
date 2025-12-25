using System;

namespace FiddlerCore.Utilities.SmartAssembly.Attributes;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Struct | AttributeTargets.Enum | AttributeTargets.Interface)]
public sealed class ObfuscateNamespaceToAttribute : Attribute
{
	public ObfuscateNamespaceToAttribute(string newName)
	{
	}
}
