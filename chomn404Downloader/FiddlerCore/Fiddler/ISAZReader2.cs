namespace Fiddler;

public interface ISAZReader2 : ISAZReader
{
	GetPasswordDelegate PasswordCallback { get; set; }
}
