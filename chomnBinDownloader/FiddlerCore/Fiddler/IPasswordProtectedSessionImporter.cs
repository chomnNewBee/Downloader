using System;
using System.Collections.Generic;

namespace Fiddler;

/// <summary>
/// ISessionImport allows loading of password-protected Session data
/// </summary>
public interface IPasswordProtectedSessionImporter : ISessionImporter, IDisposable
{
	/// <summary>
	/// Import Sessions from a password-protected data source
	/// </summary>
	/// <param name="sImportFormat">Shortname of the format</param>
	/// <param name="dictOptions">Dictionary of options that the Importer class may use</param>
	/// <param name="evtProgressNotifications">Callback event on which progress is reported or the host may cancel</param>
	/// <param name="passwordCallback">Callback that is used to request passwords from the host</param>
	/// <returns>Array of Session objects imported from source</returns>
	Session[] ImportSessions(string sImportFormat, Dictionary<string, object> dictOptions, EventHandler<ProgressCallbackEventArgs> evtProgressNotifications, GetPasswordDelegate passwordCallback);
}
