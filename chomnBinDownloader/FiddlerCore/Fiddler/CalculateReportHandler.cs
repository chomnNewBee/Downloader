namespace Fiddler;

/// <summary>
/// An event handling delegate which is called during report calculation with the set of sessions being evaluated.
/// </summary>
/// <param name="_arrSessions">The sessions in this report.</param>
public delegate void CalculateReportHandler(Session[] _arrSessions);
