namespace Fiddler;

/// <summary>
/// An event handling delegate which is called as a part of the HTTP pipeline at various stages.
/// </summary>
/// <param name="oSession">The Web Session in the pipeline.</param>
public delegate void SessionStateHandler(Session oSession);
