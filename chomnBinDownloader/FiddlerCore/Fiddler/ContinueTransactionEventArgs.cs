using System;

namespace Fiddler;

public class ContinueTransactionEventArgs : EventArgs
{
	private Session _sessOriginal;

	private Session _sessNew;

	private ContinueTransactionReason _reason;

	public ContinueTransactionReason reason => _reason;

	public Session originalSession => _sessOriginal;

	public Session newSession => _sessNew;

	internal ContinueTransactionEventArgs(Session originalSession, Session newSession, ContinueTransactionReason reason)
	{
		_sessOriginal = originalSession;
		_sessNew = newSession;
		_reason = reason;
	}
}
