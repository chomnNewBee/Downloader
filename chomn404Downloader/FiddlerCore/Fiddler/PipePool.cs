using System;
using System.Collections.Generic;
using System.Text;

namespace Fiddler;

/// <summary>
/// The PipePool maintains a collection of connected ServerPipes for reuse
/// </summary>
internal class PipePool
{
	/// <summary>
	/// Minimum idle time of pipes to be expired from the pool.
	/// Note, we don't check the pipe's ulLastPooled value when extracting a pipe, 
	/// so its age could exceed the allowed lifetime by up to MSEC_POOL_CLEANUP_INTERVAL
	/// WARNING: Don't change the timeout &gt;2 minutes casually. Server bugs apparently exist: https://bugzilla.mozilla.org/show_bug.cgi?id=491541
	/// </summary>
	internal static uint MSEC_PIPE_POOLED_LIFETIME = 115000u;

	internal static uint MSEC_POOL_CLEANUP_INTERVAL = 30000u;

	/// <summary>
	/// The Pool itself.
	/// </summary>
	private readonly Dictionary<string, Stack<ServerPipe>> thePool;

	/// <summary>
	/// Time at which a "Clear before" operation was conducted. We store this
	/// so that we don't accidentally put any pipes that were in use back into
	/// the pool after a clear operation
	/// </summary>
	private long lngLastPoolPurge = 0L;

	internal PipePool()
	{
		MSEC_PIPE_POOLED_LIFETIME = (uint)FiddlerApplication.Prefs.GetInt32Pref("fiddler.network.timeouts.serverpipe.reuse", 115000);
		thePool = new Dictionary<string, Stack<ServerPipe>>();
		FiddlerApplication.Janitor.assignWork(ScavengeCache, MSEC_POOL_CLEANUP_INTERVAL);
	}

	/// <summary>
	/// Remove any pipes from Stacks if they exceed the age threshold
	/// Remove any Stacks from pool if they are empty
	/// </summary>
	internal void ScavengeCache()
	{
		if (thePool.Count < 1)
		{
			return;
		}
		List<ServerPipe> pipesToClose = new List<ServerPipe>();
		lock (thePool)
		{
			List<string> poolExpiredStacks = new List<string>();
			ulong tcExpireBefore = Utilities.GetTickCount() - MSEC_PIPE_POOLED_LIFETIME;
			foreach (KeyValuePair<string, Stack<ServerPipe>> oKVP in thePool)
			{
				Stack<ServerPipe> stPipes = oKVP.Value;
				lock (stPipes)
				{
					if (stPipes.Count > 0)
					{
						ServerPipe oPipe2 = stPipes.Peek();
						if (oPipe2.ulLastPooled < tcExpireBefore)
						{
							pipesToClose.AddRange(stPipes);
							stPipes.Clear();
						}
						else if (stPipes.Count > 1)
						{
							ServerPipe[] oPipesInStack = stPipes.ToArray();
							if (oPipesInStack[^1].ulLastPooled < tcExpireBefore)
							{
								stPipes.Clear();
								for (int iX = oPipesInStack.Length - 1; iX >= 0; iX--)
								{
									if (oPipesInStack[iX].ulLastPooled < tcExpireBefore)
									{
										pipesToClose.Add(oPipesInStack[iX]);
									}
									else
									{
										stPipes.Push(oPipesInStack[iX]);
									}
								}
							}
						}
					}
					if (stPipes.Count == 0)
					{
						poolExpiredStacks.Add(oKVP.Key);
					}
				}
			}
			foreach (string sKey in poolExpiredStacks)
			{
				thePool.Remove(sKey);
			}
		}
		foreach (ServerPipe oPipe in pipesToClose)
		{
			oPipe.End();
		}
	}

	/// <summary>
	/// Clear all pooled Pipes, calling .End() on each.
	/// </summary>
	internal void Clear()
	{
		lngLastPoolPurge = DateTime.Now.Ticks;
		if (thePool.Count < 1)
		{
			return;
		}
		List<ServerPipe> pipesToClose = new List<ServerPipe>();
		lock (thePool)
		{
			foreach (KeyValuePair<string, Stack<ServerPipe>> oKVP in thePool)
			{
				lock (oKVP.Value)
				{
					pipesToClose.AddRange(oKVP.Value);
				}
			}
			thePool.Clear();
		}
		foreach (ServerPipe oPipe in pipesToClose)
		{
			oPipe.End();
		}
	}

	/// <summary>
	/// Return a string representing the Pipes in the Pool
	/// </summary>
	/// <returns>A string representing the pipes in the pool</returns>
	internal string InspectPool()
	{
		StringBuilder sbResult = new StringBuilder(8192);
		sbResult.AppendFormat("ServerPipePool\nfiddler.network.timeouts.serverpipe.reuse: {0}ms\nContents\n--------\n", MSEC_PIPE_POOLED_LIFETIME);
		lock (thePool)
		{
			foreach (string sPoolKey in thePool.Keys)
			{
				Stack<ServerPipe> oStack = thePool[sPoolKey];
				sbResult.AppendFormat("\t[{0}] entries for '{1}'.\n", oStack.Count, sPoolKey);
				lock (oStack)
				{
					foreach (ServerPipe oPipe in oStack)
					{
						sbResult.AppendFormat("\t\t{0}\n", oPipe.ToString());
					}
				}
			}
		}
		sbResult.Append("\n--------\n");
		return sbResult.ToString();
	}

	/// <summary>
	/// Get a Server connection for reuse, or null if a suitable connection is not in the pool.
	/// </summary>
	/// <param name="sPoolKey">The key which identifies the connection to search for.</param>
	/// <param name="iPID">The ProcessID of the client requesting the Pipe</param>
	/// <param name="HackiForSession">HACK to be removed; the SessionID# of the request for logging</param>
	/// <returns>A Pipe to reuse, or NULL</returns>
	internal ServerPipe TakePipe(string sPoolKey, int iPID, int HackiForSession)
	{
		if (!CONFIG.ReuseServerSockets)
		{
			return null;
		}
		Stack<ServerPipe> oStack;
		lock (thePool)
		{
			if ((iPID == 0 || !thePool.TryGetValue($"pid{iPID}*{sPoolKey}", out oStack) || oStack.Count < 1) && (!thePool.TryGetValue(sPoolKey, out oStack) || oStack.Count < 1))
			{
				return null;
			}
		}
		ServerPipe oResult;
		lock (oStack)
		{
			try
			{
				if (oStack.Count == 0)
				{
					return null;
				}
				oResult = oStack.Pop();
			}
			catch (Exception eX)
			{
				FiddlerApplication.Log.LogString(eX.ToString());
				return null;
			}
		}
		return oResult;
	}

	/// <summary>
	/// Store a pipe for later use, if reuse is allowed by settings and state of the pipe.
	/// </summary>
	/// <param name="oPipe">The Pipe to place in the pool</param>
	internal void PoolOrClosePipe(ServerPipe oPipe)
	{
		if (!CONFIG.ReuseServerSockets)
		{
			oPipe.End();
			return;
		}
		if (oPipe.ReusePolicy == PipeReusePolicy.NoReuse || oPipe.ReusePolicy == PipeReusePolicy.MarriedToClientPipe)
		{
			oPipe.End();
			return;
		}
		if (lngLastPoolPurge > oPipe.dtConnected.Ticks)
		{
			oPipe.End();
			return;
		}
		if (oPipe.sPoolKey == null || oPipe.sPoolKey.Length < 2)
		{
			oPipe.End();
			return;
		}
		oPipe.ulLastPooled = Utilities.GetTickCount();
		Stack<ServerPipe> oStack;
		lock (thePool)
		{
			if (!thePool.TryGetValue(oPipe.sPoolKey, out oStack))
			{
				oStack = new Stack<ServerPipe>();
				thePool.Add(oPipe.sPoolKey, oStack);
			}
		}
		lock (oStack)
		{
			oStack.Push(oPipe);
		}
	}
}
