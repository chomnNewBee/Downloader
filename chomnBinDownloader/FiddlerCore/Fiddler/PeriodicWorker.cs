using System.Collections.Generic;
using System.Threading;

namespace Fiddler;

/// <summary>
/// Somewhat similar to the Framework's "BackgroundWorker" class, the periodic worker performs a similar function on a periodic schedule.
/// NOTE: the callback occurs on a background thread.
///
/// The PeriodicWorker class is used by Fiddler to perform "cleanup" style tasks on a timer. Put work in the queue, 
/// and it will see that it's done at least as often as the schedule specified until Fiddler begins to close at which
/// point all work stops.
///
///
/// The underlying timer's interval is 1 second.
///
/// </summary>
/// <remarks>
/// I think a significant part of the reason that this class exists is that I thought the System.Threading.Timer consumed one thread for each
/// timer. In reality, per "CLR via C# 4e" all of the instances share one underlying thread and thus my concern was misplaced. Ah well.
/// </remarks>
internal class PeriodicWorker
{
	internal class taskItem
	{
		public ulong _ulLastRun;

		public uint _iPeriod;

		public SimpleEventHandler _oTask;

		public taskItem(SimpleEventHandler oTask, uint iPeriod)
		{
			_ulLastRun = Utilities.GetTickCount();
			_iPeriod = iPeriod;
			_oTask = oTask;
		}
	}

	private const int CONST_MIN_RESOLUTION = 500;

	private Timer timerInternal;

	private List<taskItem> oTaskList = new List<taskItem>();

	internal PeriodicWorker()
	{
		timerInternal = new Timer(doWork, null, 500, 500);
	}

	private void doWork(object objState)
	{
		if (FiddlerApplication.isClosing)
		{
			timerInternal.Dispose();
			return;
		}
		taskItem[] myTasks;
		lock (oTaskList)
		{
			myTasks = new taskItem[oTaskList.Count];
			oTaskList.CopyTo(myTasks);
		}
		taskItem[] array = myTasks;
		foreach (taskItem oTI in array)
		{
			if (Utilities.GetTickCount() > oTI._ulLastRun + oTI._iPeriod)
			{
				oTI._oTask();
				oTI._ulLastRun = Utilities.GetTickCount();
			}
		}
	}

	/// <summary>
	/// Assigns a "job" to the Periodic worker, on the schedule specified by iMS. 
	/// </summary>
	/// <param name="workFunction">The function to run on the timer specified.
	/// Warning: the function is NOT called on the UI thread, so use .Invoke() if needed.</param>
	/// <param name="iMS">The # of milliseconds to wait between runs</param>
	/// <returns>A taskItem which can be used to revokeWork later</returns>
	internal taskItem assignWork(SimpleEventHandler workFunction, uint iMS)
	{
		taskItem oResult = new taskItem(workFunction, iMS);
		lock (oTaskList)
		{
			oTaskList.Add(oResult);
		}
		return oResult;
	}

	/// <summary>
	/// Revokes a previously-assigned task from this worker.
	/// </summary>
	/// <param name="oToRevoke"></param>
	internal void revokeWork(taskItem oToRevoke)
	{
		if (oToRevoke == null)
		{
			return;
		}
		lock (oTaskList)
		{
			oTaskList.Remove(oToRevoke);
		}
	}
}
