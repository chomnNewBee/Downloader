using System;
using System.Collections.Generic;
using System.Threading;

namespace Fiddler;

/// <summary>
/// The ScheduledTasks class allows addition of jobs by name. It ensures that ONE instance of the named
/// job will occur at *some* point in the future, between 0 and a specified max delay. If you queue multiple
/// instances of the same-named Task, it's only done once.
/// </summary>
public static class ScheduledTasks
{
	/// <summary>
	/// A jobItem represents a Function+Time tuple. The function will run after the given time.
	/// </summary>
	private class jobItem
	{
		/// <summary>
		/// TickCount at which this job must run.
		/// </summary>
		internal ulong _ulRunAfter;

		/// <summary>
		/// Method to invoke to complete the job
		/// </summary>
		internal SimpleEventHandler _oJob;

		internal jobItem(SimpleEventHandler oJob, uint iMaxDelay)
		{
			_ulRunAfter = iMaxDelay + Utilities.GetTickCount();
			_oJob = oJob;
		}
	}

	private const int CONST_MIN_RESOLUTION = 15;

	private static Dictionary<string, jobItem> _dictSchedule = new Dictionary<string, jobItem>();

	private static Timer _timerInternal = null;

	private static ReaderWriterLock _RWLockDict = new ReaderWriterLock();

	/// <summary>
	/// Under the lock, we enumerate the schedule to find work to do and remove that work from the schedule.
	/// After we release the lock, we then do the queued work.
	/// </summary>
	/// <param name="objState"></param>
	private static void doWork(object objState)
	{
		List<KeyValuePair<string, jobItem>> listWorkToDoNow = null;
		try
		{
			_RWLockDict.AcquireReaderLock(-1);
			ulong iNow = Utilities.GetTickCount();
			foreach (KeyValuePair<string, jobItem> oDE in _dictSchedule)
			{
				if (iNow > oDE.Value._ulRunAfter)
				{
					oDE.Value._ulRunAfter = ulong.MaxValue;
					if (listWorkToDoNow == null)
					{
						listWorkToDoNow = new List<KeyValuePair<string, jobItem>>();
					}
					listWorkToDoNow.Add(oDE);
				}
			}
			if (listWorkToDoNow == null)
			{
				return;
			}
			LockCookie oLC = _RWLockDict.UpgradeToWriterLock(-1);
			try
			{
				foreach (KeyValuePair<string, jobItem> oItem2 in listWorkToDoNow)
				{
					_dictSchedule.Remove(oItem2.Key);
				}
				if (_dictSchedule.Count < 1 && _timerInternal != null)
				{
					_timerInternal.Dispose();
					_timerInternal = null;
				}
			}
			finally
			{
				_RWLockDict.DowngradeFromWriterLock(ref oLC);
			}
		}
		finally
		{
			_RWLockDict.ReleaseReaderLock();
		}
		foreach (KeyValuePair<string, jobItem> oItem in listWorkToDoNow)
		{
			try
			{
				oItem.Value._oJob();
			}
			catch (Exception)
			{
			}
		}
	}

	public static bool CancelWork(string sTaskName)
	{
		try
		{
			_RWLockDict.AcquireWriterLock(-1);
			return _dictSchedule.Remove(sTaskName);
		}
		finally
		{
			_RWLockDict.ReleaseWriterLock();
		}
	}

	public static bool ScheduleWork(string sTaskName, uint iMaxDelay, SimpleEventHandler workFunction)
	{
		try
		{
			_RWLockDict.AcquireReaderLock(-1);
			if (_dictSchedule.ContainsKey(sTaskName))
			{
				return false;
			}
		}
		finally
		{
			_RWLockDict.ReleaseReaderLock();
		}
		jobItem oJob = new jobItem(workFunction, iMaxDelay);
		try
		{
			_RWLockDict.AcquireWriterLock(-1);
			if (_dictSchedule.ContainsKey(sTaskName))
			{
				return false;
			}
			_dictSchedule.Add(sTaskName, oJob);
			if (_timerInternal == null)
			{
				_timerInternal = new Timer(doWork, null, 15, 15);
			}
		}
		finally
		{
			_RWLockDict.ReleaseWriterLock();
		}
		return true;
	}
}
