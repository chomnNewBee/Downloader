using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Text;
using System.Threading;

namespace Fiddler;

/// <summary>
/// The PreferenceBag is used to maintain a threadsafe Key/Value list of preferences, persisted in the registry, and with appropriate eventing when a value changes.
/// </summary>
public class PreferenceBag : IFiddlerPreferences, IEnumerable<KeyValuePair<string, string>>, IEnumerable
{
	/// <summary>
	/// A simple struct which contains a Branch identifier and EventHandler
	/// </summary>
	public struct PrefWatcher
	{
		internal readonly EventHandler<PrefChangeEventArgs> fnToNotify;

		internal readonly string sPrefixToWatch;

		internal PrefWatcher(string sPrefixFilter, EventHandler<PrefChangeEventArgs> fnHandler)
		{
			sPrefixToWatch = sPrefixFilter;
			fnToNotify = fnHandler;
		}
	}

	private readonly StringDictionary _dictPrefs = new StringDictionary();

	private readonly List<PrefWatcher> _listWatchers = new List<PrefWatcher>();

	private readonly ReaderWriterLockSlim _RWLockPrefs = new ReaderWriterLockSlim();

	private readonly ReaderWriterLockSlim _RWLockWatchers = new ReaderWriterLockSlim();

	private string _sRegistryPath;

	private string _sCurrentProfile = ".default";

	private static char[] _arrForbiddenChars = new char[7] { '*', ' ', '$', '%', '@', '?', '!' };

	/// <summary>
	/// Returns a string naming the current profile
	/// </summary>
	public string CurrentProfile => _sCurrentProfile;

	/// <summary>
	/// Indexer into the Preference collection.
	/// </summary>
	/// <param name="sPrefName">The name of the Preference to update/create or return.</param>
	/// <returns>The string value of the preference, or null.</returns>
	public string this[string sPrefName]
	{
		get
		{
			try
			{
				_RWLockPrefs.EnterReadLock();
				return _dictPrefs[sPrefName];
			}
			finally
			{
				_RWLockPrefs.ExitReadLock();
			}
		}
		set
		{
			if (!isValidName(sPrefName))
			{
				throw new ArgumentException($"Preference name must contain 1 to 255 characters from the set A-z0-9-_ and may not contain the word Internal.\n\nCaller tried to set: \"{sPrefName}\"");
			}
			if (value == null)
			{
				RemovePref(sPrefName);
				return;
			}
			bool _bNotifyChange = false;
			try
			{
				_RWLockPrefs.EnterWriteLock();
				if (value != _dictPrefs[sPrefName])
				{
					_bNotifyChange = true;
					_dictPrefs[sPrefName] = value;
				}
			}
			finally
			{
				_RWLockPrefs.ExitWriteLock();
			}
			if (_bNotifyChange)
			{
				PrefChangeEventArgs oArgs = new PrefChangeEventArgs(sPrefName, value);
				AsyncNotifyWatchers(oArgs);
			}
		}
	}

	internal PreferenceBag(string sRegPath)
	{
		_sRegistryPath = sRegPath;
	}

	public static bool isValidName(string sName)
	{
		return !string.IsNullOrEmpty(sName) && 256 > sName.Length && !sName.OICContains("internal") && 0 > sName.IndexOfAny(_arrForbiddenChars);
	}

	/// <summary>
	/// Get a string array of the preference names
	/// </summary>
	/// <returns>string[] of preference names</returns>
	public string[] GetPrefArray()
	{
		try
		{
			_RWLockPrefs.EnterReadLock();
			string[] arrResult = new string[_dictPrefs.Count];
			_dictPrefs.Keys.CopyTo(arrResult, 0);
			return arrResult;
		}
		finally
		{
			_RWLockPrefs.ExitReadLock();
		}
	}

	/// <summary>
	/// Gets a preference's value as a string
	/// </summary>
	/// <param name="sPrefName">The Preference Name</param>
	/// <param name="sDefault">The default value if the preference is missing</param>
	/// <returns>A string</returns>
	public string GetStringPref(string sPrefName, string sDefault)
	{
		string sRet = this[sPrefName];
		return sRet ?? sDefault;
	}

	/// <summary>
	/// Return a bool preference.
	/// </summary>
	/// <param name="sPrefName">The Preference name</param>
	/// <param name="bDefault">The default value to return if the specified preference does not exist</param>
	/// <returns>The boolean value of the Preference, or the default value</returns>
	public bool GetBoolPref(string sPrefName, bool bDefault)
	{
		string sRet = this[sPrefName];
		if (sRet == null)
		{
			return bDefault;
		}
		if (bool.TryParse(sRet, out var bRet))
		{
			return bRet;
		}
		return bDefault;
	}

	/// <summary>
	/// Return an Int32 Preference.
	/// </summary>
	/// <param name="sPrefName">The Preference name</param>
	/// <param name="iDefault">The default value to return if the specified preference does not exist</param>
	/// <returns>The Int32 value of the Preference, or the default value</returns>
	public int GetInt32Pref(string sPrefName, int iDefault)
	{
		string sRet = this[sPrefName];
		if (sRet == null)
		{
			return iDefault;
		}
		if (int.TryParse(sRet, out var iRet))
		{
			return iRet;
		}
		return iDefault;
	}

	/// <summary>
	/// Update or create a string preference.
	/// </summary>
	/// <param name="sPrefName">The name of the Preference</param>
	/// <param name="sValue">The value to assign to the Preference</param>
	public void SetStringPref(string sPrefName, string sValue)
	{
		this[sPrefName] = sValue;
	}

	/// <summary>
	/// Update or create a Int32 Preference
	/// </summary>
	/// <param name="sPrefName">The name of the Preference</param>
	/// <param name="iValue">The value to assign to the Preference</param>
	public void SetInt32Pref(string sPrefName, int iValue)
	{
		this[sPrefName] = iValue.ToString();
	}

	/// <summary>
	/// Update or create a Boolean preference.
	/// </summary>
	/// <param name="sPrefName">The name of the Preference</param>
	/// <param name="bValue">The value to assign to the Preference</param>
	public void SetBoolPref(string sPrefName, bool bValue)
	{
		this[sPrefName] = bValue.ToString();
	}

	/// <summary>
	/// Update or create multiple preferences.
	/// </summary>
	/// <param name="prefs">An enumeration of the preferences' names and values to store.</param>
	public void SetPrefs(IEnumerable<KeyValuePair<string, string>> prefs)
	{
		foreach (KeyValuePair<string, string> pref in prefs)
		{
			this[pref.Key] = pref.Value;
		}
	}

	/// <summary>
	/// Delete a Preference from the collection.
	/// </summary>
	/// <param name="sPrefName">The name of the Preference to be removed.</param>
	public void RemovePref(string sPrefName)
	{
		bool _bNotifyChange = false;
		try
		{
			_RWLockPrefs.EnterWriteLock();
			_bNotifyChange = _dictPrefs.ContainsKey(sPrefName);
			_dictPrefs.Remove(sPrefName);
		}
		finally
		{
			_RWLockPrefs.ExitWriteLock();
		}
		if (_bNotifyChange)
		{
			PrefChangeEventArgs oArgs = new PrefChangeEventArgs(sPrefName, null);
			AsyncNotifyWatchers(oArgs);
		}
	}

	/// <summary>
	/// Remove all Watchers
	/// </summary>
	private void _clearWatchers()
	{
		_RWLockWatchers.EnterWriteLock();
		try
		{
			_listWatchers.Clear();
		}
		finally
		{
			_RWLockWatchers.ExitWriteLock();
		}
	}

	/// <summary>
	/// Remove all watchers and write the registry.
	/// </summary>
	public void Close()
	{
		_clearWatchers();
	}

	/// <summary>
	/// Return a description of the contents of the preference bag
	/// </summary>
	/// <returns>Multi-line string</returns>
	public override string ToString()
	{
		return ToString(bVerbose: true);
	}

	/// <summary>
	/// Return a string-based serialization of the Preferences settings.
	/// </summary>
	/// <param name="bVerbose">TRUE for a multi-line format with all preferences</param>
	/// <returns>String</returns>
	public string ToString(bool bVerbose)
	{
		StringBuilder sbResult = new StringBuilder(128);
		try
		{
			_RWLockPrefs.EnterReadLock();
			sbResult.AppendFormat("PreferenceBag [{0} Preferences. {1} Watchers.]", _dictPrefs.Count, _listWatchers.Count);
			if (bVerbose)
			{
				sbResult.Append("\n");
				foreach (DictionaryEntry dePrefVal in _dictPrefs)
				{
					sbResult.AppendFormat("{0}:\t{1}\n", dePrefVal.Key, dePrefVal.Value);
				}
			}
		}
		finally
		{
			_RWLockPrefs.ExitReadLock();
		}
		return sbResult.ToString();
	}

	/// <summary>
	/// Returns a CRLF-delimited string containing all Preferences whose Name case-insensitively contains the specified filter string.
	/// </summary>
	/// <param name="sFilter">Partial string to match</param>
	/// <returns>A string</returns>
	internal string FindMatches(string sFilter)
	{
		StringBuilder sbResult = new StringBuilder(128);
		try
		{
			_RWLockPrefs.EnterReadLock();
			foreach (DictionaryEntry dePrefVal in _dictPrefs)
			{
				if (((string)dePrefVal.Key).OICContains(sFilter))
				{
					sbResult.AppendFormat("{0}:\t{1}\r\n", dePrefVal.Key, dePrefVal.Value);
				}
			}
		}
		finally
		{
			_RWLockPrefs.ExitReadLock();
		}
		return sbResult.ToString();
	}

	/// <summary>
	/// Add a watcher for changes to the specified preference or preference branch.
	/// </summary>
	/// <param name="sPrefixFilter">Preference branch to monitor, or String.Empty to watch all</param>
	/// <param name="pcehHandler">The EventHandler accepting PrefChangeEventArgs to notify</param>
	/// <returns>Returns the PrefWatcher object which has been added, store to pass to RemoveWatcher later.</returns>
	public PrefWatcher AddWatcher(string sPrefixFilter, EventHandler<PrefChangeEventArgs> pcehHandler)
	{
		PrefWatcher wliNew = new PrefWatcher(sPrefixFilter.ToLower(), pcehHandler);
		_RWLockWatchers.EnterWriteLock();
		try
		{
			_listWatchers.Add(wliNew);
		}
		finally
		{
			_RWLockWatchers.ExitWriteLock();
		}
		return wliNew;
	}

	/// <summary>
	/// Remove a previously attached Watcher
	/// </summary>
	/// <param name="wliToRemove">The previously-specified Watcher</param>
	public void RemoveWatcher(PrefWatcher wliToRemove)
	{
		_RWLockWatchers.EnterWriteLock();
		try
		{
			_listWatchers.Remove(wliToRemove);
		}
		finally
		{
			_RWLockWatchers.ExitWriteLock();
		}
	}

	/// <summary>
	/// This function executes on a single background thread and notifies any registered
	/// Watchers of changes in preferences they care about.
	/// </summary>
	/// <param name="objThreadState">A string containing the name of the Branch that changed</param>
	private void _NotifyThreadExecute(object objThreadState)
	{
		PrefChangeEventArgs oArgs = (PrefChangeEventArgs)objThreadState;
		string sBranch = oArgs.PrefName;
		List<EventHandler<PrefChangeEventArgs>> listToNotify = null;
		try
		{
			_RWLockWatchers.EnterReadLock();
			try
			{
				foreach (PrefWatcher wliEntry in _listWatchers)
				{
					if (sBranch.OICStartsWith(wliEntry.sPrefixToWatch))
					{
						if (listToNotify == null)
						{
							listToNotify = new List<EventHandler<PrefChangeEventArgs>>();
						}
						listToNotify.Add(wliEntry.fnToNotify);
					}
				}
			}
			finally
			{
				_RWLockWatchers.ExitReadLock();
			}
			if (listToNotify == null)
			{
				return;
			}
			foreach (EventHandler<PrefChangeEventArgs> oEach in listToNotify)
			{
				try
				{
					oEach(this, oArgs);
				}
				catch (Exception eX2)
				{
					FiddlerApplication.Log.LogString(eX2.ToString());
				}
			}
		}
		catch (Exception eX)
		{
			FiddlerApplication.Log.LogString(eX.ToString());
		}
	}

	/// <summary>
	/// Spawn a background thread to notify any interested Watchers of changes to the Target preference branch.
	/// </summary>
	/// <param name="oNotifyArgs">The arguments to pass to the interested Watchers</param>
	private void AsyncNotifyWatchers(PrefChangeEventArgs oNotifyArgs)
	{
		ThreadPool.UnsafeQueueUserWorkItem(_NotifyThreadExecute, oNotifyArgs);
	}

	public IEnumerator<KeyValuePair<string, string>> GetEnumerator()
	{
		_RWLockPrefs.EnterReadLock();
		DictionaryEntry[] dictionaryEntries = new DictionaryEntry[_dictPrefs.Count];
		_dictPrefs.CopyTo(dictionaryEntries, 0);
		_RWLockPrefs.ExitReadLock();
		for (int i = 0; i < dictionaryEntries.Length; i++)
		{
			yield return new KeyValuePair<string, string>((string)dictionaryEntries[i].Key, (string)dictionaryEntries[i].Value);
		}
	}

	IEnumerator IEnumerable.GetEnumerator()
	{
		return GetEnumerator();
	}
}
