using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;

namespace Fiddler;

/// <summary>
/// Fiddler Transcoders allow import and export of Sessions from Fiddler
/// </summary>
public class FiddlerTranscoders : IDisposable
{
	internal Dictionary<string, TranscoderTuple> m_Importers = new Dictionary<string, TranscoderTuple>();

	internal Dictionary<string, TranscoderTuple> m_Exporters = new Dictionary<string, TranscoderTuple>();

	/// <summary>
	/// True if one or more classes implementing ISessionImporter are available.
	/// </summary>
	internal bool hasImporters => m_Importers != null && m_Importers.Count > 0;

	/// <summary>
	/// True if one or more classes implementing ISessionImporter are available.
	/// </summary>
	internal bool hasExporters => m_Exporters != null && m_Exporters.Count > 0;

	/// <summary>
	/// Create the FiddlerTranscoders object
	/// </summary>
	internal FiddlerTranscoders()
	{
	}

	internal string[] getImportFormats()
	{
		EnsureTranscoders();
		if (!hasImporters)
		{
			return new string[0];
		}
		string[] arrResult = new string[m_Importers.Count];
		m_Importers.Keys.CopyTo(arrResult, 0);
		return arrResult;
	}

	internal string[] getExportFormats()
	{
		EnsureTranscoders();
		if (!hasExporters)
		{
			return new string[0];
		}
		string[] arrResult = new string[m_Exporters.Count];
		m_Exporters.Keys.CopyTo(arrResult, 0);
		return arrResult;
	}

	/// <summary>
	/// List all of the Transcoder objects that are loaded
	/// </summary>
	/// <returns></returns>
	public override string ToString()
	{
		StringBuilder sbFormats = new StringBuilder();
		sbFormats.AppendLine("IMPORT FORMATS");
		string[] importFormats = getImportFormats();
		foreach (string s in importFormats)
		{
			sbFormats.AppendFormat("\t{0}\n", s);
		}
		sbFormats.AppendLine("\nEXPORT FORMATS");
		string[] exportFormats = getExportFormats();
		foreach (string s2 in exportFormats)
		{
			sbFormats.AppendFormat("\t{0}\n", s2);
		}
		return sbFormats.ToString();
	}

	/// <summary>
	/// Add Import/Export encoders to FiddlerApplication.oTranscoders
	/// </summary>
	/// <param name="sAssemblyPath">Assembly to import exporters and importers</param>
	/// <returns>FALSE on obvious errors</returns>
	public bool ImportTranscoders(string sAssemblyPath)
	{
		try
		{
			if (!File.Exists(sAssemblyPath))
			{
				return false;
			}
			if (!CONFIG.bRunningOnCLRv4)
			{
				throw new Exception("Not reachable.");
			}
			Assembly a = Assembly.UnsafeLoadFrom(sAssemblyPath);
			if (!ScanAssemblyForTranscoders(a))
			{
				return false;
			}
		}
		catch (Exception eX)
		{
			FiddlerApplication.Log.LogFormat("Failed to load Transcoders from {0}; exception {1}", sAssemblyPath, eX.Message);
			return false;
		}
		return true;
	}

	/// <summary>
	/// Add Import/Export encoders to FiddlerApplication.oTranscoders
	/// </summary>
	/// <param name="assemblyInput">Assembly to scan for transcoders</param>
	/// <returns>FALSE on obvious errors</returns>
	public bool ImportTranscoders(Assembly assemblyInput)
	{
		try
		{
			if (!ScanAssemblyForTranscoders(assemblyInput))
			{
				return false;
			}
		}
		catch (Exception eX)
		{
			FiddlerApplication.Log.LogFormat("Failed to load Transcoders from {0}; exception {1}", assemblyInput.Location, eX.Message);
			return false;
		}
		return true;
	}

	private void ScanPathForTranscoders(string sPath)
	{
		ScanPathForTranscoders(sPath, bIsSubfolder: false);
	}

	/// <summary>
	/// Loads any assembly in the specified path that ends with .dll and does not start with "_", checks that a compatible version requirement was specified, 
	/// and adds the importer and exporters within to the collection.
	/// </summary>
	/// <param name="sPath">The path to scan for extensions</param>
	private void ScanPathForTranscoders(string sPath, bool bIsSubfolder)
	{
		try
		{
			if (!Directory.Exists(sPath))
			{
				return;
			}
			bool bNoisyLogging = FiddlerApplication.Prefs.GetBoolPref("fiddler.debug.extensions.verbose", bDefault: false);
			if (bNoisyLogging)
			{
				FiddlerApplication.Log.LogFormat("Searching for Transcoders under {0}", sPath);
			}
			if (!bIsSubfolder)
			{
				DirectoryInfo[] oDirectories = new DirectoryInfo(sPath).GetDirectories("*.ext");
				DirectoryInfo[] array = oDirectories;
				foreach (DirectoryInfo oDir in array)
				{
					ScanPathForTranscoders(oDir.FullName, bIsSubfolder: true);
				}
			}
			FileInfo[] oFiles = new DirectoryInfo(sPath).GetFiles(bIsSubfolder ? "Fiddler*.dll" : "*.dll");
			FileInfo[] array2 = oFiles;
			foreach (FileInfo oFile in array2)
			{
				if (!bIsSubfolder && Utilities.IsNotExtension(oFile.Name))
				{
					continue;
				}
				if (bNoisyLogging)
				{
					FiddlerApplication.Log.LogFormat("Looking for Transcoders inside {0}", oFile.FullName.ToString());
				}
				Assembly a;
				try
				{
					if (!CONFIG.bRunningOnCLRv4)
					{
						throw new Exception("Not reachable");
					}
					a = Assembly.UnsafeLoadFrom(oFile.FullName);
				}
				catch (Exception eX2)
				{
					FiddlerApplication.LogAddonException(eX2, "Failed to load " + oFile.FullName);
					continue;
				}
				ScanAssemblyForTranscoders(a);
			}
		}
		catch (Exception eX)
		{
			string title = "Transcoders Load Error";
			string message = $"[Fiddler] Failure loading Transcoders: {eX.Message}";
			FiddlerApplication.Log.LogFormat("{0}: {1}", title, message);
		}
	}

	private bool ScanAssemblyForTranscoders(Assembly assemblyInput)
	{
		bool bFoundTranscoders = false;
		bool bNoisyLogging = FiddlerApplication.Prefs.GetBoolPref("fiddler.debug.extensions.verbose", bDefault: false);
		try
		{
			if (!Utilities.FiddlerMeetsVersionRequirement(assemblyInput, "Importers and Exporters"))
			{
				FiddlerApplication.Log.LogFormat("Assembly {0} did not specify a RequiredVersionAttribute. Aborting load of transcoders.", assemblyInput.CodeBase);
				return false;
			}
			Type[] exportedTypes = assemblyInput.GetExportedTypes();
			foreach (Type t in exportedTypes)
			{
				if (t.IsAbstract || !t.IsPublic || !t.IsClass)
				{
					continue;
				}
				if (typeof(ISessionImporter).IsAssignableFrom(t))
				{
					try
					{
						if (!AddToImportOrExportCollection(m_Importers, t))
						{
							FiddlerApplication.Log.LogFormat("WARNING: SessionImporter {0} from {1} failed to specify any ImportExportFormat attributes.", t.Name, assemblyInput.CodeBase);
						}
						else
						{
							bFoundTranscoders = true;
							if (bNoisyLogging)
							{
								FiddlerApplication.Log.LogFormat("    Added SessionImporter {0}", t.FullName);
							}
						}
					}
					catch (Exception eX3)
					{
						string title3 = "Extension Load Error";
						string message3 = $"[Fiddler] Failure loading {t.Name} SessionImporter from {assemblyInput.CodeBase}: {eX3.Message}\n\n{eX3.StackTrace}\n\n{eX3.InnerException}";
						FiddlerApplication.Log.LogFormat("{0}: {1}", title3, message3);
					}
				}
				if (!typeof(ISessionExporter).IsAssignableFrom(t))
				{
					continue;
				}
				try
				{
					if (!AddToImportOrExportCollection(m_Exporters, t))
					{
						FiddlerApplication.Log.LogFormat("WARNING: SessionExporter {0} from {1} failed to specify any ImportExportFormat attributes.", t.Name, assemblyInput.CodeBase);
						continue;
					}
					bFoundTranscoders = true;
					if (bNoisyLogging)
					{
						FiddlerApplication.Log.LogFormat("    Added SessionExporter {0}", t.FullName);
					}
				}
				catch (Exception eX2)
				{
					string title2 = "Extension Load Error";
					string message2 = $"[Fiddler] Failure loading {t.Name} SessionExporter from {assemblyInput.CodeBase}: {eX2.Message}\n\n{eX2.StackTrace}\n\n{eX2.InnerException}";
					FiddlerApplication.Log.LogFormat("{0}: {1}", title2, message2);
				}
			}
		}
		catch (Exception eX)
		{
			string title = "Extension Load Error";
			string message = $"[Fiddler] Failure loading Importer/Exporter from {assemblyInput.CodeBase}: {eX.Message}";
			FiddlerApplication.Log.LogFormat("{0}: {1}", title, message);
			return false;
		}
		return bFoundTranscoders;
	}

	/// <summary>
	/// Ensures that Import/Export Transcoders have been loaded
	/// </summary>
	private void EnsureTranscoders()
	{
	}

	/// <summary>
	/// Returns a TranscoderTuple willing to handle the specified format
	/// </summary>
	/// <param name="sExportFormat">The Format</param>
	/// <returns>TranscoderTuple, or null</returns>
	public TranscoderTuple GetExporter(string sExportFormat)
	{
		EnsureTranscoders();
		if (m_Exporters == null)
		{
			return null;
		}
		if (!m_Exporters.TryGetValue(sExportFormat, out var ttVal))
		{
			return null;
		}
		return ttVal;
	}

	/// <summary>
	/// Returns a TranscoderTuple willing to handle the specified format
	/// </summary>
	/// <param name="sImportFormat">The Format</param>
	/// <returns>TranscoderTuple, or null</returns>
	public TranscoderTuple GetImporter(string sImportFormat)
	{
		EnsureTranscoders();
		if (m_Importers == null)
		{
			return null;
		}
		if (!m_Importers.TryGetValue(sImportFormat, out var ttVal))
		{
			return null;
		}
		return ttVal;
	}

	internal TranscoderTuple GetImporterForExtension(string sExt)
	{
		EnsureTranscoders();
		if (!hasImporters)
		{
			return null;
		}
		foreach (TranscoderTuple tt in m_Importers.Values)
		{
			if (tt.HandlesExtension(sExt))
			{
				return tt;
			}
		}
		return null;
	}

	/// <summary>
	/// Gets the format list of the specified type and adds that type to the collection.
	/// </summary>
	/// <param name="oCollection"></param>
	/// <param name="t"></param>
	/// <returns>TRUE if any formats were found; FALSE otherwise</returns>
	private static bool AddToImportOrExportCollection(Dictionary<string, TranscoderTuple> oCollection, Type t)
	{
		bool bHasFormatSpecifier = false;
		ProfferFormatAttribute[] oValues = (ProfferFormatAttribute[])Attribute.GetCustomAttributes(t, typeof(ProfferFormatAttribute));
		if (oValues != null && oValues.Length != 0)
		{
			bHasFormatSpecifier = true;
			ProfferFormatAttribute[] array = oValues;
			foreach (ProfferFormatAttribute iFA in array)
			{
				if (!oCollection.ContainsKey(iFA.FormatName))
				{
					oCollection.Add(iFA.FormatName, new TranscoderTuple(iFA, t));
				}
			}
		}
		return bHasFormatSpecifier;
	}

	/// <summary>
	/// Clear Importer and Exporter collections
	/// </summary>
	public void Dispose()
	{
		if (m_Exporters != null)
		{
			m_Exporters.Clear();
		}
		if (m_Importers != null)
		{
			m_Importers.Clear();
		}
		m_Importers = (m_Exporters = null);
	}
}
