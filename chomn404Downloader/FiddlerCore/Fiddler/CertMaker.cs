using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using BCCertMaker;

namespace Fiddler;

/// <summary>
/// This class is used to find and create certificates for use in HTTPS interception. 
/// The default implementation (DefaultCertProvider object) uses the Windows Certificate store, 
/// but if a plugin ICertificateProvider is provided, it is used instead.
/// </summary>
public class CertMaker
{
	/// <summary>
	/// Enables specification of a delegate certificate provider that generates certificates for HTTPS interception.
	/// </summary>
	public static ICertificateProvider oCertProvider = null;

	/// <summary>
	/// Lock on this object when TestExistenceOf/Create oCertProvider
	/// </summary>
	private static object _lockProvider = new object();

	public static string GetCertProviderInfo()
	{
		EnsureReady();
		if (oCertProvider is DefaultCertificateProvider)
		{
			return ((DefaultCertificateProvider)oCertProvider).GetEngineString();
		}
		string sPath = oCertProvider.GetType().Assembly.Location;
		string sAppPath = CONFIG.GetPath("App");
		if (sPath.StartsWith(sAppPath))
		{
			sPath = sPath.Substring(sAppPath.Length);
		}
		return $"{oCertProvider} from {sPath}";
	}

	/// <summary>
	/// Ensures that the Certificate Generator is ready; thread-safe
	/// </summary>
	public static void EnsureReady()
	{
		if (oCertProvider != null)
		{
			return;
		}
		lock (_lockProvider)
		{
			if (oCertProvider == null)
			{
				oCertProvider = LoadOverrideCertProvider() ?? new global::BCCertMaker.BCCertMaker();
			}
		}
	}

	/// <summary>
	/// Load a delegate Certificate Provider
	/// </summary>
	/// <returns>The provider, or null</returns>
	private static ICertificateProvider LoadOverrideCertProvider()
	{
		string sFile = FiddlerApplication.Prefs.GetStringPref("fiddler.certmaker.assembly", CONFIG.GetPath("App") + "CertMaker.dll");
		Assembly a;
		try
		{
			if (!File.Exists(sFile))
			{
				FiddlerApplication.Log.LogFormat("Assembly '{0}' was not found. Using default Certificate Generator.", sFile);
				return null;
			}
			a = Assembly.UnsafeLoadFrom(sFile);
			if (!Utilities.FiddlerMeetsVersionRequirement(a, "Certificate Makers"))
			{
				FiddlerApplication.Log.LogFormat("Assembly '{0}' did not specify a RequiredVersionAttribute. Aborting load of Certificate Generation module.", sFile);
				return null;
			}
		}
		catch (Exception eX2)
		{
			FiddlerApplication.Log.LogFormat("Failed to load CertMaker from '{0}' due to '{1}'.", sFile, eX2.Message);
			return null;
		}
		Type[] exportedTypes = a.GetExportedTypes();
		foreach (Type t in exportedTypes)
		{
			if (t.IsClass && !t.IsAbstract && t.IsPublic && typeof(ICertificateProvider).IsAssignableFrom(t))
			{
				try
				{
					return (ICertificateProvider)Activator.CreateInstance(t);
				}
				catch (Exception eX)
				{
					string title = "Load Error";
					string message = $"[Fiddler] Failure loading '{t.Name}' CertMaker from {sFile}: {eX.Message}\n\n{eX.StackTrace}\n\n{eX.InnerException}";
					FiddlerApplication.Log.LogFormat("{0}: {1}", title, message);
				}
			}
		}
		FiddlerApplication.Log.LogFormat("Assembly '{0}' did not contain a recognized ICertificateProvider.", sFile);
		return null;
	}

	/// <summary>
	/// Removes Fiddler-generated certificates from the Windows certificate store
	/// </summary>
	public static bool removeFiddlerGeneratedCerts()
	{
		return removeFiddlerGeneratedCerts(bRemoveRoot: true);
	}

	/// <summary>
	/// Removes Fiddler-generated certificates from the Windows certificate store
	/// </summary>
	/// <param name="bRemoveRoot">Indicates whether Root certificates should also be cleaned up</param>
	public static bool removeFiddlerGeneratedCerts(bool bRemoveRoot)
	{
		EnsureReady();
		if (oCertProvider is ICertificateProvider2)
		{
			return (oCertProvider as ICertificateProvider2).ClearCertificateCache(bRemoveRoot);
		}
		return oCertProvider.ClearCertificateCache();
	}

	/// <summary>
	/// Returns the Root certificate that Fiddler uses to generate per-site certificates used for HTTPS interception.
	/// </summary>
	/// <returns>Returns the root certificate, if present, or null if the root certificate does not exist.</returns>
	public static X509Certificate2 GetRootCertificate()
	{
		EnsureReady();
		return oCertProvider.GetRootCertificate();
	}

	/// <summary>
	/// Return the raw byte[]s of the root certificate, or null
	/// </summary>
	/// <returns></returns>
	internal static byte[] getRootCertBytes()
	{
		return GetRootCertificate()?.Export(X509ContentType.Cert);
	}

	internal static bool exportRootToDesktop()
	{
		try
		{
			byte[] arrRoot = getRootCertBytes();
			if (arrRoot != null)
			{
				string folderPath = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
				char directorySeparatorChar = Path.DirectorySeparatorChar;
				File.WriteAllBytes(folderPath + directorySeparatorChar + "FiddlerRoot.cer", arrRoot);
				return true;
			}
			string title2 = "Export Failed";
			string message = "The root certificate could not be located.";
			FiddlerApplication.Log.LogFormat("{0}: {1}", title2, message);
		}
		catch (Exception eX)
		{
			string title = "Certificate Export Failed";
			FiddlerApplication.Log.LogFormat("{0}: {1}", title, eX.ToString());
		}
		return false;
	}

	/// <summary>
	/// Request a certificate with the specified SubjectCN
	/// </summary>
	/// <param name="sHostname">A string of the form: "www.hostname.com"</param>
	/// <returns>A certificate or /null/ if the certificate could not be found or created</returns>
	public static X509Certificate2 FindCert(string sHostname)
	{
		EnsureReady();
		return oCertProvider.GetCertificateForHost(sHostname);
	}

	/// <summary>
	/// Pre-cache a Certificate in the Certificate Maker that should be returned in subsequent calls to FindCert
	/// </summary>
	/// <param name="sHost">The hostname for which this certificate should be returned.</param>
	/// <param name="oCert">The X509Certificate2 with attached Private Key</param>
	/// <returns>TRUE if the Certificate Provider succeeded in pre-caching the certificate. FALSE if Provider doesn't support pre-caching. THROWS if supplied Certificate lacks Private Key.</returns>
	public static bool StoreCert(string sHost, X509Certificate2 oCert)
	{
		if (!oCert.HasPrivateKey)
		{
			throw new ArgumentException("The provided certificate MUST have a private key.", "oCert");
		}
		EnsureReady();
		if (!(oCertProvider is ICertificateProvider3 oCP))
		{
			return false;
		}
		return oCP.CacheCertificateForHost(sHost, oCert);
	}

	/// <summary>
	/// Pre-cache a Certificate in the Certificate Maker that should be returned in subsequent calls to FindCert
	/// </summary>
	/// <param name="sHost">The hostname for which this certificate should be returned.</param>
	/// <param name="sPFXFilename">The filename of the PFX file containing the certificate and private key</param>
	/// <param name="sPFXPassword">The password for the PFX file</param>
	/// <notes>Throws if the Certificate Provider failed to pre-cache the certificate</notes>
	public static void StoreCert(string sHost, string sPFXFilename, string sPFXPassword)
	{
		X509Certificate2 oCert = new X509Certificate2(sPFXFilename, sPFXPassword);
		if (!StoreCert(sHost, oCert))
		{
			throw new InvalidOperationException("The current ICertificateProvider does not support storing custom certificates.");
		}
	}

	/// <summary>
	/// Determine if the self-signed root certificate exists
	/// </summary>
	/// <returns>True if the Root certificate returned from <see cref="M:Fiddler.CertMaker.GetRootCertificate">GetRootCertificate</see> is non-null, False otherwise.</returns>
	public static bool rootCertExists()
	{
		try
		{
			X509Certificate2 oRoot = GetRootCertificate();
			return oRoot != null;
		}
		catch (Exception)
		{
			return false;
		}
	}

	/// <summary>
	/// Is Fiddler's root certificate in the Root store?
	/// </summary>
	/// <returns>TRUE if so</returns>
	public static bool rootCertIsTrusted()
	{
		EnsureReady();
		bool bUserTrusted;
		bool bMachineTrusted;
		return oCertProvider.rootCertIsTrusted(out bUserTrusted, out bMachineTrusted);
	}

	/// <summary>
	/// Is Fiddler's root certificate in the Machine Root store?
	/// </summary>
	/// <returns>TRUE if so</returns>
	public static bool rootCertIsMachineTrusted()
	{
		EnsureReady();
		oCertProvider.rootCertIsTrusted(out var _, out var bMachineTrusted);
		return bMachineTrusted;
	}

	/// <summary>
	/// Create a self-signed root certificate to use as the trust anchor for HTTPS interception certificate chains
	/// </summary>
	/// <returns>TRUE if successful</returns>
	public static bool createRootCert()
	{
		EnsureReady();
		return oCertProvider.CreateRootCertificate();
	}

	/// <summary>
	/// Finds the Fiddler root certificate and prompts the user to add it to the TRUSTED store.
	/// Note: The system certificate store is used by most applications (IE, Chrome, etc) but not
	/// all; for instance, Firefox uses its own certificate store.
	/// </summary>
	/// <returns>True if successful</returns>
	public static bool trustRootCert()
	{
		EnsureReady();
		return oCertProvider.TrustRootCertificate();
	}

	internal static bool flushCertCache()
	{
		EnsureReady();
		if (!(oCertProvider is ICertificateProvider2 oCP))
		{
			return false;
		}
		return oCP.ClearCertificateCache(bClearRoot: false);
	}

	/// <summary>
	/// Dispose of the Certificate Provider, if any.
	/// </summary>
	public static void DoDispose()
	{
		if (FiddlerApplication.Prefs.GetBoolPref("fiddler.CertMaker.CleanupServerCertsOnExit", bDefault: false))
		{
			removeFiddlerGeneratedCerts(bRemoveRoot: false);
		}
		if (oCertProvider is IDisposable oDP)
		{
			oDP.Dispose();
		}
		oCertProvider = null;
	}
}
