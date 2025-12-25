using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using FiddlerCore.Utilities;

namespace Fiddler;

/// <summary>
/// [DEPRECATED] Use the BCCertMaker instead.
/// This is the default Fiddler certificate provider.
/// </summary>
public class DefaultCertificateProvider : ICertificateProvider3, ICertificateProvider2, ICertificateProvider, ICertificateProviderInfo
{
	private interface ICertificateCreator
	{
		X509Certificate2 CreateCert(string sSubject, bool isRoot);
	}

	/// <summary>
	/// CertEnroll is an ActiveX Control available on Windows Vista and later that allows programmatic generation of X509 certificates.
	/// We can use it as an alternative to MakeCert.exe; it offers better behavior (e.g. setting AKID) and doesn't require redistributing makecert.exe
	/// </summary>
	private class CertEnrollEngine : ICertificateCreator
	{
		private ICertificateProvider3 _ParentProvider;

		private Type typeX500DN;

		private Type typeX509PrivateKey;

		private Type typeOID;

		private Type typeOIDS;

		private Type typeKUExt;

		private Type typeEKUExt;

		private Type typeRequestCert;

		private Type typeX509Extensions;

		private Type typeBasicConstraints;

		private Type typeSignerCertificate;

		private Type typeX509Enrollment;

		private Type typeAlternativeName;

		private Type typeAlternativeNames;

		private Type typeAlternativeNamesExt;

		private string sProviderName = "Microsoft Enhanced Cryptographic Provider v1.0";

		private object _oSharedPrivateKey = null;

		/// <summary>
		/// Factory method. Returns null if this engine cannot be created
		/// </summary>
		internal static ICertificateCreator GetEngine(ICertificateProvider3 ParentProvider)
		{
			try
			{
				return new CertEnrollEngine(ParentProvider);
			}
			catch (Exception eX)
			{
				FiddlerApplication.Log.LogFormat("Failed to initialize CertEnrollEngine: {0}", FiddlerCore.Utilities.Utilities.DescribeException(eX));
			}
			return null;
		}

		private CertEnrollEngine(ICertificateProvider3 ParentProvider)
		{
			_ParentProvider = ParentProvider;
			sProviderName = FiddlerApplication.Prefs.GetStringPref("fiddler.certmaker.KeyProviderName", sProviderName);
			typeX500DN = Type.GetTypeFromProgID("X509Enrollment.CX500DistinguishedName", throwOnError: true);
			typeX509PrivateKey = Type.GetTypeFromProgID("X509Enrollment.CX509PrivateKey", throwOnError: true);
			typeOID = Type.GetTypeFromProgID("X509Enrollment.CObjectId", throwOnError: true);
			typeOIDS = Type.GetTypeFromProgID("X509Enrollment.CObjectIds.1", throwOnError: true);
			typeEKUExt = Type.GetTypeFromProgID("X509Enrollment.CX509ExtensionEnhancedKeyUsage");
			typeKUExt = Type.GetTypeFromProgID("X509Enrollment.CX509ExtensionKeyUsage");
			typeRequestCert = Type.GetTypeFromProgID("X509Enrollment.CX509CertificateRequestCertificate");
			typeX509Extensions = Type.GetTypeFromProgID("X509Enrollment.CX509Extensions");
			typeBasicConstraints = Type.GetTypeFromProgID("X509Enrollment.CX509ExtensionBasicConstraints");
			typeSignerCertificate = Type.GetTypeFromProgID("X509Enrollment.CSignerCertificate");
			typeX509Enrollment = Type.GetTypeFromProgID("X509Enrollment.CX509Enrollment");
			typeAlternativeName = Type.GetTypeFromProgID("X509Enrollment.CAlternativeName");
			typeAlternativeNames = Type.GetTypeFromProgID("X509Enrollment.CAlternativeNames");
			typeAlternativeNamesExt = Type.GetTypeFromProgID("X509Enrollment.CX509ExtensionAlternativeNames");
		}

		public X509Certificate2 CreateCert(string sSubjectCN, bool isRoot)
		{
			return InternalCreateCert(sSubjectCN, isRoot, switchToMTAIfNeeded: true);
		}

		/// <summary>
		/// Invoke CertEnroll
		/// </summary>
		/// <param name="sSubjectCN">Target CN</param>
		/// <param name="isRoot">TRUE if the certificate is a root cert</param>
		/// <param name="switchToMTAIfNeeded">TRUE if we should validate that we're running in a MTA thread and switch if not</param>
		/// <returns>A Cert</returns>
		private X509Certificate2 InternalCreateCert(string sSubjectCN, bool isRoot, bool switchToMTAIfNeeded)
		{
			if (switchToMTAIfNeeded && Thread.CurrentThread.GetApartmentState() != ApartmentState.MTA)
			{
				if (CONFIG.bDebugCertificateGeneration)
				{
					FiddlerApplication.Log.LogFormat("/Fiddler.CertMaker> Caller was in ApartmentState: {0}; hopping to Threadpool", Thread.CurrentThread.GetApartmentState().ToString());
				}
				X509Certificate2 newCert = null;
				ManualResetEvent oMRE = new ManualResetEvent(initialState: false);
				ThreadPool.QueueUserWorkItem(delegate
				{
					newCert = InternalCreateCert(sSubjectCN, isRoot, switchToMTAIfNeeded: false);
					oMRE.Set();
				});
				oMRE.WaitOne();
				oMRE.Close();
				return newCert;
			}
			string sFullSubject = $"CN={sSubjectCN}{CONFIG.sMakeCertSubjectO}";
			if (CONFIG.bDebugCertificateGeneration)
			{
				FiddlerApplication.Log.LogFormat("/Fiddler.CertMaker> Invoking CertEnroll for Subject: {0}; Thread's ApartmentState: {1}", sFullSubject, Thread.CurrentThread.GetApartmentState().ToString());
			}
			string sHash = FiddlerApplication.Prefs.GetStringPref(isRoot ? "fiddler.certmaker.ce.Root.SigAlg" : "fiddler.certmaker.ce.EE.SigAlg", "SHA256");
			int iGraceDays = -FiddlerApplication.Prefs.GetInt32Pref("fiddler.certmaker.GraceDays", 366);
			int iValidDays = FiddlerApplication.Prefs.GetInt32Pref("fiddler.certmaker.ValidDays", 820);
			X509Certificate2 oNewCert = null;
			try
			{
				if (isRoot)
				{
					int iPrivateKeyLen2 = FiddlerApplication.Prefs.GetInt32Pref("fiddler.certmaker.ce.Root.KeyLength", 2048);
					oNewCert = GenerateCertificate(bIsRoot: true, sSubjectCN, sFullSubject, iPrivateKeyLen2, sHash, DateTime.Now.AddDays(iGraceDays), DateTime.Now.AddDays(iValidDays), null);
				}
				else
				{
					int iPrivateKeyLen = FiddlerApplication.Prefs.GetInt32Pref("fiddler.certmaker.ce.EE.KeyLength", 2048);
					oNewCert = GenerateCertificate(bIsRoot: false, sSubjectCN, sFullSubject, iPrivateKeyLen, sHash, DateTime.Now.AddDays(iGraceDays), DateTime.Now.AddDays(iValidDays), _ParentProvider.GetRootCertificate());
				}
				if (CONFIG.bDebugCertificateGeneration)
				{
					FiddlerApplication.Log.LogFormat("/Fiddler.CertMaker> Finished CertEnroll for '{0}'. Returning {1}", sFullSubject, (oNewCert != null) ? "cert" : "null");
				}
				return oNewCert;
			}
			catch (Exception eX)
			{
				FiddlerApplication.Log.LogFormat("!ERROR: Failed to generate Certificate using CertEnroll. {0}", FiddlerCore.Utilities.Utilities.DescribeException(eX));
			}
			return null;
		}

		private X509Certificate2 GenerateCertificate(bool bIsRoot, string sSubjectCN, string sFullSubject, int iPrivateKeyLength, string sHashAlg, DateTime dtValidFrom, DateTime dtValidTo, X509Certificate2 oSigningCertificate)
		{
			if (bIsRoot != (oSigningCertificate == null))
			{
				throw new ArgumentException("You must specify a Signing Certificate if and only if you are not creating a root.", "oSigningCertificate");
			}
			object oSubjectDN = Activator.CreateInstance(typeX500DN);
			object[] arrArgs = new object[2] { sFullSubject, 0 };
			typeX500DN.InvokeMember("Encode", BindingFlags.InvokeMethod, null, oSubjectDN, arrArgs);
			object oIssuerDN = Activator.CreateInstance(typeX500DN);
			if (!bIsRoot)
			{
				arrArgs[0] = oSigningCertificate.Subject;
			}
			typeX500DN.InvokeMember("Encode", BindingFlags.InvokeMethod, null, oIssuerDN, arrArgs);
			object oPrivateKey = null;
			if (!bIsRoot)
			{
				oPrivateKey = _oSharedPrivateKey;
			}
			if (oPrivateKey == null)
			{
				oPrivateKey = Activator.CreateInstance(typeX509PrivateKey);
				arrArgs = new object[1] { sProviderName };
				typeX509PrivateKey.InvokeMember("ProviderName", BindingFlags.PutDispProperty, null, oPrivateKey, arrArgs);
				arrArgs[0] = 2;
				typeX509PrivateKey.InvokeMember("ExportPolicy", BindingFlags.PutDispProperty, null, oPrivateKey, arrArgs);
				arrArgs = new object[1] { (!bIsRoot) ? 1 : 2 };
				typeX509PrivateKey.InvokeMember("KeySpec", BindingFlags.PutDispProperty, null, oPrivateKey, arrArgs);
				if (!bIsRoot)
				{
					arrArgs = new object[1] { 176 };
					typeX509PrivateKey.InvokeMember("KeyUsage", BindingFlags.PutDispProperty, null, oPrivateKey, arrArgs);
				}
				arrArgs[0] = iPrivateKeyLength;
				typeX509PrivateKey.InvokeMember("Length", BindingFlags.PutDispProperty, null, oPrivateKey, arrArgs);
				typeX509PrivateKey.InvokeMember("Create", BindingFlags.InvokeMethod, null, oPrivateKey, null);
				if (!bIsRoot)
				{
					_oSharedPrivateKey = oPrivateKey;
				}
			}
			else if (CONFIG.bDebugCertificateGeneration)
			{
				FiddlerApplication.Log.LogFormat("/Fiddler.CertMaker> Reusing PrivateKey for '{0}'", sSubjectCN);
			}
			arrArgs = new object[1];
			object oServerAuthOID = Activator.CreateInstance(typeOID);
			arrArgs[0] = "1.3.6.1.5.5.7.3.1";
			typeOID.InvokeMember("InitializeFromValue", BindingFlags.InvokeMethod, null, oServerAuthOID, arrArgs);
			object oOIDS = Activator.CreateInstance(typeOIDS);
			arrArgs[0] = oServerAuthOID;
			typeOIDS.InvokeMember("Add", BindingFlags.InvokeMethod, null, oOIDS, arrArgs);
			object oEKUExt = Activator.CreateInstance(typeEKUExt);
			arrArgs[0] = oOIDS;
			typeEKUExt.InvokeMember("InitializeEncode", BindingFlags.InvokeMethod, null, oEKUExt, arrArgs);
			object oRequest = Activator.CreateInstance(typeRequestCert);
			arrArgs = new object[3]
			{
				1,
				oPrivateKey,
				string.Empty
			};
			typeRequestCert.InvokeMember("InitializeFromPrivateKey", BindingFlags.InvokeMethod, null, oRequest, arrArgs);
			arrArgs = new object[1] { oSubjectDN };
			typeRequestCert.InvokeMember("Subject", BindingFlags.PutDispProperty, null, oRequest, arrArgs);
			arrArgs[0] = oIssuerDN;
			typeRequestCert.InvokeMember("Issuer", BindingFlags.PutDispProperty, null, oRequest, arrArgs);
			arrArgs[0] = dtValidFrom;
			typeRequestCert.InvokeMember("NotBefore", BindingFlags.PutDispProperty, null, oRequest, arrArgs);
			arrArgs[0] = dtValidTo;
			typeRequestCert.InvokeMember("NotAfter", BindingFlags.PutDispProperty, null, oRequest, arrArgs);
			object oKUExt = Activator.CreateInstance(typeKUExt);
			arrArgs[0] = 176;
			typeKUExt.InvokeMember("InitializeEncode", BindingFlags.InvokeMethod, null, oKUExt, arrArgs);
			object oExtensions = typeRequestCert.InvokeMember("X509Extensions", BindingFlags.GetProperty, null, oRequest, null);
			arrArgs = new object[1];
			if (!bIsRoot)
			{
				arrArgs[0] = oKUExt;
				typeX509Extensions.InvokeMember("Add", BindingFlags.InvokeMethod, null, oExtensions, arrArgs);
			}
			arrArgs[0] = oEKUExt;
			typeX509Extensions.InvokeMember("Add", BindingFlags.InvokeMethod, null, oExtensions, arrArgs);
			if (!bIsRoot && FiddlerApplication.Prefs.GetBoolPref("fiddler.certmaker.AddSubjectAltName", bDefault: true))
			{
				object oSubjectAltName = Activator.CreateInstance(typeAlternativeName);
				IPAddress ipDest = Utilities.IPFromString(sSubjectCN);
				if (ipDest == null)
				{
					arrArgs = new object[2] { 3, sSubjectCN };
					typeAlternativeName.InvokeMember("InitializeFromString", BindingFlags.InvokeMethod, null, oSubjectAltName, arrArgs);
				}
				else
				{
					arrArgs = new object[3]
					{
						8,
						1,
						Convert.ToBase64String(ipDest.GetAddressBytes())
					};
					typeAlternativeName.InvokeMember("InitializeFromRawData", BindingFlags.InvokeMethod, null, oSubjectAltName, arrArgs);
				}
				object objAlternativeNames = Activator.CreateInstance(typeAlternativeNames);
				arrArgs = new object[1] { oSubjectAltName };
				typeAlternativeNames.InvokeMember("Add", BindingFlags.InvokeMethod, null, objAlternativeNames, arrArgs);
				Marshal.ReleaseComObject(oSubjectAltName);
				if (ipDest != null && AddressFamily.InterNetworkV6 == ipDest.AddressFamily)
				{
					oSubjectAltName = Activator.CreateInstance(typeAlternativeName);
					arrArgs = new object[2]
					{
						3,
						"[" + sSubjectCN + "]"
					};
					typeAlternativeName.InvokeMember("InitializeFromString", BindingFlags.InvokeMethod, null, oSubjectAltName, arrArgs);
					arrArgs = new object[1] { oSubjectAltName };
					typeAlternativeNames.InvokeMember("Add", BindingFlags.InvokeMethod, null, objAlternativeNames, arrArgs);
					Marshal.ReleaseComObject(oSubjectAltName);
				}
				object oExtAlternativeNames = Activator.CreateInstance(typeAlternativeNamesExt);
				arrArgs = new object[1] { objAlternativeNames };
				typeAlternativeNamesExt.InvokeMember("InitializeEncode", BindingFlags.InvokeMethod, null, oExtAlternativeNames, arrArgs);
				arrArgs = new object[1] { oExtAlternativeNames };
				typeX509Extensions.InvokeMember("Add", BindingFlags.InvokeMethod, null, oExtensions, arrArgs);
			}
			if (bIsRoot)
			{
				object oBasicConstraints = Activator.CreateInstance(typeBasicConstraints);
				arrArgs = new object[2] { "true", "0" };
				typeBasicConstraints.InvokeMember("InitializeEncode", BindingFlags.InvokeMethod, null, oBasicConstraints, arrArgs);
				arrArgs = new object[1] { oBasicConstraints };
				typeX509Extensions.InvokeMember("Add", BindingFlags.InvokeMethod, null, oExtensions, arrArgs);
			}
			else
			{
				object oCA = Activator.CreateInstance(typeSignerCertificate);
				arrArgs = new object[4] { 0, 0, 12, oSigningCertificate.Thumbprint };
				typeSignerCertificate.InvokeMember("Initialize", BindingFlags.InvokeMethod, null, oCA, arrArgs);
				arrArgs = new object[1] { oCA };
				typeRequestCert.InvokeMember("SignerCertificate", BindingFlags.PutDispProperty, null, oRequest, arrArgs);
			}
			object oHash = Activator.CreateInstance(typeOID);
			arrArgs = new object[4] { 1, 0, 0, sHashAlg };
			typeOID.InvokeMember("InitializeFromAlgorithmName", BindingFlags.InvokeMethod, null, oHash, arrArgs);
			arrArgs = new object[1] { oHash };
			typeRequestCert.InvokeMember("HashAlgorithm", BindingFlags.PutDispProperty, null, oRequest, arrArgs);
			typeRequestCert.InvokeMember("Encode", BindingFlags.InvokeMethod, null, oRequest, null);
			object oEnrollment = Activator.CreateInstance(typeX509Enrollment);
			arrArgs[0] = oRequest;
			typeX509Enrollment.InvokeMember("InitializeFromRequest", BindingFlags.InvokeMethod, null, oEnrollment, arrArgs);
			if (bIsRoot)
			{
				arrArgs[0] = "DO_NOT_TRUST_FiddlerRoot-CE";
				typeX509Enrollment.InvokeMember("CertificateFriendlyName", BindingFlags.PutDispProperty, null, oEnrollment, arrArgs);
			}
			arrArgs[0] = 0;
			object oCert = typeX509Enrollment.InvokeMember("CreateRequest", BindingFlags.InvokeMethod, null, oEnrollment, arrArgs);
			arrArgs = new object[4]
			{
				2,
				oCert,
				0,
				string.Empty
			};
			typeX509Enrollment.InvokeMember("InstallResponse", BindingFlags.InvokeMethod, null, oEnrollment, arrArgs);
			arrArgs = new object[3] { null, 0, 1 };
			string oCertAsString = string.Empty;
			try
			{
				oCertAsString = (string)typeX509Enrollment.InvokeMember("CreatePFX", BindingFlags.InvokeMethod, null, oEnrollment, arrArgs);
			}
			catch (Exception eX)
			{
				FiddlerApplication.Log.LogFormat("!Failed to CreatePFX: {0}", FiddlerCore.Utilities.Utilities.DescribeException(eX));
				return null;
			}
			return new X509Certificate2(Convert.FromBase64String(oCertAsString), string.Empty, X509KeyStorageFlags.Exportable);
		}
	}

	private class MakeCertEngine : ICertificateCreator
	{
		/// <summary>
		/// File path pointing to the location of MakeCert.exe
		/// </summary>
		private string _sMakeCertLocation = null;

		/// <summary>
		/// Hash to use when signing certificates.
		/// Note: sha1 is required on XP (even w/SP3, using sha256 throws 0x80090008).
		/// </summary>
		private string _sDefaultHash = "sha1";

		/// <summary>
		/// Factory method. Returns null if this engine cannot be created
		/// </summary>
		internal static ICertificateCreator GetEngine()
		{
			try
			{
				return new MakeCertEngine();
			}
			catch (Exception eX)
			{
				FiddlerApplication.Log.LogFormat("!Failed to initialize MakeCertEngine: {0}", FiddlerCore.Utilities.Utilities.DescribeException(eX));
			}
			return null;
		}

		/// <summary>
		/// Constructor: Simply cache the path to MakeCert
		/// </summary>
		private MakeCertEngine()
		{
			if (Environment.OSVersion.Version.Major > 5)
			{
				_sDefaultHash = "sha256";
			}
			_sMakeCertLocation = CONFIG.GetPath("MakeCert");
			if (!File.Exists(_sMakeCertLocation))
			{
				FiddlerApplication.Log.LogFormat("Cannot locate:\n\t\"{0}\"\n\nPlease move makecert.exe to the Fiddler installation directory.", _sMakeCertLocation);
				throw new FileNotFoundException("Cannot locate: \"" + _sMakeCertLocation + "\". Please move makecert.exe to the Fiddler installation directory.");
			}
		}

		public X509Certificate2 CreateCert(string sHostname, bool isRoot)
		{
			X509Certificate2 oNewCert = null;
			string sDateFormatString = FiddlerApplication.Prefs.GetStringPref("fiddler.certmaker.DateFormatString", "MM/dd/yyyy");
			int iGraceDays = -FiddlerApplication.Prefs.GetInt32Pref("fiddler.certmaker.GraceDays", 366);
			DateTime dtValidityStarts = DateTime.Now.AddDays(iGraceDays);
			string sCmdLine = ((!isRoot) ? string.Format(CONFIG.sMakeCertParamsEE, sHostname, CONFIG.sMakeCertSubjectO, CONFIG.sMakeCertRootCN, FiddlerApplication.Prefs.GetStringPref("fiddler.certmaker.EE.SigAlg", _sDefaultHash), dtValidityStarts.ToString(sDateFormatString, CultureInfo.InvariantCulture), FiddlerApplication.Prefs.GetStringPref("fiddler.certmaker.EE.extraparams", string.Empty)) : string.Format(CONFIG.sMakeCertParamsRoot, sHostname, CONFIG.sMakeCertSubjectO, CONFIG.sMakeCertRootCN, FiddlerApplication.Prefs.GetStringPref("fiddler.certmaker.Root.SigAlg", _sDefaultHash), dtValidityStarts.ToString(sDateFormatString, CultureInfo.InvariantCulture), FiddlerApplication.Prefs.GetStringPref("fiddler.certmaker.Root.extraparams", string.Empty)));
			if (CONFIG.bDebugCertificateGeneration)
			{
				FiddlerApplication.Log.LogFormat("/Fiddler.CertMaker> Invoking makecert.exe with arguments: {0}", sCmdLine);
			}
			int iExitCode;
			string sErrorText = Utilities.GetExecutableOutput(_sMakeCertLocation, sCmdLine, out iExitCode);
			if (CONFIG.bDebugCertificateGeneration)
			{
				FiddlerApplication.Log.LogFormat("/Fiddler.CertMaker>{3}-CreateCert({0}) => ({1}){2}", sHostname, iExitCode, (iExitCode == 0) ? "." : ("\r\n" + sErrorText), Thread.CurrentThread.ManagedThreadId);
			}
			if (iExitCode == 0)
			{
				int iRetryCount = 6;
				do
				{
					oNewCert = LoadCertificateFromWindowsStore(sHostname);
					Thread.Sleep(50 * (6 - iRetryCount));
					if (CONFIG.bDebugCertificateGeneration && oNewCert == null)
					{
						FiddlerApplication.Log.LogFormat("!WARNING: Couldn't find certificate for {0} on try #{1}", sHostname, 6 - iRetryCount);
					}
					iRetryCount--;
				}
				while (oNewCert == null && iRetryCount >= 0);
			}
			if (oNewCert == null)
			{
				string sError = $"Creation of the interception certificate failed.\n\nmakecert.exe returned {iExitCode}.\n\n{sErrorText}";
				FiddlerApplication.Log.LogFormat("Fiddler.CertMaker> [{0} {1}] Returned Error: {2} ", _sMakeCertLocation, sCmdLine, sError);
			}
			return oNewCert;
		}
	}

	private const int fiddlerCertmakerValidDays = 820;

	/// <summary>
	/// The underlying Certificate Generator (MakeCert or CertEnroll)
	/// </summary>
	private ICertificateCreator CertCreator;

	/// <summary>
	/// Cache of previously-generated EE certificates. Thread safety managed by _oRWLock
	/// </summary>
	private Dictionary<string, X509Certificate2> certServerCache = new Dictionary<string, X509Certificate2>();

	/// <summary>
	/// Cache of previously-generated Root certificate
	/// </summary>
	private X509Certificate2 certRoot = null;

	/// <summary>
	/// Should Fiddler automatically generate wildcard certificates?
	/// </summary>
	private bool UseWildcards;

	private readonly string[] arrWildcardTLDs = new string[5] { ".com", ".org", ".edu", ".gov", ".net" };

	/// <summary>
	/// Reader/Writer lock gates access to the certificate cache and generation functions.
	/// </summary>
	/// <remarks>We must set the SupportsRecursion flag because there are cases where the thread holds the lock in Write mode and then enters Read mode in a nested call.</remarks>
	private ReaderWriterLockSlim _oRWLock = new ReaderWriterLockSlim(LockRecursionPolicy.SupportsRecursion);

	private void GetReaderLock()
	{
		_oRWLock.EnterReadLock();
	}

	private void FreeReaderLock()
	{
		_oRWLock.ExitReadLock();
	}

	private void GetWriterLock()
	{
		_oRWLock.EnterWriteLock();
	}

	private void FreeWriterLock()
	{
		_oRWLock.ExitWriteLock();
	}

	public DefaultCertificateProvider()
	{
		bool bTriedCertEnroll = false;
		if (FiddlerApplication.Prefs.GetBoolPref("fiddler.certmaker.PreferCertEnroll", bDefault: true) && OSSupportsCertEnroll())
		{
			bTriedCertEnroll = true;
			CertCreator = CertEnrollEngine.GetEngine(this);
		}
		if (CertCreator == null)
		{
			CertCreator = MakeCertEngine.GetEngine();
		}
		if (CertCreator == null && !bTriedCertEnroll)
		{
			CertCreator = CertEnrollEngine.GetEngine(this);
		}
		if (CertCreator == null)
		{
			FiddlerApplication.Log.LogFormat("!Fiddler.CertMaker> Critical failure: No Certificate Creation engine could be created. Disabling HTTPS Decryption.");
			CONFIG.DecryptHTTPS = false;
			return;
		}
		UseWildcards = FiddlerApplication.Prefs.GetBoolPref("fiddler.certmaker.UseWildcards", bDefault: true);
		if (CertCreator.GetType() == typeof(MakeCertEngine))
		{
			UseWildcards = false;
		}
		if (CONFIG.bDebugCertificateGeneration)
		{
			FiddlerApplication.Log.LogFormat("/Fiddler.CertMaker> Using {0} for certificate generation; UseWildcards={1}.", CertCreator.GetType().ToString(), UseWildcards);
		}
	}

	private static bool OSSupportsCertEnroll()
	{
		return Environment.OSVersion.Version.Major > 6 || (Environment.OSVersion.Version.Major == 6 && Environment.OSVersion.Version.Minor > 0);
	}

	internal string GetEngineString()
	{
		if (CertCreator.GetType() == typeof(CertEnrollEngine))
		{
			return "CertEnroll engine";
		}
		if (CertCreator.GetType() == typeof(MakeCertEngine))
		{
			return "MakeCert engine";
		}
		return "Unknown engine";
	}

	/// <summary>
	/// Find certificates that have the specified full subject.
	/// </summary>
	/// <param name="storeName">The store to search</param>
	/// <param name="sFullSubject">FindBySubject{Distinguished}Name requires a complete match of the SUBJECT, including CN, O, and OU</param>
	/// <returns>Matching certificates</returns>
	private static X509Certificate2Collection FindCertsBySubject(StoreName storeName, StoreLocation storeLocation, string sFullSubject)
	{
		X509Store certStore = new X509Store(storeName, storeLocation);
		try
		{
			certStore.Open(OpenFlags.OpenExistingOnly);
			return certStore.Certificates.Find(X509FindType.FindBySubjectDistinguishedName, sFullSubject, validOnly: false);
		}
		finally
		{
			certStore.Close();
		}
	}

	/// <summary>
	/// Find all certificates (in the CurrentUser Personal store) that have the specified issuer.
	/// </summary>
	/// <param name="storeName">The store to search</param>
	/// <param name="sFullIssuerSubject">FindByIssuer{Distinguished}Name requires a complete match of the SUBJECT, including CN, O, and OU</param>
	/// <returns>Matching certificates</returns>
	private static X509Certificate2Collection FindCertsByIssuer(StoreName storeName, string sFullIssuerSubject)
	{
		X509Store certStore = new X509Store(storeName, StoreLocation.CurrentUser);
		try
		{
			certStore.Open(OpenFlags.OpenExistingOnly);
			return certStore.Certificates.Find(X509FindType.FindByIssuerDistinguishedName, sFullIssuerSubject, validOnly: false);
		}
		finally
		{
			certStore.Close();
		}
	}

	/// <summary>
	/// Interface method: Clear the in-memory caches and Windows certificate stores
	/// </summary>
	/// <param name="bRemoveRoot">TRUE to clear the Root Certificate from the cache and Windows stores</param>
	/// <returns>TRUE if successful</returns>
	public bool ClearCertificateCache(bool bRemoveRoot)
	{
		bool bResult = true;
		try
		{
			GetWriterLock();
			certServerCache.Clear();
			certRoot = null;
			string sFullRootSubject = $"CN={CONFIG.sMakeCertRootCN}{CONFIG.sMakeCertSubjectO}";
			X509Certificate2Collection oToRemove;
			if (bRemoveRoot)
			{
				oToRemove = FindCertsBySubject(StoreName.Root, StoreLocation.CurrentUser, sFullRootSubject);
				if (oToRemove.Count > 0)
				{
					X509Store certStore2 = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
					certStore2.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
					try
					{
						certStore2.RemoveRange(oToRemove);
					}
					catch
					{
						bResult = false;
					}
					certStore2.Close();
				}
			}
			oToRemove = FindCertsByIssuer(StoreName.My, sFullRootSubject);
			if (oToRemove.Count > 0)
			{
				if (!bRemoveRoot)
				{
					X509Certificate2 oRoot = GetRootCertificate();
					if (oRoot != null)
					{
						oToRemove.Remove(oRoot);
						if (oToRemove.Count < 1)
						{
							return true;
						}
					}
				}
				X509Store certStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
				certStore.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
				try
				{
					certStore.RemoveRange(oToRemove);
				}
				catch
				{
					bResult = false;
				}
				certStore.Close();
			}
		}
		finally
		{
			FreeWriterLock();
		}
		return bResult;
	}

	/// <summary>
	/// Interface method: Clear the in-memory caches and Windows certificate stores
	/// </summary>
	/// <returns></returns>
	public bool ClearCertificateCache()
	{
		return ClearCertificateCache(bRemoveRoot: true);
	}

	public bool rootCertIsTrusted(out bool bUserTrusted, out bool bMachineTrusted)
	{
		bUserTrusted = IsRootCertificateTrusted(StoreLocation.CurrentUser);
		bMachineTrusted = IsRootCertificateTrusted(StoreLocation.LocalMachine);
		return bUserTrusted | bMachineTrusted;
	}

	public bool TrustRootCertificate()
	{
		X509Certificate2 oRoot = GetRootCertificate();
		if (oRoot == null)
		{
			FiddlerApplication.Log.LogString("!Fiddler.CertMaker> The Root certificate could not be found.");
			return false;
		}
		try
		{
			X509Store certStore = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
			certStore.Open(OpenFlags.ReadWrite);
			try
			{
				certStore.Add(oRoot);
			}
			finally
			{
				certStore.Close();
			}
			return true;
		}
		catch (Exception eX)
		{
			FiddlerApplication.Log.LogFormat("!Fiddler.CertMaker> Unable to auto-trust root: {0}", eX);
			return false;
		}
	}

	private static bool IsRootCertificateTrusted(StoreLocation storeLocation)
	{
		X509Certificate2 rootCertificate = CertMaker.GetRootCertificate();
		if (rootCertificate == null)
		{
			return false;
		}
		X509Store store = new X509Store(StoreName.Root, storeLocation);
		try
		{
			store.Open(OpenFlags.MaxAllowed);
			return store.Certificates.Contains(rootCertificate);
		}
		finally
		{
			store.Close();
		}
	}

	/// <summary>
	/// Use MakeCert to generate a unique self-signed certificate
	/// </summary>
	/// <returns>TRUE if the Root certificate was generated successfully</returns>
	public bool CreateRootCertificate()
	{
		return CreateCert(CONFIG.sMakeCertRootCN, isRoot: true) != null;
	}

	/// <summary>
	/// Get the root certificate from cache or storage, only IF IT ALREADY EXISTS.
	/// </summary>
	/// <returns></returns>
	public X509Certificate2 GetRootCertificate()
	{
		if (certRoot != null)
		{
			return certRoot;
		}
		X509Certificate2 oRoot = LoadCertificateFromWindowsStore(CONFIG.sMakeCertRootCN);
		if (CONFIG.bDebugCertificateGeneration)
		{
			if (oRoot != null)
			{
				_LogPrivateKeyContainer(oRoot);
			}
			else
			{
				FiddlerApplication.Log.LogString("DefaultCertMaker: GetRootCertificate() did not find the root in the Windows TrustStore.");
			}
		}
		certRoot = oRoot;
		return oRoot;
	}

	private static void _LogPrivateKeyContainer(X509Certificate2 oRoot)
	{
		try
		{
			if (oRoot != null)
			{
				if (!oRoot.HasPrivateKey)
				{
					FiddlerApplication.Log.LogString("/Fiddler.CertMaker> Root Certificate located but HasPrivateKey==false!");
				}
				FiddlerApplication.Log.LogFormat("/Fiddler.CertMaker> Root Certificate located; private key in container '{0}'", (oRoot.PrivateKey as RSACryptoServiceProvider).CspKeyContainerInfo.UniqueKeyContainerName);
			}
			else
			{
				FiddlerApplication.Log.LogString("/Fiddler.CertMaker> Unable to log Root Certificate private key storage as the certificate was unexpectedly null");
			}
		}
		catch (Exception eX)
		{
			FiddlerApplication.Log.LogFormat("/Fiddler.CertMaker> Failed to identify private key location for Root Certificate. Exception: {0}", FiddlerCore.Utilities.Utilities.DescribeException(eX));
		}
	}

	/// <summary>
	/// Returns an Interception certificate for the specified hostname
	/// </summary>
	/// <param name="sHostname">Hostname for the target certificate</param>
	/// <remarks>This method uses a Reader lock when checking the cache and a Writer lock when updating the cache.</remarks>
	/// <returns>An Interception Certificate, or NULL</returns>
	public X509Certificate2 GetCertificateForHost(string sHostname)
	{
		if (UseWildcards && sHostname.OICEndsWithAny(arrWildcardTLDs) && Utilities.IndexOfNth(sHostname, 2, '.') > 0)
		{
			sHostname = "*." + Utilities.TrimBefore(sHostname, ".");
		}
		X509Certificate2 certResult;
		try
		{
			GetReaderLock();
			if (certServerCache.TryGetValue(sHostname, out certResult))
			{
				return certResult;
			}
		}
		finally
		{
			FreeReaderLock();
		}
		certResult = LoadOrCreateCertificate(sHostname, out var bCreated);
		if (certResult != null && !bCreated)
		{
			CacheCertificateForHost(sHostname, certResult);
		}
		return certResult;
	}

	/// <summary>
	/// Find a certificate from the certificate store, creating a new certificate if it was not found.
	/// </summary>
	/// <param name="sHostname">A SubjectCN hostname, of the form www.example.com</param>
	/// <param name="bAttemptedCreation">TRUE if the cert wasn't found in the Windows Certificate store and this function attempted to create it.</param>
	/// <remarks>No locks are acquired by this method itself.</remarks>
	/// <returns>A certificate or /null/</returns>
	internal X509Certificate2 LoadOrCreateCertificate(string sHostname, out bool bAttemptedCreation)
	{
		bAttemptedCreation = false;
		X509Certificate2 oCert = LoadCertificateFromWindowsStore(sHostname);
		if (oCert != null)
		{
			return oCert;
		}
		bAttemptedCreation = true;
		oCert = CreateCert(sHostname, isRoot: false);
		if (oCert == null)
		{
			FiddlerApplication.Log.LogFormat("!Fiddler.CertMaker> Tried to create cert for '{0}', but can't find it from thread {1}!", sHostname, Thread.CurrentThread.ManagedThreadId);
		}
		return oCert;
	}

	/// <summary>
	/// Find (but do not create!) a certificate from the CurrentUser certificate store, if present.
	/// </summary>
	/// <remarks>No locks are acquired by this method itself.</remarks>
	/// <returns>A certificate or /null/</returns>
	internal static X509Certificate2 LoadCertificateFromWindowsStore(string sHostname)
	{
		X509Store oStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
		try
		{
			oStore.Open(OpenFlags.ReadOnly);
			string sFullSubject = $"CN={sHostname}{CONFIG.sMakeCertSubjectO}";
			X509Certificate2Enumerator enumerator = oStore.Certificates.GetEnumerator();
			while (enumerator.MoveNext())
			{
				X509Certificate2 certCandidate = enumerator.Current;
				if (sFullSubject.OICEquals(certCandidate.Subject))
				{
					return certCandidate;
				}
			}
		}
		finally
		{
			oStore.Close();
		}
		return null;
	}

	/// <summary>
	/// Updates the Server Certificate cache under the Writer lock
	/// </summary>
	/// <param name="sHost">The target hostname</param>
	/// <param name="oCert">The certificate to cache</param>
	/// <returns></returns>
	public bool CacheCertificateForHost(string sHost, X509Certificate2 oCert)
	{
		try
		{
			GetWriterLock();
			certServerCache[sHost] = oCert;
		}
		finally
		{
			FreeWriterLock();
		}
		return true;
	}

	/// <summary>
	/// Creates a certificate for ServerAuth. If isRoot is set, designates that this is a self-signed root.
	/// </summary>
	/// <remarks>Uses a reader lock when checking for the Root certificate. Uses a Writer lock when creating a certificate.</remarks>
	/// <param name="sHostname">A string of the form: "www.hostname.com"</param>
	/// <param name="isRoot">A boolean indicating if this is a request to create the root certificate</param>
	/// <returns>Newly-created certificate, or Null</returns>
	private X509Certificate2 CreateCert(string sHostname, bool isRoot)
	{
		if (sHostname.IndexOfAny(new char[4] { '"', '\r', '\n', '\0' }) != -1)
		{
			return null;
		}
		if (!isRoot && GetRootCertificate() == null)
		{
			try
			{
				GetWriterLock();
				if (GetRootCertificate() == null && !CreateRootCertificate())
				{
					string title = "Certificate Error";
					string message = "Creation of the root certificate was not successful.";
					FiddlerApplication.Log.LogFormat("{0}: {1}", title, message);
					return null;
				}
			}
			finally
			{
				FreeWriterLock();
			}
		}
		X509Certificate2 oNewCert = null;
		try
		{
			GetWriterLock();
			if (!certServerCache.TryGetValue(sHostname, out var oCheckAgain))
			{
				oCheckAgain = LoadCertificateFromWindowsStore(sHostname);
			}
			if (oCheckAgain != null)
			{
				if (CONFIG.bDebugCertificateGeneration)
				{
					FiddlerApplication.Log.LogFormat("/Fiddler.CertMaker>{1} A racing thread already successfully CreatedCert({0})", sHostname, Thread.CurrentThread.ManagedThreadId);
				}
				return oCheckAgain;
			}
			oNewCert = CertCreator.CreateCert(sHostname, isRoot);
			if (oNewCert != null)
			{
				if (isRoot)
				{
					certRoot = oNewCert;
				}
				else
				{
					certServerCache[sHostname] = oNewCert;
				}
			}
		}
		finally
		{
			FreeWriterLock();
		}
		if (oNewCert == null && !isRoot)
		{
			FiddlerApplication.Log.LogFormat("!Fiddler.CertMaker> Failed to create certificate for '{0}'.", sHostname);
			_LogPrivateKeyContainer(GetRootCertificate());
		}
		return oNewCert;
	}

	public string GetConfigurationString()
	{
		if (CertCreator == null)
		{
			return "No Engine Loaded.";
		}
		StringBuilder sbInfo = new StringBuilder();
		string sEngine = Utilities.TrimBefore(CertCreator.GetType().ToString(), "+");
		sbInfo.AppendFormat("Certificate Engine:\t{0}\n", sEngine);
		if (sEngine == "CertEnrollEngine")
		{
			sbInfo.AppendFormat("HashAlg-Root:\t{0}\n", FiddlerApplication.Prefs.GetStringPref("fiddler.certmaker.ce.Root.SigAlg", "SHA256"));
			sbInfo.AppendFormat("HashAlg-EE:\t{0}\n", FiddlerApplication.Prefs.GetStringPref("fiddler.certmaker.ce.EE.SigAlg", "SHA256"));
			sbInfo.AppendFormat("KeyLen-Root:\t{0}bits\n", FiddlerApplication.Prefs.GetInt32Pref("fiddler.certmaker.ce.Root.KeyLength", 2048));
			sbInfo.AppendFormat("KeyLen-EE:\t{0}bits\n", FiddlerApplication.Prefs.GetInt32Pref("fiddler.certmaker.ce.EE.KeyLength", 2048));
			sbInfo.AppendFormat("ValidFrom:\t{0} days ago\n", FiddlerApplication.Prefs.GetInt32Pref("fiddler.certmaker.GraceDays", 366));
			sbInfo.AppendFormat("ValidFor:\t\t{0} days\n", FiddlerApplication.Prefs.GetInt32Pref("fiddler.certmaker.ValidDays", 820));
		}
		else
		{
			sbInfo.AppendFormat("ValidFrom:\t{0} days ago\n", FiddlerApplication.Prefs.GetInt32Pref("fiddler.certmaker.GraceDays", 366));
			sbInfo.AppendFormat("HashAlg-Root:\t{0}\n", FiddlerApplication.Prefs.GetStringPref("fiddler.certmaker.Root.SigAlg", (Environment.OSVersion.Version.Major > 5) ? "SHA256" : "SHA1"));
			sbInfo.AppendFormat("HashAlg-EE:\t{0}\n", FiddlerApplication.Prefs.GetStringPref("fiddler.certmaker.EE.SigAlg", (Environment.OSVersion.Version.Major > 5) ? "SHA256" : "SHA1"));
			sbInfo.AppendFormat("ExtraParams-Root:\t{0}\n", FiddlerApplication.Prefs.GetStringPref("fiddler.certmaker.EE.extraparams", string.Empty));
			sbInfo.AppendFormat("ExtraParams-EE:\t{0}\n", FiddlerApplication.Prefs.GetStringPref("fiddler.certmaker.root.extraparams", string.Empty));
		}
		return sbInfo.ToString();
	}
}
