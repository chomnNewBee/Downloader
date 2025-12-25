using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using Fiddler;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace BCCertMaker;

public class BCCertMaker : ICertificateProvider5, ICertificateProvider4, ICertificateProvider3, ICertificateProvider2, ICertificateProvider, ICertificateProviderInfo, IDisposable
{
	/// <summary>
	/// How long should we wait for parallel creations
	/// </summary>
	private int iParallelTimeout = 25000;

	/// <summary>
	/// "SHA256WITHRSA", "SHA384WITHRSA", "SHA512WITHRSA", "MD5WITHRSA", etc
	/// </summary>
	private string _sDefaultHash = "SHA256WITHRSA";

	/// <summary>
	/// Cache of EndEntity certificates that have been generated in this session.
	/// </summary>
	private Dictionary<string, X509Certificate2> certCache = new Dictionary<string, X509Certificate2>();

	/// <summary>
	/// The ReaderWriter lock gates access to the certCache
	/// </summary>
	private ReaderWriterLock _RWLockForCache = new ReaderWriterLock();

	/// <summary>
	/// Queue of creations in progress, indexed by certificate CN.
	/// ManualResetEvent info: http://msdn.microsoft.com/en-us/library/ksb7zs2x(v=vs.95).aspx
	/// </summary>
	private Dictionary<string, ManualResetEvent> dictCreationQueue = new Dictionary<string, ManualResetEvent>();

	/// <summary>
	/// The ReaderWriter lock gates access to the Queue which ensures we only have one Certificate-Generating-per-Host
	/// </summary>
	private ReaderWriterLock _RWLockForQueue = new ReaderWriterLock();

	/// <summary>
	/// The BouncyCastle Root certificate
	/// </summary>
	private Org.BouncyCastle.X509.X509Certificate oCACert = null;

	/// <summary>
	/// The BouncyCastle Root Private key
	/// </summary>
	private AsymmetricKeyParameter oCAKey = null;

	/// <summary>
	/// The EE Certificate Public/Private key that we'll reuse for all EE certificates if the
	/// preference fiddler.certmaker.bc.ReusePrivateKeys is set.
	/// </summary>
	private AsymmetricCipherKeyPair oEEKeyPair = null;

	/// <summary>
	/// Object we use to lock on when updating oEEKeyPair
	/// </summary>
	private object oEEKeyLock = new object();

	/// <summary>
	/// Object we use to lock on when updating oCACert / OCAKey
	/// </summary>
	private object oCALock = new object();

	/// <summary>
	/// Should Fiddler automatically generate wildcard certificates?
	/// </summary>
	private bool UseWildcards;

	/// <summary>
	/// TLDs for which should Fiddler generate wildcarded 3rd-level-domain certs
	/// </summary>
	private readonly string[] arrWildcardTLDs = new string[5] { ".com", ".org", ".edu", ".gov", ".net" };

	/// <summary>
	/// Length for the Public/Private Key used in the EE certificate
	/// </summary>
	private static int iCertBitness => FiddlerApplication.Prefs.GetInt32Pref("fiddler.certmaker.bc.KeyLength", 2048);

	/// <summary>
	/// Length for the Public/Private Key used in the Root certificate
	/// </summary>
	private static int iRootCertBitness => FiddlerApplication.Prefs.GetInt32Pref("fiddler.certmaker.bc.RootKeyLength", 2048);

	/// <summary>
	/// Should verbose logging information be emitted?
	/// </summary>
	private static bool bDebugSpew => FiddlerApplication.Prefs.GetBoolPref("fiddler.certmaker.bc.Debug", bDefault: false);

	/// <summary>
	/// Controls whether we use the same Public/Private keypair for all Server Certificates  (improves perf)
	/// </summary>
	private static bool bReuseServerKey => FiddlerApplication.Prefs.GetBoolPref("fiddler.certmaker.bc.ReusePrivateKeys", bDefault: true);

	/// <summary>
	/// Controls whether we use the same Public/Private keypair for the root AND all Server Certificates (improves perf)
	/// </summary>
	private static bool bReuseRootKeyAsServerKey => FiddlerApplication.Prefs.GetBoolPref("fiddler.certmaker.bc.ReuseRootKeysForEE", bDefault: true);

	public IDictionary<string, X509Certificate2> CertCache
	{
		get
		{
			_RWLockForCache.AcquireReaderLock(-1);
			IDictionary<string, X509Certificate2> copy = new Dictionary<string, X509Certificate2>(certCache);
			_RWLockForCache.ReleaseReaderLock();
			return copy;
		}
	}

	private static string GetRootFriendly()
	{
		return FiddlerApplication.Prefs.GetStringPref("fiddler.certmaker.bc.RootFriendly", "DO_NOT_TRUST_FiddlerRoot-BC");
	}

	private static string GetRootCN()
	{
		return FiddlerApplication.Prefs.GetStringPref("fiddler.certmaker.bc.RootCN", "DO_NOT_TRUST_FiddlerRoot");
	}

	/// <summary>
	/// Get the base name for the KeyContainer into which the private key goes. If EE Keys are being reused, then we use only
	/// this ID.
	/// </summary>
	/// <returns></returns>
	private string GetKeyContainerNameBase()
	{
		return FiddlerApplication.Prefs.GetStringPref("fiddler.certmaker.bc.KeyContainerName", "FiddlerBCKey");
	}

	/// <summary>
	/// Returns the Subject O field. Note that Fiddler's normal root uses "DO_NOT_TRUST" rather than "DO_NOT_TRUST_BC".
	/// </summary>
	/// <returns></returns>
	private string GetCertO()
	{
		return "DO_NOT_TRUST_BC";
	}

	private string GetCertOU()
	{
		return "Created by http://www.fiddler2.com";
	}

	public BCCertMaker()
	{
		FiddlerApplication.Log.LogFormat("Fiddler ICertificateProvider v{0} loaded.\n\tfiddler.certmaker.bc.Debug:\t{1}\n\tObjectID:\t\t\t0x{2:x}", Assembly.GetExecutingAssembly().GetName().Version.ToString(), bDebugSpew, GetHashCode());
		iParallelTimeout = FiddlerApplication.Prefs.GetInt32Pref("fiddler.certmaker.bc.ParallelTimeout", iParallelTimeout);
		UseWildcards = FiddlerApplication.Prefs.GetBoolPref("fiddler.certmaker.UseWildcards", bDefault: true);
		if (bDebugSpew)
		{
			FiddlerApplication.Log.LogFormat("\tUsing BCMakeCert.dll v{0}", typeof(AttributeX509).Assembly.GetName().Version.ToString());
		}
		if (Environment.OSVersion.Version.Major < 6)
		{
			int iProviderType = FiddlerApplication.Prefs.GetInt32Pref("fiddler.certmaker.bc.KeyProviderType", -1);
			if (iProviderType < 0)
			{
				FiddlerApplication.Prefs.SetInt32Pref("fiddler.certmaker.bc.KeyProviderType", 1);
				return;
			}
			FiddlerApplication.Log.LogFormat("!CertMaker was reconfigured to use KeyProviderType={0}. Values != 1 are expected to fail on Windows XP.", iProviderType);
		}
		else
		{
			_sDefaultHash = "SHA256WITHRSA";
		}
	}

	/// <summary>
	/// Flush EE certificates to force regeneration
	/// </summary>
	private void _InternalFlushEECertCache()
	{
		try
		{
			_RWLockForCache.AcquireWriterLock(-1);
			oEEKeyPair = null;
			if (certCache.Count >= 1)
			{
				certCache.Clear();
			}
		}
		finally
		{
			_RWLockForCache.ReleaseWriterLock();
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
	///
	/// </summary>
	/// <param name="storeName"></param>
	/// <param name="sFullIssuerSubject">FindByIssuer{Distinguished}Name requires a complete match of the SUBJECT, including CN, O, and OU</param>
	/// <returns></returns>
	private static X509Certificate2Collection FindCertsByIssuer(StoreName storeName, StoreLocation storeLocation, string sFullIssuerSubject)
	{
		try
		{
			X509Store certStore = new X509Store(storeName, storeLocation);
			certStore.Open(OpenFlags.OpenExistingOnly);
			X509Certificate2Collection certs = certStore.Certificates.Find(X509FindType.FindByIssuerDistinguishedName, sFullIssuerSubject, validOnly: false);
			certStore.Close();
			if (bDebugSpew)
			{
				FiddlerApplication.Log.LogFormat("Fiddler.BCCertMaker> FindCertsByIssuer found {0} certificates in {1}.{2} matching '{3}'.", certs.Count, storeLocation, storeName, sFullIssuerSubject);
			}
			return certs;
		}
		catch (Exception eX)
		{
			FiddlerApplication.Log.LogFormat("FindCertsByIssuer failed: {0}", eX.Message);
			return new X509Certificate2Collection();
		}
	}

	/// <summary>
	/// Converts from a BouncyCastle Certificate object into a .NET X509Certificate2 object
	/// </summary>
	/// <param name="certBC">A BouncyCastle X509Certificate</param>
	/// <returns>The .NET X509Certificate2</returns>
	private static X509Certificate2 ConvertBCCertToDotNetCert(X509Certificate certBC)
	{
		return new X509Certificate2(DotNetUtilities.ToX509Certificate(certBC));
	}

	private static X509Certificate2 ConvertBCCertToDotNetCert(X509Certificate certBC, AsymmetricKeyParameter privateKey)
	{
		//IL_0001: Unknown result type (might be due to invalid IL or missing references)
		//IL_0007: Expected O, but got Unknown
		//IL_001d: Unknown result type (might be due to invalid IL or missing references)
		//IL_002b: Unknown result type (might be due to invalid IL or missing references)
		//IL_0031: Expected O, but got Unknown
		//IL_0036: Expected O, but got Unknown
		//IL_0046: Unknown result type (might be due to invalid IL or missing references)
		//IL_0050: Expected O, but got Unknown
		Pkcs12StoreBuilder pkcs12StoreBuilder = new Pkcs12StoreBuilder();
		pkcs12StoreBuilder.SetUseDerEncoding(true);
		Pkcs12Store pkcs12Store = pkcs12StoreBuilder.Build();
		pkcs12Store.SetKeyEntry(string.Empty, new AsymmetricKeyEntry(privateKey), (X509CertificateEntry[])(object)new X509CertificateEntry[1]
		{
			new X509CertificateEntry(certBC)
		});
		using MemoryStream pfxStream = new MemoryStream();
		pkcs12Store.Save((Stream)pfxStream, new char[0], new SecureRandom());
		pfxStream.Seek(0L, SeekOrigin.Begin);
		return new X509Certificate2(pfxStream.ToArray());
	}

	/// <summary>
	/// Copy BC cert to Windows Certificate Storage, without key. THROWS on Errors
	/// </summary>
	/// <param name="sFriendlyName"></param>
	/// <param name="newCert"></param>
	/// <param name="oSL"></param>
	/// <param name="oSN"></param>
	private static void AddBCCertToStore(string sFriendlyName, X509Certificate newCert, StoreLocation oSL, StoreName oSN)
	{
		X509Certificate2 certDotNet = ConvertBCCertToDotNetCert(newCert);
		certDotNet.FriendlyName = sFriendlyName;
		X509Store store = new X509Store(oSN, oSL);
		store.Open(OpenFlags.ReadWrite);
		try
		{
			store.Add(certDotNet);
		}
		finally
		{
			store.Close();
		}
	}

	/// <summary>
	/// Generates a new EE Certificate using the given CA Certificate to sign it. Throws on Crypto Exceptions.
	/// </summary>
	/// <param name="sCN"></param>
	/// <param name="caCert"></param>
	/// <param name="caKey"></param>
	/// <returns></returns>
	private X509Certificate2 CreateCertificateFromCA(string sCN, X509Certificate caCert, AsymmetricKeyParameter caKey)
	{
		//IL_0074: Unknown result type (might be due to invalid IL or missing references)
		//IL_007a: Expected O, but got Unknown
		//IL_0089: Unknown result type (might be due to invalid IL or missing references)
		//IL_008f: Expected O, but got Unknown
		//IL_0107: Unknown result type (might be due to invalid IL or missing references)
		//IL_010e: Expected O, but got Unknown
		//IL_0226: Unknown result type (might be due to invalid IL or missing references)
		//IL_0230: Expected O, but got Unknown
		//IL_0203: Unknown result type (might be due to invalid IL or missing references)
		//IL_020d: Expected O, but got Unknown
		//IL_0277: Unknown result type (might be due to invalid IL or missing references)
		//IL_027e: Expected O, but got Unknown
		//IL_025e: Unknown result type (might be due to invalid IL or missing references)
		//IL_0265: Expected O, but got Unknown
		//IL_0168: Unknown result type (might be due to invalid IL or missing references)
		//IL_016f: Expected O, but got Unknown
		//IL_02b9: Unknown result type (might be due to invalid IL or missing references)
		//IL_02c3: Expected O, but got Unknown
		//IL_02be: Unknown result type (might be due to invalid IL or missing references)
		//IL_02c5: Expected O, but got Unknown
		//IL_02c7: Unknown result type (might be due to invalid IL or missing references)
		//IL_02ce: Expected O, but got Unknown
		//IL_0309: Unknown result type (might be due to invalid IL or missing references)
		//IL_0314: Expected O, but got Unknown
		//IL_030f: Unknown result type (might be due to invalid IL or missing references)
		//IL_0316: Expected O, but got Unknown
		//IL_0318: Unknown result type (might be due to invalid IL or missing references)
		//IL_031f: Expected O, but got Unknown
		//IL_0321: Unknown result type (might be due to invalid IL or missing references)
		//IL_0328: Expected O, but got Unknown
		//IL_032c: Unknown result type (might be due to invalid IL or missing references)
		//IL_0333: Expected O, but got Unknown
		//IL_0335: Unknown result type (might be due to invalid IL or missing references)
		//IL_033c: Expected O, but got Unknown
		//IL_01a6: Unknown result type (might be due to invalid IL or missing references)
		//IL_01ac: Expected O, but got Unknown
		//IL_01c9: Unknown result type (might be due to invalid IL or missing references)
		//IL_01d3: Expected O, but got Unknown
		Stopwatch oSW = Stopwatch.StartNew();
		if (bDebugSpew)
		{
			FiddlerApplication.Log.LogFormat("Fiddler.BCCertMaker> CreatingCert for: {0}", sCN);
		}
		AsymmetricCipherKeyPair keyPair = _GetPublicPrivateKeyPair(sCN);
		if (bDebugSpew)
		{
			FiddlerApplication.Log.LogFormat("Fiddler.BCCertMaker> PrivateKey Generation took: {0}ms; {1}-bit key.", oSW.ElapsedMilliseconds, iCertBitness);
		}
		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
		BigInteger serialNumber = new BigInteger(1, Guid.NewGuid().ToByteArray());
		certGen.SetSerialNumber(serialNumber);
		certGen.SetIssuerDN(caCert.IssuerDN);
		certGen.SetNotBefore(DateTime.Today.AddDays(FiddlerApplication.Prefs.GetInt32Pref("fiddler.certmaker.bc.EE.CreatedDaysAgo", -7)));
		certGen.SetNotAfter(DateTime.Today.AddYears(FiddlerApplication.Prefs.GetInt32Pref("fiddler.certmaker.bc.EE.YearsValid", 2)));
		X509Name dnName = new X509Name($"OU={GetCertOU()}, O={GetCertO()}, CN={sCN}");
		certGen.SetSubjectDN(dnName);
		certGen.SetPublicKey(keyPair.Public);
		certGen.SetSignatureAlgorithm(FiddlerApplication.Prefs.GetStringPref("fiddler.certmaker.bc.EE.SigAlg", _sDefaultHash));
		if (FiddlerApplication.Prefs.GetBoolPref("fiddler.certmaker.bc.AddSubjectAltName", bDefault: true))
		{
			IPAddress ipTarget = Utilities.IPFromString(sCN);
			GeneralName name = new GeneralName((ipTarget == null) ? 2 : 7, sCN);
			Asn1Encodable[] SAN = (Asn1Encodable[])(object)((ipTarget == null || ipTarget.AddressFamily != AddressFamily.InterNetworkV6) ? new Asn1Encodable[1] { (Asn1Encodable)name } : new Asn1Encodable[2]
			{
				(Asn1Encodable)name,
				(Asn1Encodable)new GeneralName(2, "[" + sCN + "]")
			});
			certGen.AddExtension(X509Extensions.SubjectAlternativeName, false, (Asn1Encodable)new DerSequence(SAN));
		}
		if (FiddlerApplication.Prefs.GetBoolPref("fiddler.certmaker.bc.EE.SetAKID", bDefault: true))
		{
			certGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, FiddlerApplication.Prefs.GetBoolPref("fiddler.certmaker.bc.EE.CriticalAKID", bDefault: false), (Asn1Encodable)new AuthorityKeyIdentifierStructure(caCert));
		}
		certGen.AddExtension(X509Extensions.BasicConstraints, FiddlerApplication.Prefs.GetBoolPref("fiddler.certmaker.bc.EE.CriticalBasicConstraints", bDefault: false), (Asn1Encodable)new BasicConstraints(false));
		ExtendedKeyUsage oEKU = ((!FiddlerApplication.Prefs.GetBoolPref("fiddler.certmaker.bc.AddClientAuthEKU", bDefault: false)) ? new ExtendedKeyUsage((KeyPurposeID[])(object)new KeyPurposeID[1] { KeyPurposeID.IdKPServerAuth }) : new ExtendedKeyUsage((KeyPurposeID[])(object)new KeyPurposeID[2]
		{
			KeyPurposeID.IdKPServerAuth,
			KeyPurposeID.IdKPClientAuth
		}));
		certGen.AddExtension(X509Extensions.ExtendedKeyUsage, FiddlerApplication.Prefs.GetBoolPref("fiddler.certmaker.bc.EE.CriticalEKU", bDefault: false), (Asn1Encodable)(object)oEKU);
		if (FiddlerApplication.Prefs.GetBoolPref("fiddler.certmaker.bc.AddEVPolicyOID", bDefault: false))
		{
			PolicyInformation pi = new PolicyInformation(new DerObjectIdentifier("2.16.840.1.113733.1.7.23.6"));
			DerSequence sqPolicy = new DerSequence((Asn1Encodable)(object)pi);
			certGen.AddExtension(X509Extensions.CertificatePolicies, false, (Asn1Encodable)(object)sqPolicy);
		}
		if (FiddlerApplication.Prefs.GetBoolPref("fiddler.certmaker.bc.AddCRL", bDefault: false))
		{
			GeneralName gn = new GeneralName((Asn1Object)new DerIA5String(FiddlerApplication.Prefs.GetStringPref("fiddler.certmaker.bc.CRLURL", "http://www.fiddler2.com/revocationlist.crl")), 6);
			GeneralNames gns = new GeneralNames(gn);
			DistributionPointName dpn = new DistributionPointName(gns);
			DistributionPoint distp = new DistributionPoint(dpn, (ReasonFlags)null, (GeneralNames)null);
			DerSequence seq = new DerSequence((Asn1Encodable)(object)distp);
			certGen.AddExtension(X509Extensions.CrlDistributionPoints, false, (Asn1Encodable)(object)seq);
		}
		X509Certificate newCert = certGen.Generate(caKey);
		if (bDebugSpew)
		{
			FiddlerApplication.Log.LogFormat("Fiddler.BCCertMaker> EECert Generation took: {0}ms in total.", oSW.ElapsedMilliseconds);
		}
		oSW.Reset();
		oSW.Start();
		X509Certificate2 certDotNet = ConvertBCCertToDotNetCert(newCert, keyPair.Private);
		if (!certDotNet.HasPrivateKey)
		{
			FiddlerApplication.Log.LogString("Fiddler.BCCertMaker> FAIL: No Private Key");
		}
		if (FiddlerApplication.Prefs.GetBoolPref("fiddler.certmaker.bc.EmitEECertFile", bDefault: false))
		{
			try
			{
				string sFilename = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory) + "\\" + sCN + ".cer";
				File.WriteAllBytes(sFilename, certDotNet.Export(X509ContentType.Cert));
				FiddlerApplication.Log.LogFormat("Wrote file {0}", sFilename);
			}
			catch (Exception eX)
			{
				FiddlerApplication.Log.LogFormat("Failed to write CER file: {0}", eX.ToString());
			}
		}
		if (bDebugSpew)
		{
			FiddlerApplication.Log.LogFormat("Fiddler.BCCertMaker> BC-to-.NET Conversion took: {0}ms.", oSW.ElapsedMilliseconds);
		}
		return certDotNet;
	}

	/// <summary>
	/// Generates (or retrieves from cache) a Public/Private keypair to attach to an EE Certificate
	/// </summary>
	/// <param name="sCN">The CN for the certificate being generated (used for Logging only)</param>
	/// <returns>A KeyPair</returns>
	private AsymmetricCipherKeyPair _GetPublicPrivateKeyPair(string sCN)
	{
		//IL_009b: Unknown result type (might be due to invalid IL or missing references)
		//IL_00a0: Unknown result type (might be due to invalid IL or missing references)
		//IL_00a2: Expected O, but got Unknown
		//IL_00a7: Expected O, but got Unknown
		AsymmetricCipherKeyPair keyPair;
		if (bReuseServerKey | bReuseRootKeyAsServerKey)
		{
			keyPair = oEEKeyPair;
			if (keyPair == null)
			{
				lock (oEEKeyLock)
				{
					keyPair = oEEKeyPair;
					if (keyPair == null)
					{
						if (!bReuseRootKeyAsServerKey || oCAKey == null)
						{
							keyPair = (oEEKeyPair = _GenerateKeyPair());
						}
						else
						{
							if (bDebugSpew)
							{
								FiddlerApplication.Log.LogFormat("Reusing the RootKey as the EEKey.");
							}
							AsymmetricCipherKeyPair val = new AsymmetricCipherKeyPair(oCACert.GetPublicKey(), oCAKey);
							keyPair = val;
							oEEKeyPair = val;
						}
					}
				}
			}
		}
		else
		{
			keyPair = _GenerateKeyPair();
		}
		LogAKey(sCN, keyPair);
		return keyPair;
	}

	private static void LogAKey(string sCN, AsymmetricCipherKeyPair keyPair)
	{
		if (FiddlerApplication.Prefs.GetBoolPref("fiddler.certmaker.bc.LogPrivateKeys", bDefault: false))
		{
			PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private);
			byte[] arrKey = ((Asn1Encodable)((Asn1Encodable)privateKeyInfo).ToAsn1Object()).GetDerEncoded();
			FiddlerApplication.Log.LogFormat("Fiddler.BCCertMaker> Private Key for {0}: {1}", sCN, Convert.ToBase64String(arrKey));
		}
	}

	private static AsymmetricCipherKeyPair _GenerateKeyPair()
	{
		//IL_0001: Unknown result type (might be due to invalid IL or missing references)
		//IL_0007: Expected O, but got Unknown
		//IL_0007: Unknown result type (might be due to invalid IL or missing references)
		//IL_000d: Expected O, but got Unknown
		//IL_0014: Unknown result type (might be due to invalid IL or missing references)
		//IL_001e: Expected O, but got Unknown
		SecureRandom random = new SecureRandom();
		RsaKeyPairGenerator rsaFactory = new RsaKeyPairGenerator();
		rsaFactory.Init(new KeyGenerationParameters(random, iCertBitness));
		return rsaFactory.GenerateKeyPair();
	}

	/// <summary>
	/// Called to make a new cert.
	/// </summary>
	/// <param name="sHostname"></param>
	/// <returns></returns>
	private X509Certificate2 MakeNewCert(string sHostname)
	{
		if (bDebugSpew)
		{
			FiddlerApplication.Log.LogFormat("Fiddler.BCCertMaker> Asked to MakeNewCert({0}) from thread {1}...", sHostname, Thread.CurrentThread.ManagedThreadId);
		}
		X509Certificate2 certNew;
		try
		{
			_RWLockForQueue.AcquireReaderLock(-1);
			dictCreationQueue.TryGetValue(sHostname, out var oWaitForIt);
			_RWLockForQueue.ReleaseLock();
			if (oWaitForIt != null)
			{
				return ReturnCertWhenReady(sHostname, oWaitForIt);
			}
			_RWLockForQueue.AcquireWriterLock(-1);
			if (dictCreationQueue.ContainsKey(sHostname))
			{
				_RWLockForQueue.ReleaseWriterLock();
				return ReturnCertWhenReady(sHostname, dictCreationQueue[sHostname]);
			}
			ManualResetEvent oAnnounceToOthers = new ManualResetEvent(initialState: false);
			dictCreationQueue.Add(sHostname, oAnnounceToOthers);
			_RWLockForQueue.ReleaseWriterLock();
			if (bDebugSpew)
			{
				FiddlerApplication.Log.LogFormat("Proceeding to generate ({0}) on thread {1}.", sHostname, Thread.CurrentThread.ManagedThreadId);
			}
			EnsureRootCertificate();
			certNew = CreateCertificateFromCA(sHostname, oCACert, oCAKey);
		}
		catch (Exception eX)
		{
			FiddlerApplication.Log.LogFormat("Fiddler.BCCertMaker> Failed to create certificate for {0}: {1}\n{2}", sHostname, eX.Message, eX.StackTrace);
			SignalCertificateReady(sHostname);
			return null;
		}
		try
		{
			_RWLockForCache.AcquireWriterLock(-1);
			if (bDebugSpew)
			{
				FiddlerApplication.Log.LogFormat("Fiddler.BCCertMaker> Caching EECert for {0}", sHostname);
			}
			certCache[sHostname] = certNew;
		}
		finally
		{
			_RWLockForCache.ReleaseWriterLock();
		}
		SignalCertificateReady(sHostname);
		return certNew;
	}

	/// <summary>
	/// Waits on the provided event until it is signaled, then returns the contents of the Cert Cache for the specified sHostname
	/// </summary>
	/// <param name="sHostname">The hostname of a Certificate which is pending creation</param>
	/// <param name="oWaitForIt">The event which will be signaled when the cert is ready (max wait is 15 seconds)</param>
	/// <returns>The Certificate (or possibly null)</returns>
	private X509Certificate2 ReturnCertWhenReady(string sHostname, ManualResetEvent oWaitForIt)
	{
		if (bDebugSpew)
		{
			FiddlerApplication.Log.LogFormat("/Queue indicated that creation of certificate [{0}] was in-progress. Waiting up to {1}ms on thread: #{2}", sHostname, iParallelTimeout, Thread.CurrentThread.ManagedThreadId);
		}
		if (oWaitForIt.WaitOne(iParallelTimeout, exitContext: false))
		{
			if (bDebugSpew)
			{
				FiddlerApplication.Log.LogFormat("/Got Signal that certificate [{0}] was ready. Returning to thread #{1}.", sHostname, Thread.CurrentThread.ManagedThreadId);
			}
		}
		else
		{
			FiddlerApplication.Log.LogFormat("!Fiddler Timed out waiting for Signal that certificate [{0}] was ready. Returning to thread #{1}.", sHostname, Thread.CurrentThread.ManagedThreadId);
		}
		try
		{
			return certCache[sHostname];
		}
		catch (Exception)
		{
			FiddlerApplication.Log.LogFormat("!Certificate cache didn't find certificate for [{0}]. Returning null to thread #{1}.", sHostname, Thread.CurrentThread.ManagedThreadId);
			return null;
		}
	}

	/// <summary>
	/// Signals anyone waiting that the certificate desired is now available.
	/// </summary>
	/// <param name="sHostname">Hostname of the target certificate</param>
	private void SignalCertificateReady(string sHostname)
	{
		try
		{
			_RWLockForQueue.AcquireWriterLock(-1);
			if (dictCreationQueue.TryGetValue(sHostname, out var oToNotify))
			{
				if (bDebugSpew)
				{
					FiddlerApplication.Log.LogFormat("/Signaling [{0}] is ready, created by thread {1}.", sHostname, Thread.CurrentThread.ManagedThreadId);
				}
				dictCreationQueue.Remove(sHostname);
				oToNotify.Set();
			}
			else
			{
				FiddlerApplication.Log.LogFormat("!Fiddler.BCCertmaker> Didn't find Event object to notify for {0}", sHostname);
			}
		}
		finally
		{
			_RWLockForQueue.ReleaseWriterLock();
		}
	}

	/// <summary>
	/// Ensure that the Root Certificate exists, loading or generating it if necessary. 
	/// Throws if the root could not be ensured.
	/// </summary>
	private void EnsureRootCertificate()
	{
		if ((oCACert == null || oCAKey == null) && !CreateRootCertificate())
		{
			throw new InvalidOperationException("Unable to create required BC Root certificate.");
		}
	}

	/// <summary>
	/// Finds cert, uses Reader lock.
	/// </summary>
	/// <param name="sHostname"></param>
	/// <returns></returns>
	public X509Certificate2 GetCertificateForHost(string sHostname)
	{
		if (UseWildcards && sHostname.OICEndsWithAny(arrWildcardTLDs) && Utilities.IndexOfNth(sHostname, 2, '.') > 0)
		{
			sHostname = "*." + Utilities.TrimBefore(sHostname, ".");
		}
		try
		{
			_RWLockForCache.AcquireReaderLock(-1);
			if (certCache.TryGetValue(sHostname, out var oResult))
			{
				return oResult;
			}
		}
		finally
		{
			_RWLockForCache.ReleaseReaderLock();
		}
		return MakeNewCert(sHostname);
	}

	/// <summary>
	/// Store a generated Root Certificate and PrivateKey in Preferences.
	/// </summary>
	private void StoreRootInPreference()
	{
		if (FiddlerApplication.Prefs.GetBoolPref("fiddler.certmaker.bc.ReuseRoot", bDefault: true))
		{
			byte[] arrCert = oCACert.GetEncoded();
			FiddlerApplication.Prefs.SetStringPref("fiddler.certmaker.bc.cert", Convert.ToBase64String(arrCert));
			PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(oCAKey);
			byte[] arrKey = ((Asn1Encodable)((Asn1Encodable)privateKeyInfo).ToAsn1Object()).GetDerEncoded();
			FiddlerApplication.Prefs.SetStringPref("fiddler.certmaker.bc.key", Convert.ToBase64String(arrKey));
		}
	}

	/// <summary>
	/// Load a previously-generated Root Certificate and PrivateKey from Preferences.
	/// </summary>
	/// <returns></returns>
	private bool ReloadRootFromPreference()
	{
		//IL_0061: Unknown result type (might be due to invalid IL or missing references)
		//IL_0068: Expected O, but got Unknown
		if (!FiddlerApplication.Prefs.GetBoolPref("fiddler.certmaker.bc.ReuseRoot", bDefault: true))
		{
			return false;
		}
		string sCert = FiddlerApplication.Prefs.GetStringPref("fiddler.certmaker.bc.cert", null);
		string sKey = FiddlerApplication.Prefs.GetStringPref("fiddler.certmaker.bc.key", null);
		if (string.IsNullOrEmpty(sCert) || string.IsNullOrEmpty(sKey))
		{
			return false;
		}
		try
		{
			X509CertificateParser oCP = new X509CertificateParser();
			oCACert = oCP.ReadCertificate(Convert.FromBase64String(sCert));
			oCAKey = PrivateKeyFactory.CreateKey(Convert.FromBase64String(sKey));
			if (bDebugSpew)
			{
				FiddlerApplication.Log.LogFormat("Fiddler.BCCertMaker> Loaded root certificate and key from Preference. SubjectDN:{0}", ((object)oCACert.SubjectDN).ToString());
			}
			return true;
		}
		catch (Exception eX)
		{
			if (bDebugSpew)
			{
				FiddlerApplication.Log.LogFormat("Fiddler.BCCertMaker> Warning: Unable to reload root certificate and key: {0}. Regenerating.", eX.Message);
			}
		}
		oCACert = null;
		oCAKey = null;
		FiddlerApplication.Prefs.RemovePref("fiddler.certmaker.bc.cert");
		FiddlerApplication.Prefs.RemovePref("fiddler.certmaker.bc.key");
		return false;
	}

	public bool CreateRootCertificate()
	{
		//IL_00c1: Unknown result type (might be due to invalid IL or missing references)
		//IL_00c7: Expected O, but got Unknown
		//IL_00c8: Unknown result type (might be due to invalid IL or missing references)
		//IL_00d2: Expected O, but got Unknown
		//IL_00cd: Unknown result type (might be due to invalid IL or missing references)
		//IL_00dc: Expected O, but got Unknown
		//IL_00d7: Unknown result type (might be due to invalid IL or missing references)
		//IL_00e1: Expected O, but got Unknown
		//IL_00ea: Unknown result type (might be due to invalid IL or missing references)
		//IL_00f1: Expected O, but got Unknown
		//IL_0124: Unknown result type (might be due to invalid IL or missing references)
		//IL_012b: Expected O, but got Unknown
		//IL_01b5: Unknown result type (might be due to invalid IL or missing references)
		//IL_01bf: Expected O, but got Unknown
		//IL_01d8: Unknown result type (might be due to invalid IL or missing references)
		//IL_01e2: Expected O, but got Unknown
		//IL_0201: Unknown result type (might be due to invalid IL or missing references)
		//IL_020b: Expected O, but got Unknown
		//IL_0241: Unknown result type (might be due to invalid IL or missing references)
		//IL_024b: Expected O, but got Unknown
		lock (oCALock)
		{
			if (oCAKey != null && oCACert != null)
			{
				if (bDebugSpew)
				{
					FiddlerApplication.Log.LogString("Root Certificate was already created by another thread. Reusing...");
				}
				return true;
			}
			if (ReloadRootFromPreference())
			{
				return true;
			}
			string sSigAlg = FiddlerApplication.Prefs.GetStringPref("fiddler.certmaker.bc.Root.SigAlg", _sDefaultHash);
			if (bDebugSpew)
			{
				FiddlerApplication.Log.LogFormat("!Fiddler.BCCertMaker> Creating new Root certificate from thread #{0}\n\tKey: {1}-bit\n\tSigAlg: {2}\n", Thread.CurrentThread.ManagedThreadId, iRootCertBitness, sSigAlg);
			}
			RsaKeyPairGenerator rsaFactory = new RsaKeyPairGenerator();
			rsaFactory.Init(new KeyGenerationParameters(new SecureRandom((IRandomGenerator)new CryptoApiRandomGenerator()), iRootCertBitness));
			AsymmetricCipherKeyPair keyPair = rsaFactory.GenerateKeyPair();
			X509V3CertificateGenerator v3CertGen = new X509V3CertificateGenerator();
			BigInteger serialNumber = BigInteger.ProbablePrime(120, new Random());
			v3CertGen.SetSerialNumber(serialNumber);
			X509Name certName = new X509Name($"OU={GetCertOU()}, O={GetCertO()}, CN={GetRootCN()}");
			v3CertGen.SetIssuerDN(certName);
			v3CertGen.SetSubjectDN(certName);
			v3CertGen.SetNotBefore(DateTime.Today.AddDays(-7.0));
			v3CertGen.SetNotAfter(DateTime.Now.AddYears(FiddlerApplication.Prefs.GetInt32Pref("fiddler.certmaker.bc.Root.YearsValid", 10)));
			v3CertGen.SetPublicKey(keyPair.Public);
			v3CertGen.SetSignatureAlgorithm(sSigAlg);
			v3CertGen.AddExtension(X509Extensions.BasicConstraints, FiddlerApplication.Prefs.GetBoolPref("fiddler.certmaker.bc.Root.CriticalBasicConstraints", bDefault: true), (Asn1Encodable)new BasicConstraints(0));
			v3CertGen.AddExtension(X509Extensions.KeyUsage, FiddlerApplication.Prefs.GetBoolPref("fiddler.certmaker.bc.Root.CriticalKeyUsage", bDefault: true), (Asn1Encodable)new KeyUsage(4));
			v3CertGen.AddExtension(X509Extensions.SubjectKeyIdentifier, FiddlerApplication.Prefs.GetBoolPref("fiddler.certmaker.bc.Root.CriticalSKID", bDefault: false), (Asn1Encodable)new SubjectKeyIdentifierStructure(keyPair.Public));
			if (FiddlerApplication.Prefs.GetBoolPref("fiddler.certmaker.bc.Root.SetAKID", bDefault: false))
			{
				v3CertGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, FiddlerApplication.Prefs.GetBoolPref("fiddler.certmaker.bc.Root.CriticalAKID", bDefault: false), (Asn1Encodable)new AuthorityKeyIdentifierStructure(keyPair.Public));
			}
			oCACert = v3CertGen.Generate(keyPair.Private);
			oCAKey = keyPair.Private;
		}
		StoreRootInPreference();
		if (FiddlerApplication.Prefs.GetBoolPref("fiddler.certmaker.bc.EmitRootCertFile", bDefault: false))
		{
			string folderPath = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
			char directorySeparatorChar = Path.DirectorySeparatorChar;
			string pfxFile = folderPath + directorySeparatorChar + "FiddlerBCRoot.pfx";
			WriteRootCertificateAndPrivateKeyToPkcs12File(pfxFile, null);
		}
		if (bDebugSpew)
		{
			FiddlerApplication.Log.LogFormat("Fiddler.BCCertMaker> Root certificate created.");
		}
		return true;
	}

	public X509Certificate2 GetRootCertificate()
	{
		if (oCACert == null && !ReloadRootFromPreference())
		{
			return null;
		}
		return ConvertBCCertToDotNetCert(oCACert);
	}

	/// <summary>
	/// Copies the Root certificate into the Current User's Root store. This will show a prompt even if run at Admin.
	/// </summary>
	/// <returns></returns>
	public bool TrustRootCertificate()
	{
		if (oCACert == null)
		{
			FiddlerApplication.Log.LogString("Fiddler.BCCertMaker> Unable to trust Root certificate; not found.");
			return false;
		}
		try
		{
			AddBCCertToStore(GetRootFriendly(), oCACert, StoreLocation.CurrentUser, StoreName.Root);
		}
		catch (Exception eX)
		{
			FiddlerApplication.Log.LogFormat("Fiddler.BCCertMaker> Failed to trust Root certificate: {0}", eX.Message);
			return false;
		}
		return true;
	}

	public bool rootCertIsTrusted(out bool bUserTrusted, out bool bMachineTrusted)
	{
		bUserTrusted = IsRootCertificateTrusted(StoreLocation.CurrentUser);
		bMachineTrusted = IsRootCertificateTrusted(StoreLocation.LocalMachine);
		return bUserTrusted | bMachineTrusted;
	}

	public bool CacheCertificateForHost(string sHost, X509Certificate2 oCert)
	{
		try
		{
			_RWLockForCache.AcquireWriterLock(-1);
			certCache[sHost] = oCert;
		}
		finally
		{
			_RWLockForCache.ReleaseWriterLock();
		}
		return true;
	}

	/// <summary>
	/// Clears the in-memory caches including the Root Certificate.
	/// </summary>
	/// <remarks>
	/// <para>
	/// This method does not delete the private keys of the certificates.
	/// </para>
	/// <para>
	/// In order to delete them, please cast this instance to <see cref="T:Fiddler.ICertificateProvider4" />
	/// and get a copy of the cache by using the <see cref="P:Fiddler.ICertificateProvider4.CertCache" /> property.
	/// </para>
	/// </remarks>
	/// <returns>TRUE if successful</returns>
	public bool ClearCertificateCache()
	{
		return ClearCertificateCache(bClearRoot: true);
	}

	/// <summary>
	/// Clears the in-memory caches.
	/// </summary>
	/// <remarks>
	/// <para>
	/// This method does not delete the private keys of the certificates.
	/// </para>
	/// <para>
	/// In order to delete them, please cast this instance to <see cref="T:Fiddler.ICertificateProvider4" />
	/// and get a copy of the cache by using the <see cref="P:Fiddler.ICertificateProvider4.CertCache" /> property.
	/// </para>
	/// </remarks>
	/// <param name="bClearRoot">TRUE to clear the Root Certificate from the cache.</param>
	/// <returns>TRUE if successful</returns>
	public bool ClearCertificateCache(bool bClearRoot)
	{
		if (bDebugSpew)
		{
			FiddlerApplication.Log.LogString("Fiddler.BCCertMaker> Begin certificate cache cleanup.");
		}
		try
		{
			_InternalFlushEECertCache();
			if (bDebugSpew)
			{
				FiddlerApplication.Log.LogString("Fiddler.BCCertMaker> Purged in-memory cache.");
			}
			if (bClearRoot)
			{
				FiddlerApplication.Prefs.RemovePref("fiddler.certmaker.bc.cert");
				FiddlerApplication.Prefs.RemovePref("fiddler.certmaker.bc.key");
				oCACert = null;
				oCAKey = null;
				X509Certificate2Collection oToRemove = FindCertsByIssuer(StoreName.Root, StoreLocation.CurrentUser, $"CN={GetRootCN()}, O={GetCertO()}, OU={GetCertOU()}");
				if (oToRemove.Count > 0)
				{
					if (bDebugSpew)
					{
						FiddlerApplication.Log.LogFormat("Fiddler.BCCertMaker> Removing {0} certificates from Windows Current User Root Store", oToRemove.Count);
					}
					try
					{
						X509Store certStore = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
						certStore.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
						try
						{
							certStore.RemoveRange(oToRemove);
						}
						catch
						{
						}
						certStore.Close();
					}
					catch
					{
					}
				}
			}
			if (bDebugSpew)
			{
				FiddlerApplication.Log.LogFormat("Fiddler.BCCertMaker> Finished clearing certificate cache (EE{0}).", bClearRoot ? "+Root" : " only");
			}
			return true;
		}
		catch (Exception eX)
		{
			string title = "BCCertMaker Cleanup Failed";
			FiddlerApplication.Log.LogFormat("{0}: {1}", title, eX.ToString());
			return false;
		}
	}

	/// <summary>
	/// Reads the root certificate and its private key from a PKCS#12 formated stream.
	/// </summary>
	/// <param name="pkcs12Stream">The PKCS#12 formated stream.</param>
	/// <param name="password">The password which is used to protect the private key. Could be null or empty if the private key is not protected.</param>
	/// <param name="alias">The alias for the certificate and the private key. If null, the first alias found (if any) will be used.</param>
	public void ReadRootCertificateAndPrivateKeyFromStream(Stream pkcs12Stream, string password, string alias = null)
	{
		ValidateArgumentIsNotNull(pkcs12Stream, "pkcs12Stream");
		Pkcs12Store pkcs12Store = GetPkcs12Store();
		pkcs12Store.Load(pkcs12Stream, PasswordToCharArray(password));
		if (alias == null)
		{
			{
				IEnumerator enumerator = pkcs12Store.Aliases.GetEnumerator();
				try
				{
					if (enumerator.MoveNext())
					{
						string a = (string)enumerator.Current;
						alias = a;
					}
				}
				finally
				{
					IDisposable disposable = enumerator as IDisposable;
					if (disposable != null)
					{
						disposable.Dispose();
					}
				}
			}
		}
		X509CertificateEntry certificateEntry = pkcs12Store.GetCertificate(alias);
		AsymmetricKeyEntry keyEntry = pkcs12Store.GetKey(alias);
		if (certificateEntry == null || keyEntry == null)
		{
			throw new ArgumentException("No certificate and private key with alias: '" + alias + "' were found.");
		}
		oCACert = certificateEntry.Certificate;
		oCAKey = keyEntry.Key;
	}

	/// <summary>
	/// Writes the root certificate and its private key to a PKCS#12 stream.
	/// </summary>
	/// <param name="pkcs12Stream">The PKCS#12 stream.</param>
	/// <param name="password">The password which is used to protect the private key. If null or empty, the private key is written unprotected.</param>
	/// <param name="alias">The alias for the certificate and the private key. If null, a random alias will be created.</param>
	public void WriteRootCertificateAndPrivateKeyToStream(Stream pkcs12Stream, string password, string alias = null)
	{
		//IL_0015: Unknown result type (might be due to invalid IL or missing references)
		//IL_001b: Expected O, but got Unknown
		//IL_0046: Unknown result type (might be due to invalid IL or missing references)
		//IL_0059: Unknown result type (might be due to invalid IL or missing references)
		//IL_005f: Expected O, but got Unknown
		//IL_0064: Expected O, but got Unknown
		ValidateRootCertificateAndPrivateKeyAreInitialized();
		ValidateArgumentIsNotNull(pkcs12Stream, "pkcs12Stream");
		SecureRandom random = new SecureRandom();
		if (alias == null)
		{
			alias = BitConverter.ToString(BitConverter.GetBytes(random.NextLong()));
		}
		Pkcs12Store pkcs12Store = GetPkcs12Store();
		pkcs12Store.SetKeyEntry(alias, new AsymmetricKeyEntry(oCAKey), (X509CertificateEntry[])(object)new X509CertificateEntry[1]
		{
			new X509CertificateEntry(oCACert)
		});
		pkcs12Store.Save(pkcs12Stream, PasswordToCharArray(password), random);
	}

	/// <summary>
	/// Writes the root certificate without the private key to a stream using DER encoding.
	/// </summary>
	/// <param name="stream">The stream.</param>
	public void WriteRootCertificateToStream(Stream stream)
	{
		ValidateRootCertificateIsInitialized();
		ValidateArgumentIsNotNull(stream, "stream");
		X509Certificate2 rootCertificate = ConvertBCCertToDotNetCert(oCACert);
		byte[] rootCertificateByteArray = rootCertificate.Export(X509ContentType.Cert);
		stream.Write(rootCertificateByteArray, 0, rootCertificateByteArray.Length);
	}

	/// <summary>
	/// Reads the root certificate and its private key from the PKCS#12 file (.pfx | .p12).
	/// </summary>
	/// <param name="filename">The filename of the PKCS#12 file (.pfx | .p12)</param>
	/// <param name="password">The password which is used to protect the private key.</param>
	/// <param name="alias">The alias for the certificate and the private key. If null, the first alias in the pkcs12 will be used.</param>
	public void ReadRootCertificateAndPrivateKeyFromPkcs12File(string filename, string password, string alias = null)
	{
		using FileStream fileStream = new FileStream(filename, FileMode.Open);
		ReadRootCertificateAndPrivateKeyFromStream(fileStream, password, alias);
	}

	/// <summary>
	/// Writes the root certificate and its private key to a PKCS#12 file (.pfx | .p12).
	/// </summary>
	/// <param name="filename">The filename of the PKCS#12 file (.pfx | .p12).</param>
	/// <param name="password">The password which is used to protect the private key.</param>
	/// <param name="alias">The alias for the certificate and the private key. If null, a random alias will be created.</param>
	public void WriteRootCertificateAndPrivateKeyToPkcs12File(string filename, string password, string alias = null)
	{
		using FileStream stream = new FileStream(filename, FileMode.CreateNew);
		WriteRootCertificateAndPrivateKeyToStream(stream, password, alias);
	}

	/// <summary>
	/// Writes the root certificate without the private key to a DER encoded file(.cer | .crt | .der).
	/// </summary>
	/// <param name="filename">The filename of the DER encoded file (.cer | .crt | .der)</param>
	public void WriteRootCertificateToDerEncodedFile(string filename)
	{
		using FileStream stream = new FileStream(filename, FileMode.CreateNew);
		WriteRootCertificateToStream(stream);
	}

	private Pkcs12Store GetPkcs12Store()
	{
		//IL_0001: Unknown result type (might be due to invalid IL or missing references)
		//IL_0007: Expected O, but got Unknown
		Pkcs12StoreBuilder pkcs12StoreBuilder = new Pkcs12StoreBuilder();
		return pkcs12StoreBuilder.Build();
	}

	private char[] PasswordToCharArray(string password)
	{
		if (string.IsNullOrEmpty(password))
		{
			return new char[0];
		}
		return password.ToCharArray();
	}

	private void ValidateArgumentIsNotNull(object arg, string argName)
	{
		if (arg == null)
		{
			throw new ArgumentNullException(argName, "The argument '" + argName + "' cannot be null.");
		}
	}

	private void ValidateRootCertificateIsInitialized()
	{
		if (oCACert == null)
		{
			throw new InvalidOperationException("There is no root certificate.");
		}
	}

	private void ValidateRootCertificateAndPrivateKeyAreInitialized()
	{
		ValidateRootCertificateIsInitialized();
		if (oCAKey == null)
		{
			throw new InvalidOperationException("There is no root certificate private key.");
		}
	}

	/// <summary>
	/// Dispose by clearing all of the EE Certificates' private keys, preventing pollution of the user's \Microsoft\Crypto\RSA\ folder.
	/// </summary>
	public void Dispose()
	{
		_InternalFlushEECertCache();
	}

	public string GetConfigurationString()
	{
		StringBuilder sbInfo = new StringBuilder();
		sbInfo.AppendFormat("Certificate Engine:\t{0}\n", GetType());
		sbInfo.AppendFormat("Engine Version:\t{0}\n\n", FileVersionInfo.GetVersionInfo(Assembly.GetExecutingAssembly().Location).FileVersion.ToString());
		sbInfo.AppendFormat("ValidFrom:\t{0} days ago\n", -FiddlerApplication.Prefs.GetInt32Pref("fiddler.certmaker.bc.EE.CreatedDaysAgo", -7));
		sbInfo.AppendFormat("ValidFor:\t\t{0} years\n", FiddlerApplication.Prefs.GetInt32Pref("fiddler.certmaker.bc.EE.YearsValid", 2));
		sbInfo.AppendFormat("HashAlg:\t\t{0}\n", _sDefaultHash);
		sbInfo.AppendFormat("KeyLen:\t\t{0}\n", FiddlerApplication.Prefs.GetInt32Pref("fiddler.certmaker.bc.KeyLength", 2048));
		sbInfo.AppendFormat("RootKeyLen:\t{0}\n", FiddlerApplication.Prefs.GetInt32Pref("fiddler.certmaker.bc.RootKeyLength", 2048));
		sbInfo.AppendFormat("ReuseServerKeys:\t{0}\n", FiddlerApplication.Prefs.GetBoolPref("fiddler.certmaker.bc.ReusePrivateKeys", bDefault: true));
		return sbInfo.ToString();
	}
}
