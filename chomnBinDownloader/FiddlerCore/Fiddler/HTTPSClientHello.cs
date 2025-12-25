using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Fiddler;

/// <summary>
/// The HTTPSClientHello class is used to parse the bytes of a HTTPS ClientHello message.
/// </summary>
internal class HTTPSClientHello
{
	private int _HandshakeVersion;

	private int _MessageLen;

	private int _MajorVersion;

	private int _MinorVersion;

	private byte[] _Random;

	private byte[] _SessionID;

	private uint[] _CipherSuites;

	private byte[] _CompressionSuites;

	private string _ServerNameIndicator;

	private List<string> _Extensions;

	internal static readonly string[] HTTPSCompressionSuites = new string[2] { "NO_COMPRESSION", "DEFLATE" };

	internal static readonly string[] SSL3CipherSuites = new string[31]
	{
		"SSL_NULL_WITH_NULL_NULL", "SSL_RSA_WITH_NULL_MD5", "SSL_RSA_WITH_NULL_SHA", "SSL_RSA_EXPORT_WITH_RC4_40_MD5", "SSL_RSA_WITH_RC4_128_MD5", "SSL_RSA_WITH_RC4_128_SHA", "SSL_RSA_EXPORT_WITH_RC2_40_MD5", "SSL_RSA_WITH_IDEA_SHA", "SSL_RSA_EXPORT_WITH_DES40_SHA", "SSL_RSA_WITH_DES_SHA",
		"SSL_RSA_WITH_3DES_EDE_SHA", "SSL_DH_DSS_EXPORT_WITH_DES40_SHA", "SSL_DH_DSS_WITH_DES_SHA", "SSL_DH_DSS_WITH_3DES_EDE_SHA", "SSL_DH_RSA_EXPORT_WITH_DES40_SHA", "SSL_DH_RSA_WITH_DES_SHA", "SSL_DH_RSA_WITH_3DES_EDE_SHA", "SSL_DHE_DSS_EXPORT_WITH_DES40_SHA", "SSL_DHE_DSS_WITH_DES_SHA", "SSL_DHE_DSS_WITH_3DES_EDE_SHA",
		"SSL_DHE_RSA_EXPORT_WITH_DES40_SHA", "SSL_DHE_RSA_WITH_DES_SHA", "SSL_DHE_RSA_WITH_3DES_EDE_SHA", "SSL_DH_anon_EXPORT_WITH_RC4_40_MD5", "SSL_DH_anon_WITH_RC4_128_MD5", "SSL_DH_anon_EXPORT_WITH_DES40_SHA", "SSL_DH_anon_WITH_DES_SHA", "SSL_DH_anon_WITH_3DES_EDE_SHA", "SSL_FORTEZZA_KEA_WITH_NULL_SHA", "SSL_FORTEZZA_KEA_WITH_FORTEZZA_SHA",
		"SSL_FORTEZZA_KEA_WITH_RC4_128_SHA"
	};

	/// <summary>
	/// Map cipher id numbers to names. See http://www.iana.org/assignments/tls-parameters/
	/// Format is PROTOCOL_KEYAGREEMENT_AUTHENTICATIONMECHANISM_CIPHER_MACPRIMITIVE
	/// </summary>
	internal static readonly Dictionary<uint, string> dictTLSCipherSuites = new Dictionary<uint, string>
	{
		{ 0u, "TLS_NULL_WITH_NULL_NULL" },
		{ 1u, "TLS_RSA_WITH_NULL_MD5" },
		{ 2u, "TLS_RSA_WITH_NULL_SHA" },
		{ 3u, "TLS_RSA_EXPORT_WITH_RC4_40_MD5" },
		{ 4u, "TLS_RSA_WITH_RC4_128_MD5" },
		{ 5u, "TLS_RSA_WITH_RC4_128_SHA" },
		{ 6u, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5" },
		{ 7u, "TLS_RSA_WITH_IDEA_CBC_SHA" },
		{ 8u, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA" },
		{ 9u, "TLS_RSA_WITH_DES_CBC_SHA" },
		{ 10u, "TLS_RSA_WITH_3DES_EDE_CBC_SHA" },
		{ 11u, "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA" },
		{ 12u, "TLS_DH_DSS_WITH_DES_CBC_SHA" },
		{ 13u, "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA" },
		{ 14u, "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA" },
		{ 15u, "TLS_DH_RSA_WITH_DES_CBC_SHA" },
		{ 16u, "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA" },
		{ 17u, "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA" },
		{ 18u, "TLS_DHE_DSS_WITH_DES_CBC_SHA" },
		{ 19u, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA" },
		{ 20u, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA" },
		{ 21u, "TLS_DHE_RSA_WITH_DES_CBC_SHA" },
		{ 22u, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA" },
		{ 23u, "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5" },
		{ 24u, "TLS_DH_anon_WITH_RC4_128_MD5" },
		{ 25u, "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA" },
		{ 26u, "TLS_DH_anon_WITH_DES_CBC_SHA" },
		{ 27u, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA" },
		{ 30u, "TLS_KRB5_WITH_DES_CBC_SHA" },
		{ 31u, "TLS_KRB5_WITH_3DES_EDE_CBC_SHA" },
		{ 32u, "TLS_KRB5_WITH_RC4_128_SHA" },
		{ 33u, "TLS_KRB5_WITH_IDEA_CBC_SHA" },
		{ 34u, "TLS_KRB5_WITH_DES_CBC_MD5" },
		{ 35u, "TLS_KRB5_WITH_3DES_EDE_CBC_MD5" },
		{ 36u, "TLS_KRB5_WITH_RC4_128_MD5" },
		{ 37u, "TLS_KRB5_WITH_IDEA_CBC_MD5" },
		{ 38u, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA" },
		{ 39u, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA" },
		{ 40u, "TLS_KRB5_EXPORT_WITH_RC4_40_SHA" },
		{ 41u, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5" },
		{ 42u, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5" },
		{ 43u, "TLS_KRB5_EXPORT_WITH_RC4_40_MD5" },
		{ 44u, "TLS_PSK_WITH_NULL_SHA" },
		{ 45u, "TLS_DHE_PSK_WITH_NULL_SHA" },
		{ 46u, "TLS_RSA_PSK_WITH_NULL_SHA" },
		{ 47u, "TLS_RSA_WITH_AES_128_CBC_SHA" },
		{ 48u, "TLS_DH_DSS_WITH_AES_128_CBC_SHA" },
		{ 49u, "TLS_DH_RSA_WITH_AES_128_CBC_SHA" },
		{ 50u, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA" },
		{ 51u, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA" },
		{ 52u, "TLS_DH_anon_WITH_AES_128_CBC_SHA" },
		{ 53u, "TLS_RSA_WITH_AES_256_CBC_SHA" },
		{ 54u, "TLS_DH_DSS_WITH_AES_256_CBC_SHA" },
		{ 55u, "TLS_DH_RSA_WITH_AES_256_CBC_SHA" },
		{ 56u, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA" },
		{ 57u, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA" },
		{ 58u, "TLS_DH_anon_WITH_AES_256_CBC_SHA" },
		{ 59u, "TLS_RSA_WITH_NULL_SHA256" },
		{ 60u, "TLS_RSA_WITH_AES_128_CBC_SHA256" },
		{ 61u, "TLS_RSA_WITH_AES_256_CBC_SHA256" },
		{ 62u, "TLS_DH_DSS_WITH_AES_128_CBC_SHA256" },
		{ 63u, "TLS_DH_RSA_WITH_AES_128_CBC_SHA256" },
		{ 64u, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256" },
		{ 65u, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA" },
		{ 66u, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA" },
		{ 67u, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA" },
		{ 68u, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA" },
		{ 69u, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA" },
		{ 70u, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA" },
		{ 103u, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256" },
		{ 104u, "TLS_DH_DSS_WITH_AES_256_CBC_SHA256" },
		{ 105u, "TLS_DH_RSA_WITH_AES_256_CBC_SHA256" },
		{ 106u, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256" },
		{ 107u, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256" },
		{ 108u, "TLS_DH_anon_WITH_AES_128_CBC_SHA256" },
		{ 109u, "TLS_DH_anon_WITH_AES_256_CBC_SHA256" },
		{ 132u, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA" },
		{ 133u, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA" },
		{ 134u, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA" },
		{ 135u, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA" },
		{ 136u, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA" },
		{ 137u, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA" },
		{ 138u, "TLS_PSK_WITH_RC4_128_SHA" },
		{ 139u, "TLS_PSK_WITH_3DES_EDE_CBC_SHA" },
		{ 140u, "TLS_PSK_WITH_AES_128_CBC_SHA" },
		{ 141u, "TLS_PSK_WITH_AES_256_CBC_SHA" },
		{ 142u, "TLS_DHE_PSK_WITH_RC4_128_SHA" },
		{ 143u, "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA" },
		{ 144u, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA" },
		{ 145u, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA" },
		{ 146u, "TLS_RSA_PSK_WITH_RC4_128_SHA" },
		{ 147u, "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA" },
		{ 148u, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA" },
		{ 149u, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA" },
		{ 150u, "TLS_RSA_WITH_SEED_CBC_SHA" },
		{ 151u, "TLS_DH_DSS_WITH_SEED_CBC_SHA" },
		{ 152u, "TLS_DH_RSA_WITH_SEED_CBC_SHA" },
		{ 153u, "TLS_DHE_DSS_WITH_SEED_CBC_SHA" },
		{ 154u, "TLS_DHE_RSA_WITH_SEED_CBC_SHA" },
		{ 155u, "TLS_DH_anon_WITH_SEED_CBC_SHA" },
		{ 156u, "TLS_RSA_WITH_AES_128_GCM_SHA256" },
		{ 157u, "TLS_RSA_WITH_AES_256_GCM_SHA384" },
		{ 158u, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256" },
		{ 159u, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384" },
		{ 160u, "TLS_DH_RSA_WITH_AES_128_GCM_SHA256" },
		{ 161u, "TLS_DH_RSA_WITH_AES_256_GCM_SHA384" },
		{ 162u, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256" },
		{ 163u, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384" },
		{ 164u, "TLS_DH_DSS_WITH_AES_128_GCM_SHA256" },
		{ 165u, "TLS_DH_DSS_WITH_AES_256_GCM_SHA384" },
		{ 166u, "TLS_DH_anon_WITH_AES_128_GCM_SHA256" },
		{ 167u, "TLS_DH_anon_WITH_AES_256_GCM_SHA384" },
		{ 168u, "TLS_PSK_WITH_AES_128_GCM_SHA256" },
		{ 169u, "TLS_PSK_WITH_AES_256_GCM_SHA384" },
		{ 170u, "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256" },
		{ 171u, "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384" },
		{ 172u, "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256" },
		{ 173u, "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384" },
		{ 174u, "TLS_PSK_WITH_AES_128_CBC_SHA256" },
		{ 175u, "TLS_PSK_WITH_AES_256_CBC_SHA384" },
		{ 176u, "TLS_PSK_WITH_NULL_SHA256" },
		{ 177u, "TLS_PSK_WITH_NULL_SHA384" },
		{ 178u, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256" },
		{ 179u, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384" },
		{ 180u, "TLS_DHE_PSK_WITH_NULL_SHA256" },
		{ 181u, "TLS_DHE_PSK_WITH_NULL_SHA384" },
		{ 182u, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256" },
		{ 183u, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384" },
		{ 184u, "TLS_RSA_PSK_WITH_NULL_SHA256" },
		{ 185u, "TLS_RSA_PSK_WITH_NULL_SHA384" },
		{ 186u, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
		{ 187u, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256" },
		{ 188u, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
		{ 189u, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256" },
		{ 190u, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
		{ 191u, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256" },
		{ 192u, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256" },
		{ 193u, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256" },
		{ 194u, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256" },
		{ 195u, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256" },
		{ 196u, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256" },
		{ 197u, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256" },
		{ 198u, "TLS_SM4_GCM_SM3" },
		{ 199u, "TLS_SM4_CCM_SM3" },
		{ 255u, "TLS_EMPTY_RENEGOTIATION_INFO_SCSV" },
		{ 4865u, "TLS_AES_128_GCM_SHA256" },
		{ 4866u, "TLS_AES_256_GCM_SHA384" },
		{ 4867u, "TLS_CHACHA20_POLY1305_SHA256" },
		{ 4868u, "TLS_AES_128_CCM_SHA256" },
		{ 4869u, "TLS_AES_128_CCM_8_SHA256" },
		{ 22016u, "TLS_FALLBACK_SCSV" },
		{ 49153u, "TLS_ECDH_ECDSA_WITH_NULL_SHA" },
		{ 49154u, "TLS_ECDH_ECDSA_WITH_RC4_128_SHA" },
		{ 49155u, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA" },
		{ 49156u, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA" },
		{ 49157u, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA" },
		{ 49158u, "TLS_ECDHE_ECDSA_WITH_NULL_SHA" },
		{ 49159u, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA" },
		{ 49160u, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA" },
		{ 49161u, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA" },
		{ 49162u, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA" },
		{ 49163u, "TLS_ECDH_RSA_WITH_NULL_SHA" },
		{ 49164u, "TLS_ECDH_RSA_WITH_RC4_128_SHA" },
		{ 49165u, "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA" },
		{ 49166u, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA" },
		{ 49167u, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA" },
		{ 49168u, "TLS_ECDHE_RSA_WITH_NULL_SHA" },
		{ 49169u, "TLS_ECDHE_RSA_WITH_RC4_128_SHA" },
		{ 49170u, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA" },
		{ 49171u, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" },
		{ 49172u, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA" },
		{ 49173u, "TLS_ECDH_anon_WITH_NULL_SHA" },
		{ 49174u, "TLS_ECDH_anon_WITH_RC4_128_SHA" },
		{ 49175u, "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA" },
		{ 49176u, "TLS_ECDH_anon_WITH_AES_128_CBC_SHA" },
		{ 49177u, "TLS_ECDH_anon_WITH_AES_256_CBC_SHA" },
		{ 49178u, "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA" },
		{ 49179u, "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA" },
		{ 49180u, "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA" },
		{ 49181u, "TLS_SRP_SHA_WITH_AES_128_CBC_SHA" },
		{ 49182u, "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA" },
		{ 49183u, "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA" },
		{ 49184u, "TLS_SRP_SHA_WITH_AES_256_CBC_SHA" },
		{ 49185u, "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA" },
		{ 49186u, "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA" },
		{ 49187u, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256" },
		{ 49188u, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384" },
		{ 49189u, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256" },
		{ 49190u, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384" },
		{ 49191u, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256" },
		{ 49192u, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384" },
		{ 49193u, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256" },
		{ 49194u, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384" },
		{ 49195u, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" },
		{ 49196u, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" },
		{ 49197u, "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256" },
		{ 49198u, "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384" },
		{ 49199u, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" },
		{ 49200u, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" },
		{ 49201u, "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256" },
		{ 49202u, "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384" },
		{ 49203u, "TLS_ECDHE_PSK_WITH_RC4_128_SHA" },
		{ 49204u, "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA" },
		{ 49205u, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA" },
		{ 49206u, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA" },
		{ 49207u, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256" },
		{ 49208u, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384" },
		{ 49209u, "TLS_ECDHE_PSK_WITH_NULL_SHA" },
		{ 49210u, "TLS_ECDHE_PSK_WITH_NULL_SHA256" },
		{ 49211u, "TLS_ECDHE_PSK_WITH_NULL_SHA384" },
		{ 49212u, "TLS_RSA_WITH_ARIA_128_CBC_SHA256" },
		{ 49213u, "TLS_RSA_WITH_ARIA_256_CBC_SHA384" },
		{ 49214u, "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256" },
		{ 49215u, "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384" },
		{ 49216u, "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256" },
		{ 49217u, "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384" },
		{ 49218u, "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256" },
		{ 49219u, "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384" },
		{ 49220u, "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256" },
		{ 49221u, "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384" },
		{ 49222u, "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256" },
		{ 49223u, "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384" },
		{ 49224u, "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256" },
		{ 49225u, "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384" },
		{ 49226u, "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256" },
		{ 49227u, "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384" },
		{ 49228u, "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256" },
		{ 49229u, "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384" },
		{ 49230u, "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256" },
		{ 49231u, "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384" },
		{ 49232u, "TLS_RSA_WITH_ARIA_128_GCM_SHA256" },
		{ 49233u, "TLS_RSA_WITH_ARIA_256_GCM_SHA384" },
		{ 49234u, "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256" },
		{ 49235u, "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384" },
		{ 49236u, "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256" },
		{ 49237u, "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384" },
		{ 49238u, "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256" },
		{ 49239u, "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384" },
		{ 49240u, "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256" },
		{ 49241u, "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384" },
		{ 49242u, "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256" },
		{ 49243u, "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384" },
		{ 49244u, "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256" },
		{ 49245u, "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384" },
		{ 49246u, "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256" },
		{ 49247u, "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384" },
		{ 49248u, "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256" },
		{ 49249u, "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384" },
		{ 49250u, "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256" },
		{ 49251u, "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384" },
		{ 49252u, "TLS_PSK_WITH_ARIA_128_CBC_SHA256" },
		{ 49253u, "TLS_PSK_WITH_ARIA_256_CBC_SHA384" },
		{ 49254u, "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256" },
		{ 49255u, "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384" },
		{ 49256u, "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256" },
		{ 49257u, "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384" },
		{ 49258u, "TLS_PSK_WITH_ARIA_128_GCM_SHA256" },
		{ 49259u, "TLS_PSK_WITH_ARIA_256_GCM_SHA384" },
		{ 49260u, "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256" },
		{ 49261u, "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384" },
		{ 49262u, "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256" },
		{ 49263u, "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384" },
		{ 49264u, "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256" },
		{ 49265u, "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384" },
		{ 49266u, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256" },
		{ 49267u, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384" },
		{ 49268u, "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256" },
		{ 49269u, "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384" },
		{ 49270u, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
		{ 49271u, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384" },
		{ 49272u, "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
		{ 49273u, "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384" },
		{ 49274u, "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256" },
		{ 49275u, "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384" },
		{ 49276u, "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256" },
		{ 49277u, "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384" },
		{ 49278u, "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256" },
		{ 49279u, "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384" },
		{ 49280u, "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256" },
		{ 49281u, "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384" },
		{ 49282u, "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256" },
		{ 49283u, "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384" },
		{ 49284u, "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256" },
		{ 49285u, "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384" },
		{ 49286u, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256" },
		{ 49287u, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384" },
		{ 49288u, "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256" },
		{ 49289u, "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384" },
		{ 49290u, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256" },
		{ 49291u, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384" },
		{ 49292u, "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256" },
		{ 49293u, "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384" },
		{ 49294u, "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256" },
		{ 49295u, "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384" },
		{ 49296u, "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256" },
		{ 49297u, "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384" },
		{ 49298u, "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256" },
		{ 49299u, "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384" },
		{ 49300u, "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256" },
		{ 49301u, "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384" },
		{ 49302u, "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256" },
		{ 49303u, "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384" },
		{ 49304u, "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256" },
		{ 49305u, "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384" },
		{ 49306u, "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256" },
		{ 49307u, "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384" },
		{ 49308u, "TLS_RSA_WITH_AES_128_CCM" },
		{ 49309u, "TLS_RSA_WITH_AES_256_CCM" },
		{ 49310u, "TLS_DHE_RSA_WITH_AES_128_CCM" },
		{ 49311u, "TLS_DHE_RSA_WITH_AES_256_CCM" },
		{ 49312u, "TLS_RSA_WITH_AES_128_CCM_8" },
		{ 49313u, "TLS_RSA_WITH_AES_256_CCM_8" },
		{ 49314u, "TLS_DHE_RSA_WITH_AES_128_CCM_8" },
		{ 49315u, "TLS_DHE_RSA_WITH_AES_256_CCM_8" },
		{ 49316u, "TLS_PSK_WITH_AES_128_CCM" },
		{ 49317u, "TLS_PSK_WITH_AES_256_CCM" },
		{ 49318u, "TLS_DHE_PSK_WITH_AES_128_CCM" },
		{ 49319u, "TLS_DHE_PSK_WITH_AES_256_CCM" },
		{ 49320u, "TLS_PSK_WITH_AES_128_CCM_8" },
		{ 49321u, "TLS_PSK_WITH_AES_256_CCM_8" },
		{ 49322u, "TLS_PSK_DHE_WITH_AES_128_CCM_8" },
		{ 49323u, "TLS_PSK_DHE_WITH_AES_256_CCM_8" },
		{ 49324u, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM" },
		{ 49325u, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM" },
		{ 49326u, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8" },
		{ 49327u, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8" },
		{ 49328u, "TLS_ECCPWD_WITH_AES_128_GCM_SHA256" },
		{ 49329u, "TLS_ECCPWD_WITH_AES_256_GCM_SHA384" },
		{ 49330u, "TLS_ECCPWD_WITH_AES_128_CCM_SHA256" },
		{ 49331u, "TLS_ECCPWD_WITH_AES_256_CCM_SHA384" },
		{ 49332u, "TLS_SHA256_SHA256" },
		{ 49333u, "TLS_SHA384_SHA384" },
		{ 49408u, "TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC" },
		{ 49409u, "TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC" },
		{ 49410u, "TLS_GOSTR341112_256_WITH_28147_CNT_IMIT" },
		{ 52392u, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" },
		{ 52393u, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" },
		{ 52394u, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256" },
		{ 52395u, "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256" },
		{ 52396u, "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256" },
		{ 52397u, "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256" },
		{ 52398u, "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256" },
		{ 53249u, "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256" },
		{ 53250u, "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384" },
		{ 53251u, "TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256" },
		{ 53253u, "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256" }
	};

	public string ServerNameIndicator
	{
		get
		{
			if (!string.IsNullOrEmpty(_ServerNameIndicator))
			{
				return _ServerNameIndicator;
			}
			return string.Empty;
		}
	}

	public string SessionID
	{
		get
		{
			if (_SessionID == null)
			{
				return string.Empty;
			}
			return Utilities.ByteArrayToString(_SessionID);
		}
	}

	private static string CipherSuitesToString(uint[] inArr)
	{
		if (inArr == null)
		{
			return "null";
		}
		if (inArr.Length == 0)
		{
			return "empty";
		}
		StringBuilder sbOutput = new StringBuilder(inArr.Length * 20);
		for (int i = 0; i < inArr.Length; i++)
		{
			sbOutput.Append("\t[" + inArr[i].ToString("X4") + "]\t");
			string sSuite;
			if (inArr[i] < SSL3CipherSuites.Length)
			{
				sbOutput.AppendLine(SSL3CipherSuites[inArr[i]]);
			}
			else if (dictTLSCipherSuites.TryGetValue(inArr[i], out sSuite))
			{
				sbOutput.AppendLine(sSuite);
			}
			else
			{
				sbOutput.AppendLine("Unrecognized cipher - See https://www.iana.org/assignments/tls-parameters/");
			}
		}
		return sbOutput.ToString();
	}

	private static string CompressionSuitesToString(byte[] inArr)
	{
		if (inArr == null)
		{
			return "(not specified)";
		}
		if (inArr.Length == 0)
		{
			return "(none)";
		}
		StringBuilder sbOutput = new StringBuilder();
		for (int i = 0; i < inArr.Length; i++)
		{
			sbOutput.Append("\t[" + inArr[i].ToString("X2") + "]\t");
			if (inArr[i] < HTTPSCompressionSuites.Length)
			{
				sbOutput.AppendLine(HTTPSCompressionSuites[inArr[i]]);
			}
			else
			{
				sbOutput.AppendLine("Unrecognized compression format");
			}
		}
		return sbOutput.ToString();
	}

	private static string ExtensionListToString(List<string> slExts)
	{
		if (slExts == null || slExts.Count < 1)
		{
			return "\tnone";
		}
		return string.Join("\n", slExts.ToArray());
	}

	public override string ToString()
	{
		StringBuilder sbOutput = new StringBuilder(512);
		if (_HandshakeVersion == 2)
		{
			sbOutput.Append("A SSLv2-compatible ClientHello handshake was found. Fiddler extracted the parameters below.\n\n");
		}
		else
		{
			sbOutput.Append("A SSLv3-compatible ClientHello handshake was found. Fiddler extracted the parameters below.\n\n");
		}
		sbOutput.AppendFormat("Version: {0}\n", HTTPSUtilities.HTTPSVersionToString(_MajorVersion, _MinorVersion));
		if(_Random!=null)
		{
            sbOutput.AppendFormat("Random: {0}\n", Utilities.ByteArrayToString(_Random));
            uint uiSecSinceEpoch = (uint)((_Random[3] << 24) + (_Random[2] << 16) + (_Random[1] << 8) + _Random[0]);
            DateTime dtWhen = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc).AddSeconds(uiSecSinceEpoch).ToLocalTime();
            sbOutput.AppendFormat("\"Time\": {0}\n", dtWhen);
        }
		sbOutput.AppendFormat("SessionID: {0}\n", Utilities.ByteArrayToString(_SessionID));
		sbOutput.AppendFormat("Extensions: \n{0}\n", ExtensionListToString(_Extensions));
		sbOutput.AppendFormat("Ciphers: \n{0}\n", CipherSuitesToString(_CipherSuites));
		sbOutput.AppendFormat("Compression: \n{0}\n", CompressionSuitesToString(_CompressionSuites));
		return sbOutput.ToString();
	}

	/// <summary>
	/// Parse ClientHello from stream. See Page 77 of SSL &amp; TLS Essentials
	/// </summary>
	internal bool LoadFromStream(Stream oNS)
	{
		int cBytes = 0;
		switch (oNS.ReadByte())
		{
		case 128:
		{
			_HandshakeVersion = 2;
			int iRecordLen = oNS.ReadByte();
			int iMsgType = oNS.ReadByte();
			_MajorVersion = oNS.ReadByte();
			_MinorVersion = oNS.ReadByte();
			if (_MajorVersion == 0 && _MinorVersion == 2)
			{
				_MajorVersion = 2;
				_MinorVersion = 0;
			}
			int iCiphersLen = oNS.ReadByte() << 8;
			iCiphersLen += oNS.ReadByte();
			int iSessionIDLen = oNS.ReadByte() << 8;
			iSessionIDLen += oNS.ReadByte();
			int iRandomLen = oNS.ReadByte() << 8;
			iRandomLen += oNS.ReadByte();
			_CipherSuites = new uint[iCiphersLen / 3];
			for (int iCipher = 0; iCipher < _CipherSuites.Length; iCipher++)
			{
				_CipherSuites[iCipher] = (uint)((oNS.ReadByte() << 16) + (oNS.ReadByte() << 8) + oNS.ReadByte());
			}
			_SessionID = new byte[iSessionIDLen];
			cBytes = oNS.Read(_SessionID, 0, _SessionID.Length);
			_Random = new byte[iRandomLen];
			cBytes = oNS.Read(_Random, 0, _Random.Length);
			break;
		}
		case 22:
		{
			_HandshakeVersion = 3;
			_MajorVersion = oNS.ReadByte();
			_MinorVersion = oNS.ReadByte();
			int iRecordLen2 = oNS.ReadByte() << 8;
			iRecordLen2 += oNS.ReadByte();
			int iMsgType2 = oNS.ReadByte();
			if (iMsgType2 != 1)
			{
				return false;
			}
			byte[] data = new byte[3];
			cBytes = oNS.Read(data, 0, data.Length);
			if (cBytes < 3)
			{
				return false;
			}
			_MessageLen = (data[0] << 16) + (data[1] << 8) + data[2];
			_MajorVersion = oNS.ReadByte();
			_MinorVersion = oNS.ReadByte();
			_Random = new byte[32];
			cBytes = oNS.Read(_Random, 0, 32);
			if (cBytes < 32)
			{
				return false;
			}
			int iSessionIDLen2 = oNS.ReadByte();
			_SessionID = new byte[iSessionIDLen2];
			cBytes = oNS.Read(_SessionID, 0, _SessionID.Length);
			data = new byte[2];
			cBytes = oNS.Read(data, 0, data.Length);
			if (cBytes < 2)
			{
				return false;
			}
			int cbCiphers = (data[0] << 8) + data[1];
			_CipherSuites = new uint[cbCiphers / 2];
			data = new byte[cbCiphers];
			cBytes = oNS.Read(data, 0, data.Length);
			if (cBytes != data.Length)
			{
				return false;
			}
			for (int x2 = 0; x2 < _CipherSuites.Length; x2++)
			{
				_CipherSuites[x2] = (uint)((data[2 * x2] << 8) + data[2 * x2 + 1]);
			}
			int cCompressionSuites = oNS.ReadByte();
			if (cCompressionSuites < 1)
			{
				return false;
			}
			_CompressionSuites = new byte[cCompressionSuites];
			for (int x = 0; x < _CompressionSuites.Length; x++)
			{
				int iSuite = oNS.ReadByte();
				if (iSuite < 0)
				{
					return false;
				}
				_CompressionSuites[x] = (byte)iSuite;
			}
			if (_MajorVersion < 3 || (_MajorVersion == 3 && _MinorVersion < 1))
			{
				return true;
			}
			data = new byte[2];
			cBytes = oNS.Read(data, 0, data.Length);
			if (cBytes < 2)
			{
				return true;
			}
			int cExtensionsLen = (data[0] << 8) + data[1];
			if (cExtensionsLen < 1)
			{
				return true;
			}
			data = new byte[cExtensionsLen];
			cBytes = oNS.Read(data, 0, data.Length);
			if (cBytes == data.Length)
			{
				ParseClientHelloExtensions(data);
			}
			break;
		}
		}
		return true;
	}

	/// <summary>
	/// Parse a single extension using the list from http://tools.ietf.org/html/rfc6066
	/// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xml
	/// https://src.chromium.org/viewvc/chrome/trunk/src/net/third_party/nss/ssl/sslt.h
	/// </summary>
	/// <param name="iExtType"></param>
	/// <param name="arrData"></param>
	private void ParseClientHelloExtension(int iExtType, byte[] arrData)
	{
		if (_Extensions == null)
		{
			_Extensions = new List<string>();
		}
		switch (iExtType)
		{
		case 0:
		{
			StringBuilder sbHostList = new StringBuilder();
			int cbHostLen;
			for (int iPtr = 2; iPtr < arrData.Length; iPtr += 3 + cbHostLen)
			{
				int iHostType = arrData[iPtr];
				cbHostLen = (arrData[iPtr + 1] << 8) + arrData[iPtr + 2];
				string sHost = Encoding.ASCII.GetString(arrData, iPtr + 3, cbHostLen);
				if (iHostType == 0)
				{
					_ServerNameIndicator = sHost;
					sbHostList.AppendFormat("{0}{1}", (sbHostList.Length > 1) ? "; " : string.Empty, sHost);
				}
			}
			_Extensions.Add($"\tserver_name\t{sbHostList.ToString()}");
			break;
		}
		case 1:
			_Extensions.Add($"\tmax_fragment_length\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 2:
			_Extensions.Add($"\tclient_certificate_url\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 3:
			_Extensions.Add($"\ttrusted_ca_keys\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 4:
			_Extensions.Add($"\ttruncated_hmac\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 5:
		{
			string sStatusRequest = Utilities.ByteArrayToString(arrData);
			if (sStatusRequest == "01 00 00 00 00")
			{
				sStatusRequest = "OCSP - Implicit Responder";
			}
			_Extensions.Add($"\tstatus_request\t{sStatusRequest}");
			break;
		}
		case 6:
			_Extensions.Add($"\tuser_mapping\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 9:
			_Extensions.Add($"\tcert_type\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 10:
			_Extensions.Add($"\tsupported_groups\t{HTTPSUtilities.GetSupportedGroupsAsString(arrData)}");
			break;
		case 11:
			_Extensions.Add($"\tec_point_formats\t{HTTPSUtilities.GetECCPointFormatsAsString(arrData)}");
			break;
		case 12:
			_Extensions.Add($"\tsrp_rfc_5054\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 13:
			_Extensions.Add($"\tsignature_algs\t{HTTPSUtilities.GetSignatureAndHashAlgsAsString(arrData)}");
			break;
		case 14:
			_Extensions.Add($"\tuse_srtp\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 15:
			_Extensions.Add($"\theartbeat_rfc_6520\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 16:
		{
			string sALPN = HTTPSUtilities.GetProtocolListAsString(arrData);
			_Extensions.Add($"\tALPN\t\t{sALPN}");
			break;
		}
		case 17:
			_Extensions.Add($"\tstatus_request_v2 (RFC6961)\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 18:
			_Extensions.Add($"\tSignedCertTimestamp (RFC6962)\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 19:
			_Extensions.Add($"\tClientCertificateType (RFC7250)\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 20:
			_Extensions.Add($"\tServerCertificateType (RFC7250)\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 21:
			_Extensions.Add($"\tpadding\t\t{HTTPSUtilities.DescribePadding(arrData)}");
			break;
		case 22:
			_Extensions.Add($"\tencrypt_then_mac (RFC7366)\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 23:
			_Extensions.Add($"\textended_master_secret\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 24:
			_Extensions.Add($"\ttoken_binding\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 25:
			_Extensions.Add($"\tcached_info\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 35:
			_Extensions.Add($"\tSessionTicket\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 40:
			_Extensions.Add($"\tkey_share\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 41:
			_Extensions.Add($"\tpre_shared_key\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 42:
			_Extensions.Add($"\tearly_data\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 43:
			_Extensions.Add($"\tsupported_versions\t{HTTPSUtilities.GetSupportedVersions(arrData)}");
			break;
		case 44:
			_Extensions.Add($"\tcookie\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 45:
			_Extensions.Add($"\tpsk_key_exchange_modes\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 46:
			_Extensions.Add($"\tticket_early_data_info\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 47:
			_Extensions.Add($"\tcertificate_authorities\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 49:
			_Extensions.Add("\tpost_handshake_auth");
			break;
		case 50:
			_Extensions.Add($"\tsignature_algorithms_cert\t{HTTPSUtilities.GetSignatureAndHashAlgsAsString(arrData)}");
			break;
		case 51:
			_Extensions.Add($"\tkey_share\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 13172:
			_Extensions.Add($"\tNextProtocolNego\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 21760:
			_Extensions.Add($"\ttoken_binding(MSDraft)\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 30031:
		case 30032:
			_Extensions.Add($"\tchannel_id(GoogleDraft)\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 2570:
		case 6682:
		case 10794:
		case 14906:
		case 19018:
		case 23130:
		case 27242:
		case 31354:
		case 35466:
		case 39578:
		case 43690:
		case 47802:
		case 51914:
		case 56026:
		case 60138:
		case 64250:
			_Extensions.Add($"\tgrease (0x{iExtType:x})\t{Utilities.ByteArrayToString(arrData)}");
			break;
		case 35655:
			_Extensions.Add($"\tCompatPadding\t{arrData.Length.ToString()} bytes");
			break;
		case 65281:
			_Extensions.Add($"\trenegotiation_info\t{Utilities.ByteArrayToString(arrData)}");
			break;
		default:
			_Extensions.Add($"\t0x{iExtType:x4}\t\t{Utilities.ByteArrayToString(arrData)}");
			break;
		}
	}

	private void ParseClientHelloExtensions(byte[] arrExtensionsData)
	{
		int iExtDataLen;
		for (int iPtr = 0; iPtr < arrExtensionsData.Length; iPtr += 4 + iExtDataLen)
		{
			int iExtensionType = (arrExtensionsData[iPtr] << 8) + arrExtensionsData[iPtr + 1];
			iExtDataLen = (arrExtensionsData[iPtr + 2] << 8) + arrExtensionsData[iPtr + 3];
			byte[] arrExtData = new byte[iExtDataLen];
			Buffer.BlockCopy(arrExtensionsData, iPtr + 4, arrExtData, 0, arrExtData.Length);
			ParseClientHelloExtension(iExtensionType, arrExtData);
		}
	}
}
