using System;
using System.IO;
using System.Runtime.Serialization;

namespace Fiddler;

/// <summary>
/// This object holds Session information as a set of four easily-marshalled byte arrays.
/// It is serializable, which enables  cross-process transfer of this data (as in a drag/drop operation).
/// (Internally, data is serialized as if it were being stored in a SAZ file)
/// </summary>
[Serializable]
public class SessionData : ISerializable
{
	public byte[] arrRequest;

	public byte[] arrResponse;

	public byte[] arrMetadata;

	public byte[] arrWebSocketMessages;

	/// <summary>
	/// Create a SessionData object. 
	/// Note: Method must run as cheaply as possible, since it runs on all Drag/Dropped sessions within Fiddler itself.
	/// </summary>
	/// <param name="oS"></param>
	public SessionData(Session oS)
	{
		MemoryStream oMS = new MemoryStream();
		oS.WriteRequestToStream(bHeadersOnly: false, bIncludeProtocolAndHostWithPath: true, oMS);
		arrRequest = oMS.ToArray();
		oMS = new MemoryStream();
		oS.WriteResponseToStream(oMS, bHeadersOnly: false);
		arrResponse = oMS.ToArray();
		oMS = new MemoryStream();
		oS.WriteMetadataToStream(oMS);
		arrMetadata = oMS.ToArray();
		oMS = new MemoryStream();
		oS.WriteWebSocketMessagesToStream(oMS);
		arrWebSocketMessages = oMS.ToArray();
	}

	public SessionData(SerializationInfo info, StreamingContext ctxt)
	{
		arrRequest = (byte[])info.GetValue("Request", typeof(byte[]));
		arrResponse = (byte[])info.GetValue("Response", typeof(byte[]));
		arrMetadata = (byte[])info.GetValue("Metadata", typeof(byte[]));
		arrWebSocketMessages = (byte[])info.GetValue("WSMsgs", typeof(byte[]));
	}

	public virtual void GetObjectData(SerializationInfo info, StreamingContext ctxt)
	{
		info.AddValue("Request", arrRequest);
		info.AddValue("Response", arrResponse);
		info.AddValue("Metadata", arrMetadata);
		info.AddValue("WSMsgs", arrWebSocketMessages);
	}
}
