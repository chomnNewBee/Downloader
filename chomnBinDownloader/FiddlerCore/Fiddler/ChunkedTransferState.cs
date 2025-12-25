namespace Fiddler;

internal enum ChunkedTransferState
{
	Unknown,
	/// <summary>
	/// Read the first character of the hexadecimal size
	/// </summary>
	ReadStartOfSize,
	ReadingSize,
	ReadingChunkExtToCR,
	ReadLFAfterChunkHeader,
	ReadingBlock,
	ReadCRAfterBlock,
	ReadLFAfterBlock,
	/// <summary>
	/// Read the first character of the next Trailer header (if any)
	/// </summary>
	ReadStartOfTrailer,
	/// <summary>
	/// We're in a trailer. Read up to the next \r
	/// </summary>
	ReadToTrailerCR,
	/// <summary>
	/// We've just read a trailer CR, now read its LF
	/// </summary>
	ReadTrailerLF,
	/// <summary>
	/// We read a CR on an "empty" Trailer line, so now we just need the final LF
	/// </summary>
	ReadFinalLF,
	/// <summary>
	/// The chunked body was successfully read with no excess
	/// </summary>
	Completed,
	/// <summary>
	/// Completed, but we read too many bytes. Call getOverage to return how many bytes to put back
	/// </summary>
	Overread,
	/// <summary>
	/// The body was malformed
	/// </summary>
	Malformed
}
