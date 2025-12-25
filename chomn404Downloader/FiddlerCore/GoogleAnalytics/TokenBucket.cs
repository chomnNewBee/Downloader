using System;

namespace GoogleAnalytics;

internal class TokenBucket
{
	private readonly object locker = new object();

	private double capacity = 0.0;

	private double tokens = 0.0;

	private double fillRate = 0.0;

	private DateTime timeStamp;

	public TokenBucket(double tokens, double fillRate)
	{
		capacity = tokens;
		this.tokens = tokens;
		this.fillRate = fillRate;
		timeStamp = DateTime.UtcNow;
	}

	public bool Consume(double tokens = 1.0)
	{
		lock (locker)
		{
			if (GetTokens() - tokens > 0.0)
			{
				this.tokens -= tokens;
				return true;
			}
			return false;
		}
	}

	private double GetTokens()
	{
		DateTime now = DateTime.UtcNow;
		if (tokens < capacity)
		{
			double delta = fillRate * (now - timeStamp).TotalSeconds;
			tokens = Math.Min(capacity, tokens + delta);
			timeStamp = now;
		}
		return tokens;
	}
}
