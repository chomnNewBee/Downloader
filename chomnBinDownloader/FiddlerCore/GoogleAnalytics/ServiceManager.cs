using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace GoogleAnalytics;

/// <summary>
/// Implements a service manager used to send <see cref="T:GoogleAnalytics.Hit" />s to Google Analytics.
/// </summary>
internal class ServiceManager : IServiceManager
{
	private static Random random;

	private static readonly Uri endPointUnsecureDebug = new Uri("http://www.google-analytics.com/debug/collect");

	private static readonly Uri endPointSecureDebug = new Uri("https://ssl.google-analytics.com/debug/collect");

	private static readonly Uri endPointUnsecure = new Uri("http://www.google-analytics.com/collect");

	private static readonly Uri endPointSecure = new Uri("https://ssl.google-analytics.com/collect");

	private readonly Queue<Hit> hits;

	private readonly IList<Task> dispatchingTasks;

	private readonly TokenBucket hitTokenBucket;

	private readonly IWebProxy proxy;

	private Timer timer;

	private TimeSpan dispatchPeriod;

	private bool isEnabled = true;

	/// <summary>
	/// Gets or sets whether <see cref="T:GoogleAnalytics.Hit" />s should be sent via SSL. Default is true.
	/// </summary>
	public bool IsSecure { get; set; }

	/// <summary>
	/// Gets or sets whether <see cref="T:GoogleAnalytics.Hit" />s should be sent to the debug endpoint. Default is false.
	/// </summary>
	public bool IsDebug { get; set; }

	/// <summary>
	/// Gets or sets whether throttling should be used. Default is false.
	/// </summary>
	public bool ThrottlingEnabled { get; set; }

	/// <summary>
	/// Gets or sets whether data should be sent via POST or GET method. Default is POST.
	/// </summary>
	public bool PostData { get; set; }

	/// <summary>
	/// Gets or sets whether a cache buster should be applied to all requests. Default is false.
	/// </summary>
	public bool BustCache { get; set; }

	/// <summary>
	/// Gets or sets the user agent request header used by Google Analytics to determine the platform and device generating the hits.
	/// </summary>
	public string UserAgent { get; set; }

	/// <summary>
	/// Gets or sets the frequency at which hits should be sent to the service. Default is immediate.
	/// </summary>
	/// <remarks>Setting to TimeSpan.Zero will cause the hit to get sent immediately.</remarks>
	public TimeSpan DispatchPeriod
	{
		get
		{
			return dispatchPeriod;
		}
		set
		{
			if (dispatchPeriod != value)
			{
				dispatchPeriod = value;
				if (timer != null)
				{
					timer.Dispose();
					timer = null;
				}
				if (dispatchPeriod > TimeSpan.Zero)
				{
					timer = new Timer(timer_Tick, null, DispatchPeriod, DispatchPeriod);
				}
			}
		}
	}

	/// <summary>
	/// Gets or sets whether the dispatcher is enabled. If disabled, hits will be queued but not dispatched.
	/// </summary>
	/// <remarks>Typically this is used to indicate whether or not the network is available.</remarks>
	public bool IsEnabled
	{
		get
		{
			return isEnabled;
		}
		set
		{
			if (isEnabled != value)
			{
				isEnabled = value;
				if (isEnabled && DispatchPeriod >= TimeSpan.Zero)
				{
					Task nowait = DispatchAsync();
				}
			}
		}
	}

	/// <summary>
	/// Provides notification that a <see cref="T:GoogleAnalytics.Hit" /> has been been successfully sent.
	/// </summary>
	public event EventHandler<HitSentEventArgs> HitSent;

	/// <summary>
	/// Provides notification that a <see cref="T:GoogleAnalytics.Hit" /> failed to send.
	/// </summary>
	/// <remarks>Failed <see cref="T:GoogleAnalytics.Hit" />s will be added to the queue in order to reattempt at the next dispatch time.</remarks>
	public event EventHandler<HitFailedEventArgs> HitFailed;

	/// <summary>
	/// Provides notification that a <see cref="T:GoogleAnalytics.Hit" /> was malformed and rejected by Google Analytics.
	/// </summary>
	public event EventHandler<HitMalformedEventArgs> HitMalformed;

	/// <summary>
	/// Instantiates a new instance of <see cref="T:GoogleAnalytics.ServiceManager" />.
	/// </summary>
	/// <param name="proxy">A proxy to be used by the manager when dispatching hits. If null, the default IE proxy is used.</param>
	public ServiceManager(IWebProxy proxy)
	{
		this.proxy = proxy;
		PostData = true;
		dispatchingTasks = new List<Task>();
		hits = new Queue<Hit>();
		DispatchPeriod = TimeSpan.Zero;
		IsSecure = true;
		hitTokenBucket = new TokenBucket(60.0, 0.5);
	}

	/// <summary>
	/// Empties the queue of <see cref="T:GoogleAnalytics.Hit" />s waiting to be dispatched.
	/// </summary>
	/// <remarks>If a <see cref="T:GoogleAnalytics.Hit" /> is actively beeing sent, this will not abort the request.</remarks>
	public void Clear()
	{
		lock (hits)
		{
			hits.Clear();
		}
	}

	/// <summary>
	/// Dispatches all hits in the queue.
	/// </summary>
	/// <returns>Returns once all items that were in the queue at the time the method was called have finished being sent.</returns>
	public async Task DispatchAsync()
	{
		if (!isEnabled)
		{
			return;
		}
		Task allDispatchingTasks = null;
		lock (dispatchingTasks)
		{
			if (dispatchingTasks.Any())
			{
				allDispatchingTasks = Task.WhenAll(dispatchingTasks);
			}
		}
		if (allDispatchingTasks != null)
		{
			await allDispatchingTasks;
		}
		if (isEnabled)
		{
			Hit[] hitsToSend;
			lock (hits)
			{
				hitsToSend = hits.ToArray();
				Clear();
			}
			if (hitsToSend.Any())
			{
				await RunDispatchingTask(DispatchQueuedHits(hitsToSend));
			}
		}
	}

	/// <inheritdoc />
	public virtual void EnqueueHit(IDictionary<string, string> @params)
	{
		Hit hit = new Hit(@params);
		if (DispatchPeriod == TimeSpan.Zero && IsEnabled)
		{
			Task t = RunDispatchingTask(DispatchImmediateHit(hit));
			return;
		}
		lock (hits)
		{
			hits.Enqueue(hit);
		}
	}

	/// <summary>
	/// Suspends operations and flushes the queue.
	/// </summary>
	/// <remarks>Call <see cref="M:GoogleAnalytics.ServiceManager.Resume" /> when returning from a suspended state to resume operations.</remarks>
	/// <returns>Operation returns when all <see cref="T:GoogleAnalytics.Hit" />s have been flushed.</returns>
	public async Task SuspendAsync()
	{
		await DispatchAsync();
		if (timer != null)
		{
			timer.Dispose();
			timer = null;
		}
	}

	/// <summary>
	/// Resumes operations after <see cref="M:GoogleAnalytics.ServiceManager.SuspendAsync" /> is called.
	/// </summary>
	public void Resume()
	{
		if (dispatchPeriod > TimeSpan.Zero)
		{
			timer = new Timer(timer_Tick, null, DispatchPeriod, DispatchPeriod);
		}
	}

	private async void timer_Tick(object sender)
	{
		await DispatchAsync();
	}

	private async Task RunDispatchingTask(Task newDispatchingTask)
	{
		lock (dispatchingTasks)
		{
			dispatchingTasks.Add(newDispatchingTask);
		}
		try
		{
			await newDispatchingTask;
		}
		finally
		{
			lock (dispatchingTasks)
			{
				dispatchingTasks.Remove(newDispatchingTask);
			}
		}
	}

	private async Task DispatchQueuedHits(IEnumerable<Hit> hits)
	{
		using HttpClient httpClient = GetHttpClient();
		DateTimeOffset now = DateTimeOffset.UtcNow;
		foreach (Hit hit in hits)
		{
			if (isEnabled && (!ThrottlingEnabled || hitTokenBucket.Consume()))
			{
				Dictionary<string, string> hitData = hit.Data.ToDictionary((KeyValuePair<string, string> kvp) => kvp.Key, (KeyValuePair<string, string> kvp) => kvp.Value);
				hitData.Add("qt", ((long)now.Subtract(hit.TimeStamp).TotalMilliseconds).ToString());
				await DispatchHitData(hit, httpClient, hitData);
			}
			else
			{
				lock (this.hits)
				{
					this.hits.Enqueue(hit);
				}
			}
		}
	}

	private async Task DispatchImmediateHit(Hit hit)
	{
		using HttpClient httpClient = GetHttpClient();
		Dictionary<string, string> hitData = hit.Data.ToDictionary((KeyValuePair<string, string> kvp) => kvp.Key, (KeyValuePair<string, string> kvp) => kvp.Value);
		await DispatchHitData(hit, httpClient, hitData);
	}

	private async Task DispatchHitData(Hit hit, HttpClient httpClient, IDictionary<string, string> hitData)
	{
		if (BustCache)
		{
			hitData.Add("z", GetCacheBuster());
		}
		try
		{
			using HttpResponseMessage response = await SendHitAsync(hit, httpClient, hitData);
			try
			{
				response.EnsureSuccessStatusCode();
				await OnHitSentAsync(hit, response);
			}
			catch
			{
				OnHitMalformed(hit, response);
			}
		}
		catch (Exception ex)
		{
			OnHitFailed(hit, ex);
		}
	}

	private async Task<HttpResponseMessage> SendHitAsync(Hit hit, HttpClient httpClient, IDictionary<string, string> hitData)
	{
		Uri endPoint = ((!IsDebug) ? (IsSecure ? endPointSecure : endPointUnsecure) : (IsSecure ? endPointSecureDebug : endPointUnsecureDebug));
		if (PostData)
		{
			using (ByteArrayContent content = GetEncodedContent(hitData))
			{
				return await httpClient.PostAsync(endPoint, content);
			}
		}
		return await httpClient.GetAsync(endPoint?.ToString() + "?" + GetUrlEncodedString(hitData));
	}

	private void OnHitMalformed(Hit hit, HttpResponseMessage response)
	{
		this.HitMalformed?.Invoke(this, new HitMalformedEventArgs(hit, (int)response.StatusCode));
	}

	private void OnHitFailed(Hit hit, Exception exception)
	{
		this.HitFailed?.Invoke(this, new HitFailedEventArgs(hit, exception));
	}

	private async Task OnHitSentAsync(Hit hit, HttpResponseMessage response)
	{
		EventHandler<HitSentEventArgs> hitSent = this.HitSent;
		if (hitSent != null)
		{
			object sender = this;
			hitSent(sender, new HitSentEventArgs(hit, await response.Content.ReadAsStringAsync()));
		}
	}

	private HttpClient GetHttpClient()
	{
		HttpClient result = new HttpClient(new HttpClientHandler
		{
			Proxy = proxy
		});
		if (!string.IsNullOrEmpty(UserAgent))
		{
			result.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
		}
		return result;
	}

	private static string GetCacheBuster()
	{
		if (random == null)
		{
			random = new Random();
		}
		return random.Next().ToString();
	}

	private static ByteArrayContent GetEncodedContent(IEnumerable<KeyValuePair<string, string>> nameValueCollection)
	{
		return new StringContent(GetUrlEncodedString(nameValueCollection));
	}

	private static string GetUrlEncodedString(IEnumerable<KeyValuePair<string, string>> nameValueCollection)
	{
		return string.Join("&", from item in nameValueCollection
			where item.Value != null
			select item.Key + "=" + Uri.EscapeDataString((item.Value.Length > 65519) ? item.Value.Substring(0, 65519) : item.Value));
	}
}
