namespace ThermoForge.Core.Services;

/// <summary>
/// Runs <c>poll</c> on a background loop at a fixed interval. <see cref="Polled"/> and
/// <see cref="Faulted"/> fire on the polling thread; subscribers marshal to the UI.
/// A failing poll is reported and the loop keeps going.
/// </summary>
public sealed class PollingLoop<T> : IAsyncDisposable
{
    private readonly Func<T> _poll;
    private readonly TimeSpan _interval;
    private CancellationTokenSource? _cts;
    private Task? _loop;

    public PollingLoop(Func<T> poll, TimeSpan interval)
    {
        _poll = poll;
        _interval = interval;
    }

    public event EventHandler<T>? Polled;

    public event EventHandler<Exception>? Faulted;

    public void Start()
    {
        if (_loop is not null)
            throw new InvalidOperationException("Polling loop is already running.");

        _cts = new CancellationTokenSource();
        _loop = Task.Run(() => RunAsync(_cts.Token));
    }

    public async ValueTask DisposeAsync()
    {
        if (_cts is null)
            return;

        await _cts.CancelAsync();
        if (_loop is not null)
            await _loop;
        _cts.Dispose();
    }

    private async Task RunAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(_interval);
        try
        {
            do
            {
                T result;
                try
                {
                    result = _poll();
                }
                catch (Exception ex)
                {
                    Faulted?.Invoke(this, ex);
                    continue;
                }
                Polled?.Invoke(this, result);
            }
            while (await timer.WaitForNextTickAsync(ct));
        }
        catch (OperationCanceledException)
        {
        }
    }
}
