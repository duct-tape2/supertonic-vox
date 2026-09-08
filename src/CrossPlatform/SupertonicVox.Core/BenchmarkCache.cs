using System.Text.Json;

namespace SupertonicVox.Core;

public sealed class JsonBenchmarkCache(string filePath) : IBenchmarkCache
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
    };
    private readonly SemaphoreSlim gate = new(1, 1);

    public async Task<BenchmarkResult?> GetAsync(
        string appVersion,
        string engineId,
        string modelRevision,
        string hardwareFingerprint,
        CancellationToken cancellationToken = default)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var entries = await ReadAllAsync(cancellationToken).ConfigureAwait(false);
            return entries.FirstOrDefault(entry =>
                entry.Success &&
                entry.AppVersion == appVersion &&
                entry.EngineId == engineId &&
                entry.ModelRevision == modelRevision &&
                entry.HardwareFingerprint == hardwareFingerprint);
        }
        finally
        {
            gate.Release();
        }
    }

    public async Task PutAsync(BenchmarkResult result, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(result);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var entries = await ReadAllAsync(cancellationToken).ConfigureAwait(false);
            entries.RemoveAll(entry =>
                entry.AppVersion == result.AppVersion &&
                entry.EngineId == result.EngineId &&
                entry.ModelRevision == result.ModelRevision &&
                entry.HardwareFingerprint == result.HardwareFingerprint);
            entries.Add(result);
            await WriteAtomicAsync(entries, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            gate.Release();
        }
    }

    private async Task<List<BenchmarkResult>> ReadAllAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(filePath)) return [];
        try
        {
            await using var source = new FileStream(
                filePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                64 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            return await JsonSerializer.DeserializeAsync<List<BenchmarkResult>>(
                       source,
                       JsonOptions,
                       cancellationToken).ConfigureAwait(false)
                   ?? [];
        }
        catch (Exception exception) when (exception is JsonException or IOException)
        {
            return [];
        }
    }

    private async Task WriteAtomicAsync(
        IReadOnlyList<BenchmarkResult> entries,
        CancellationToken cancellationToken)
    {
        var fullPath = Path.GetFullPath(filePath);
        var directory = Path.GetDirectoryName(fullPath)
                        ?? throw new InvalidOperationException("Benchmark cache directory is unavailable.");
        Directory.CreateDirectory(directory);
        var temporary = Path.Combine(directory, $".{Path.GetFileName(fullPath)}.{Guid.NewGuid():N}.tmp");
        try
        {
            await using (var destination = new FileStream(
                             temporary,
                             FileMode.CreateNew,
                             FileAccess.Write,
                             FileShare.None,
                             64 * 1024,
                             FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await JsonSerializer.SerializeAsync(
                    destination,
                    entries,
                    JsonOptions,
                    cancellationToken).ConfigureAwait(false);
                await destination.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            File.Move(temporary, fullPath, true);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }
}
