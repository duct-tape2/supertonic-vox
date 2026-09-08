using System.Text.Json;

namespace SupertonicVox.Core;

public sealed record UserPreferences(string? ManualEngineId);

public sealed class UserPreferenceStore(string filePath)
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
    };

    public async Task<UserPreferences> LoadAsync(CancellationToken cancellationToken = default)
    {
        if (!File.Exists(filePath)) return new UserPreferences(null);
        try
        {
            await using var source = File.OpenRead(filePath);
            return await JsonSerializer.DeserializeAsync<UserPreferences>(
                       source,
                       Options,
                       cancellationToken).ConfigureAwait(false)
                   ?? new UserPreferences(null);
        }
        catch (Exception exception) when (exception is IOException or JsonException)
        {
            return new UserPreferences(null);
        }
    }

    public async Task SaveAsync(UserPreferences preferences, CancellationToken cancellationToken = default)
    {
        var fullPath = Path.GetFullPath(filePath);
        var directory = Path.GetDirectoryName(fullPath)
                        ?? throw new InvalidOperationException("Preference directory is unavailable.");
        Directory.CreateDirectory(directory);
        var temporary = Path.Combine(directory, $".{Path.GetFileName(fullPath)}.{Guid.NewGuid():N}.tmp");
        try
        {
            await using (var destination = File.Create(temporary))
            {
                await JsonSerializer.SerializeAsync(
                    destination,
                    preferences,
                    Options,
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
