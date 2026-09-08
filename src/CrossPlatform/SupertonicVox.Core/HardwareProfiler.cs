using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.ComponentModel;

namespace SupertonicVox.Core;

public sealed class HardwareProfiler(IProcessRunner processRunner) : IHardwareProfiler
{
    private static readonly TimeSpan ProbeTimeout = TimeSpan.FromSeconds(8);

    public async Task<HardwareProfile> ProfileAsync(
        string dataDirectory,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataDirectory);
        var platform = DetectPlatform();
        var architecture = DetectArchitecture();
        var cpuName = RuntimeInformation.ProcessArchitecture.ToString();
        var totalMemory = SafeTotalMemory();
        var availableMemory = totalMemory;
        var gpus = new List<GpuDevice>();
        var features = DetectCpuFeatures();

        try
        {
            if (platform == PlatformKind.MacOS)
            {
                (cpuName, totalMemory, availableMemory, gpus) = await ProbeMacAsync(
                    cpuName,
                    totalMemory,
                    cancellationToken).ConfigureAwait(false);
            }
            else if (platform == PlatformKind.Windows)
            {
                (cpuName, totalMemory, availableMemory, gpus) = await ProbeWindowsAsync(
                    cpuName,
                    totalMemory,
                    cancellationToken).ConfigureAwait(false);
            }
        }
        catch (Exception exception) when (
            exception is IOException or JsonException or FormatException or Win32Exception or OperationCanceledException)
        {
            if (exception is OperationCanceledException && cancellationToken.IsCancellationRequested)
            {
                throw;
            }
        }

        var freeDisk = GetFreeDiskBytes(dataDirectory);
        var isAppleSilicon = platform == PlatformKind.MacOS && architecture == CpuArchitectureKind.Arm64;
        var fingerprint = HardwareFingerprint.Create(
            platform,
            architecture,
            cpuName,
            Environment.ProcessorCount,
            totalMemory,
            gpus);
        return new HardwareProfile
        {
            Platform = platform,
            Architecture = architecture,
            CpuName = cpuName,
            LogicalCoreCount = Environment.ProcessorCount,
            TotalMemoryBytes = totalMemory,
            AvailableMemoryBytes = availableMemory,
            FreeDiskBytes = freeDisk,
            IsAppleSilicon = isAppleSilicon,
            Gpus = gpus,
            CpuFeatures = features,
            Fingerprint = fingerprint,
        };
    }

    private async Task<(string Cpu, ulong Total, ulong Available, List<GpuDevice> Gpus)> ProbeMacAsync(
        string fallbackCpu,
        ulong fallbackMemory,
        CancellationToken cancellationToken)
    {
        var cpu = fallbackCpu;
        var total = fallbackMemory;
        var memoryResult = await processRunner.RunAsync(
            "/usr/sbin/sysctl",
            ["-n", "hw.memsize"],
            ProbeTimeout,
            cancellationToken).ConfigureAwait(false);
        if (memoryResult.Success && ulong.TryParse(memoryResult.StandardOutput.Trim(), out var parsedMemory))
        {
            total = parsedMemory;
        }
        var cpuResult = await processRunner.RunAsync(
            "/usr/sbin/sysctl",
            ["-n", "machdep.cpu.brand_string"],
            ProbeTimeout,
            cancellationToken).ConfigureAwait(false);
        if (cpuResult.Success && !string.IsNullOrWhiteSpace(cpuResult.StandardOutput))
        {
            cpu = cpuResult.StandardOutput.Trim();
        }

        var gpus = new List<GpuDevice>();
        var displayResult = await processRunner.RunAsync(
            "/usr/sbin/system_profiler",
            ["SPDisplaysDataType", "-json"],
            ProbeTimeout,
            cancellationToken).ConfigureAwait(false);
        if (displayResult.Success)
        {
            gpus.AddRange(ParseMacDisplays(displayResult.StandardOutput, total));
        }
        return (cpu, total, total, DistinctGpus(gpus));
    }

    private async Task<(string Cpu, ulong Total, ulong Available, List<GpuDevice> Gpus)> ProbeWindowsAsync(
        string fallbackCpu,
        ulong fallbackMemory,
        CancellationToken cancellationToken)
    {
        const string script = "$c=Get-CimInstance Win32_ComputerSystem;" +
            "$o=Get-CimInstance Win32_OperatingSystem;" +
            "$p=Get-CimInstance Win32_Processor|Select-Object -First 1;" +
            "$g=@(Get-CimInstance Win32_VideoController|ForEach-Object{@{name=$_.Name;memory=[uint64]$_.AdapterRAM}});" +
            "@{cpu=$p.Name;total=[uint64]$c.TotalPhysicalMemory;available=[uint64]$o.FreePhysicalMemory*1024;gpus=$g}|ConvertTo-Json -Compress -Depth 4";
        var result = await processRunner.RunAsync(
            "powershell.exe",
            ["-NoProfile", "-NonInteractive", "-Command", script],
            ProbeTimeout,
            cancellationToken).ConfigureAwait(false);
        if (!result.Success)
        {
            return (fallbackCpu, fallbackMemory, fallbackMemory, []);
        }

        using var document = JsonDocument.Parse(result.StandardOutput);
        var root = document.RootElement;
        var cpu = GetString(root, "cpu") ?? fallbackCpu;
        var total = GetUInt64(root, "total") ?? fallbackMemory;
        var available = GetUInt64(root, "available") ?? total;
        var gpus = new List<GpuDevice>();
        if (root.TryGetProperty("gpus", out var gpuElements) && gpuElements.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in gpuElements.EnumerateArray())
            {
                var name = GetString(item, "name") ?? "Unknown GPU";
                var memory = GetUInt64(item, "memory") ?? 0;
                var backend = name.Contains("NVIDIA", StringComparison.OrdinalIgnoreCase)
                    ? AccelerationBackend.Cuda
                    : AccelerationBackend.Cpu;
                gpus.Add(new GpuDevice(name, backend, memory, false));
            }
        }
        var nvidiaDevices = await TryProbeNvidiaAsync(cancellationToken).ConfigureAwait(false);
        if (nvidiaDevices.Count > 0)
        {
            gpus.RemoveAll(device => device.Name.Contains("NVIDIA", StringComparison.OrdinalIgnoreCase));
            gpus.AddRange(nvidiaDevices);
        }
        return (cpu, total, available, DistinctGpus(gpus));
    }

    private async Task<List<GpuDevice>> TryProbeNvidiaAsync(CancellationToken cancellationToken)
    {
        try
        {
            var result = await processRunner.RunAsync(
                "nvidia-smi.exe",
                ["--query-gpu=name,memory.total", "--format=csv,noheader,nounits"],
                ProbeTimeout,
                cancellationToken).ConfigureAwait(false);
            return result.Success ? ParseNvidiaSmi(result.StandardOutput) : [];
        }
        catch (Exception exception) when (
            exception is IOException or Win32Exception or FormatException or OperationCanceledException)
        {
            if (exception is OperationCanceledException && cancellationToken.IsCancellationRequested) throw;
            return [];
        }
    }

    private static PlatformKind DetectPlatform()
    {
        if (OperatingSystem.IsWindows()) return PlatformKind.Windows;
        if (OperatingSystem.IsMacOS()) return PlatformKind.MacOS;
        return PlatformKind.Unknown;
    }

    private static CpuArchitectureKind DetectArchitecture() => RuntimeInformation.ProcessArchitecture switch
    {
        Architecture.X64 => CpuArchitectureKind.X64,
        Architecture.Arm64 => CpuArchitectureKind.Arm64,
        _ => CpuArchitectureKind.Unknown,
    };

    private static IReadOnlyList<string> DetectCpuFeatures()
    {
        var features = new List<string>();
        if (System.Runtime.Intrinsics.X86.Avx2.IsSupported) features.Add("AVX2");
        if (System.Runtime.Intrinsics.X86.Sse42.IsSupported) features.Add("SSE4.2");
        if (System.Runtime.Intrinsics.Arm.AdvSimd.IsSupported) features.Add("AdvSIMD");
        return features;
    }

    private static ulong SafeTotalMemory()
    {
        var value = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes;
        return value > 0 ? checked((ulong)value) : 0;
    }

    private static ulong GetFreeDiskBytes(string dataDirectory)
    {
        try
        {
            var fullPath = Path.GetFullPath(dataDirectory);
            var root = Path.GetPathRoot(fullPath);
            return string.IsNullOrWhiteSpace(root) ? 0 : checked((ulong)new DriveInfo(root).AvailableFreeSpace);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return 0;
        }
    }

    private static IEnumerable<JsonElement> FindObjects(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            yield return element;
            foreach (var property in element.EnumerateObject())
            {
                foreach (var child in FindObjects(property.Value)) yield return child;
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                foreach (var child in FindObjects(item)) yield return child;
            }
        }
    }

    internal static List<GpuDevice> ParseMacDisplays(string json, ulong unifiedMemoryBytes)
    {
        using var document = JsonDocument.Parse(json);
        var gpus = new List<GpuDevice>();
        foreach (var candidate in FindObjects(document.RootElement))
        {
            var name = GetString(candidate, "sppci_model") ?? GetString(candidate, "_name");
            var metal = GetString(candidate, "spdisplays_metal") ??
                        GetString(candidate, "spdisplays_mtlgpufamilysupport");
            if (!string.IsNullOrWhiteSpace(name) && !string.IsNullOrWhiteSpace(metal))
            {
                gpus.Add(new GpuDevice(name, AccelerationBackend.Metal, unifiedMemoryBytes, true));
            }
        }
        return DistinctGpus(gpus);
    }

    internal static List<GpuDevice> ParseNvidiaSmi(string output)
    {
        var devices = new List<GpuDevice>();
        foreach (var rawLine in output.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = rawLine.LastIndexOf(',');
            if (separator <= 0) continue;
            var name = rawLine[..separator].Trim();
            var memoryText = rawLine[(separator + 1)..].Trim();
            if (string.IsNullOrWhiteSpace(name) ||
                !ulong.TryParse(memoryText, out var memoryMiB) ||
                memoryMiB == 0 ||
                memoryMiB > ulong.MaxValue / (1024UL * 1024UL))
            {
                continue;
            }
            devices.Add(new GpuDevice(
                name,
                AccelerationBackend.Cuda,
                memoryMiB * 1024UL * 1024UL,
                false));
        }
        return DistinctGpus(devices);
    }

    private static string? GetString(JsonElement element, string propertyName) =>
        element.ValueKind == JsonValueKind.Object &&
        element.TryGetProperty(propertyName, out var value) &&
        value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static ulong? GetUInt64(JsonElement element, string propertyName)
    {
        if (element.ValueKind != JsonValueKind.Object || !element.TryGetProperty(propertyName, out var value))
        {
            return null;
        }
        if (value.ValueKind == JsonValueKind.Number && value.TryGetUInt64(out var number)) return number;
        if (value.ValueKind == JsonValueKind.String && ulong.TryParse(value.GetString(), out number)) return number;
        return null;
    }

    private static List<GpuDevice> DistinctGpus(IEnumerable<GpuDevice> gpus) =>
        gpus.GroupBy(gpu => gpu.Name, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .ToList();
}

public static class HardwareFingerprint
{
    public static string Create(
        PlatformKind platform,
        CpuArchitectureKind architecture,
        string cpuName,
        int logicalCores,
        ulong totalMemoryBytes,
        IEnumerable<GpuDevice> gpus)
    {
        var canonical = string.Join(
            "\n",
            platform,
            architecture,
            cpuName.Trim(),
            logicalCores,
            totalMemoryBytes,
            string.Join(",", gpus.OrderBy(gpu => gpu.Name).Select(gpu => $"{gpu.Name}:{gpu.Backend}:{gpu.MemoryBytes}")));
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }
}
