using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Runtime.InteropServices;

namespace SupertonicVox.Core;

internal interface ILoopbackListenerOwnerVerifier
{
    Task VerifyOwnedAsync(int processId, int port, CancellationToken cancellationToken);
}

internal static class LoopbackListenerOwnerVerifier
{
    public static ILoopbackListenerOwnerVerifier CreateDefault()
    {
        if (OperatingSystem.IsWindows()) return new WindowsLoopbackListenerOwnerVerifier();
        if (OperatingSystem.IsMacOS()) return new MacOsLoopbackListenerOwnerVerifier();
        return new UnsupportedLoopbackListenerOwnerVerifier();
    }
}

internal sealed class UnsupportedLoopbackListenerOwnerVerifier : ILoopbackListenerOwnerVerifier
{
    public Task VerifyOwnedAsync(int processId, int port, CancellationToken cancellationToken) =>
        throw new RuntimePackException("Sidecar listener ownership is unsupported on this platform.");
}

internal sealed class MacOsLoopbackListenerOwnerVerifier : ILoopbackListenerOwnerVerifier
{
    private const string LsofPath = "/usr/sbin/lsof";
    private const int MaximumOutputCharacters = 16 * 1024;

    public async Task VerifyOwnedAsync(
        int processId,
        int port,
        CancellationToken cancellationToken)
    {
        ValidateIdentity(processId, port);
        if (!File.Exists(LsofPath))
            throw new RuntimePackException("The macOS listener ownership verifier is unavailable.");

        var startInfo = new ProcessStartInfo
        {
            FileName = LsofPath,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var argument in new[]
                 {
                     "-nP", "-a", "-p", processId.ToString(CultureInfo.InvariantCulture),
                     $"-iTCP@127.0.0.1:{port}", "-sTCP:LISTEN", "-F0pn",
                 })
            startInfo.ArgumentList.Add(argument);

        using var process = new Process { StartInfo = startInfo };
        if (!process.Start())
            throw new RuntimePackException("Could not start the macOS listener ownership verifier.");
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(2));
            var stdoutTask = ReadBoundedAsync(process.StandardOutput, MaximumOutputCharacters, timeout.Token);
            var stderrTask = ReadBoundedAsync(process.StandardError, 4096, timeout.Token);
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            var stdout = await stdoutTask.ConfigureAwait(false);
            _ = await stderrTask.ConfigureAwait(false);
            if (process.ExitCode != 0 || !OutputMatches(stdout, processId, port))
                throw new RuntimePackException("The loopback listener is not owned by the sidecar process.");
        }
        catch (OperationCanceledException)
        {
            OwnedSidecarProcessHost.TryKill(process);
            throw new RuntimePackException("Listener ownership verification timed out.");
        }
    }

    internal static bool OutputMatches(string output, int processId, int port)
    {
        ValidateIdentity(processId, port);
        var fields = output.Split('\0', StringSplitOptions.RemoveEmptyEntries)
            .Select(value => value.Trim())
            .Where(value => value.Length > 0)
            .ToArray();
        return fields.Count(value => string.Equals(
                   value,
                   $"p{processId}",
                   StringComparison.Ordinal)) == 1 &&
               fields.Count(value => string.Equals(
                   value,
                   $"n127.0.0.1:{port}",
                   StringComparison.Ordinal)) == 1;
    }

    private static async Task<string> ReadBoundedAsync(
        StreamReader reader,
        int maximumCharacters,
        CancellationToken cancellationToken)
    {
        var output = new System.Text.StringBuilder();
        var buffer = new char[1024];
        while (true)
        {
            var read = await reader.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
            if (read == 0) return output.ToString();
            if (output.Length + read > maximumCharacters)
                throw new RuntimePackException("Listener ownership verifier output exceeded its limit.");
            output.Append(buffer, 0, read);
        }
    }

    private static void ValidateIdentity(int processId, int port)
    {
        if (processId <= 0 || port is < 1024 or > 65535)
            throw new ArgumentOutOfRangeException(nameof(processId));
    }
}

internal sealed class WindowsLoopbackListenerOwnerVerifier : ILoopbackListenerOwnerVerifier
{
    private const int AddressFamilyInternet = 2;
    private const uint ErrorInsufficientBuffer = 122;
    private const uint NoError = 0;
    private const uint TcpStateListen = 2;
    private const int MaximumTableBytes = 16 * 1024 * 1024;

    public Task VerifyOwnedAsync(int processId, int port, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (processId <= 0 || port is < 1024 or > 65535)
            throw new ArgumentOutOfRangeException(nameof(processId));

        var size = 0;
        var status = GetExtendedTcpTable(
            nint.Zero,
            ref size,
            true,
            AddressFamilyInternet,
            TcpTableClass.TcpTableOwnerPidListener,
            0);
        if (status != ErrorInsufficientBuffer || size is < 4 or > MaximumTableBytes)
            throw new RuntimePackException("Windows listener ownership table size is invalid.");

        var table = Marshal.AllocHGlobal(size);
        try
        {
            status = GetExtendedTcpTable(
                table,
                ref size,
                true,
                AddressFamilyInternet,
                TcpTableClass.TcpTableOwnerPidListener,
                0);
            if (status != NoError)
                throw new RuntimePackException("Windows listener ownership lookup failed.");
            var rowCount = Marshal.ReadInt32(table);
            var rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();
            if (rowCount < 0 || checked(4L + (long)rowCount * rowSize) > size)
                throw new RuntimePackException("Windows listener ownership table is malformed.");

            var matches = 0;
            var current = table + 4;
            for (var index = 0; index < rowCount; index++, current += rowSize)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(current);
                if (row.State != TcpStateListen || row.OwningPid != (uint)processId ||
                    !new IPAddress(row.LocalAddress).Equals(IPAddress.Loopback) ||
                    DecodePort(row.LocalPort) != port)
                    continue;
                matches++;
            }
            if (matches != 1)
                throw new RuntimePackException("The loopback listener is not uniquely owned by the sidecar process.");
        }
        finally
        {
            Marshal.FreeHGlobal(table);
        }
        return Task.CompletedTask;
    }

    internal static int DecodePort(uint networkOrderPort) =>
        (ushort)IPAddress.NetworkToHostOrder(unchecked((short)(networkOrderPort & 0xffff)));

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        nint tcpTable,
        ref int outputBufferLength,
        [MarshalAs(UnmanagedType.Bool)] bool order,
        int addressFamily,
        TcpTableClass tableClass,
        uint reserved);

    private enum TcpTableClass
    {
        TcpTableOwnerPidListener = 3,
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct MibTcpRowOwnerPid
    {
        public readonly uint State;
        public readonly uint LocalAddress;
        public readonly uint LocalPort;
        public readonly uint RemoteAddress;
        public readonly uint RemotePort;
        public readonly uint OwningPid;
    }
}
