using SupertonicVox.Core;

namespace SupertonicVox.Core.Tests;

public sealed class HardwareProfilerTests
{
    [Fact]
    public void ParsesCurrentAppleMetalFamilyField()
    {
        const string json = """
            {
              "SPDisplaysDataType": [{
                "_name": "Apple M1 Ultra",
                "spdisplays_mtlgpufamilysupport": "spdisplays_metal4",
                "sppci_cores": "48",
                "sppci_model": "Apple M1 Ultra"
              }]
            }
            """;

        var devices = HardwareProfiler.ParseMacDisplays(json, 64UL * 1024 * 1024 * 1024);

        var gpu = Assert.Single(devices);
        Assert.Equal("Apple M1 Ultra", gpu.Name);
        Assert.Equal(AccelerationBackend.Metal, gpu.Backend);
        Assert.True(gpu.IsIntegrated);
        Assert.Equal(64UL * 1024 * 1024 * 1024, gpu.MemoryBytes);
    }

    [Fact]
    public void ParsesNvidiaMemoryBeyondCimUInt32Limit()
    {
        const string output = "NVIDIA GeForce RTX 4090, 24564\r\nNVIDIA RTX A4000, 16376\r\n";

        var devices = HardwareProfiler.ParseNvidiaSmi(output);

        Assert.Equal(2, devices.Count);
        Assert.All(devices, device => Assert.Equal(AccelerationBackend.Cuda, device.Backend));
        Assert.Equal(24564UL * 1024 * 1024, devices[0].MemoryBytes);
        Assert.True(devices[0].MemoryBytes > uint.MaxValue);
    }
}
