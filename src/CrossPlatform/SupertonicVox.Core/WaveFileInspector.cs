using System.Buffers.Binary;

namespace SupertonicVox.Core;

public sealed record WaveFileMetadata(
    int SampleRate,
    short Channels,
    short BitsPerSample,
    int DataBytes,
    TimeSpan Duration);

public static class WaveFileInspector
{
    private const int MaximumChunks = 128;

    public static bool TryReadPcm16(ReadOnlySpan<byte> bytes, out WaveFileMetadata? metadata)
    {
        metadata = null;
        if (bytes.Length < 44 || !bytes[..4].SequenceEqual("RIFF"u8) ||
            !bytes.Slice(8, 4).SequenceEqual("WAVE"u8)) return false;
        var declaredRiffSize = BinaryPrimitives.ReadUInt32LittleEndian(bytes.Slice(4, 4));
        if (declaredRiffSize != bytes.Length - 8) return false;

        short format = 0;
        short channels = 0;
        int sampleRate = 0;
        int byteRate = 0;
        short blockAlign = 0;
        short bitsPerSample = 0;
        int dataBytes = -1;
        var offset = 12;
        for (var count = 0; offset <= bytes.Length - 8 && count < MaximumChunks; count++)
        {
            var id = bytes.Slice(offset, 4);
            var size = BinaryPrimitives.ReadUInt32LittleEndian(bytes.Slice(offset + 4, 4));
            if (size > int.MaxValue) return false;
            var payloadOffset = offset + 8;
            if (payloadOffset > bytes.Length - (int)size) return false;

            if (id.SequenceEqual("fmt "u8))
            {
                if (size < 16) return false;
                var formatBytes = bytes.Slice(payloadOffset, (int)size);
                format = BinaryPrimitives.ReadInt16LittleEndian(formatBytes[..2]);
                channels = BinaryPrimitives.ReadInt16LittleEndian(formatBytes.Slice(2, 2));
                sampleRate = BinaryPrimitives.ReadInt32LittleEndian(formatBytes.Slice(4, 4));
                byteRate = BinaryPrimitives.ReadInt32LittleEndian(formatBytes.Slice(8, 4));
                blockAlign = BinaryPrimitives.ReadInt16LittleEndian(formatBytes.Slice(12, 2));
                bitsPerSample = BinaryPrimitives.ReadInt16LittleEndian(formatBytes.Slice(14, 2));
            }
            else if (id.SequenceEqual("data"u8))
            {
                dataBytes = (int)size;
            }

            offset = checked(payloadOffset + (int)size + ((int)size & 1));
            if (format != 0 && dataBytes >= 0) break;
        }

        if (format != 1 || channels != 1 || bitsPerSample != 16 ||
            sampleRate is < 8_000 or > 192_000 || blockAlign != 2 || byteRate != sampleRate * 2 ||
            dataBytes <= 0 || (dataBytes & 1) != 0) return false;
        var samples = dataBytes / sizeof(short);
        metadata = new WaveFileMetadata(
            sampleRate,
            channels,
            bitsPerSample,
            dataBytes,
            TimeSpan.FromSeconds(samples / (double)sampleRate));
        return true;
    }
}
