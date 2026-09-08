using System;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace TTS_WinForms_App.Services;

internal static class LocalSidecarSecurity
{
	public const string TokenHeaderName = "X-Local-TTS-Token";
	public const long VoxResponseLimitBytes = 128L * 1024 * 1024;
	public const long SupertonicResponseLimitBytes = 512L * 1024 * 1024;
	public const long ReferenceWavLimitBytes = 64L * 1024 * 1024;

	public static string CreateToken()
	{
		return Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
	}

	public static string CreateSessionId()
	{
		return Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
	}

	public static HttpClient CreateLoopbackClient(TimeSpan timeout)
	{
		HttpClientHandler handler = new HttpClientHandler
		{
			UseProxy = false
		};
		return new HttpClient(handler, disposeHandler: true)
		{
			Timeout = timeout
		};
	}

	public static void AddToken(HttpRequestMessage request, string token)
	{
		if (string.IsNullOrWhiteSpace(token))
		{
			throw new InvalidOperationException("로컬 TTS 서버 인증 토큰이 준비되지 않았습니다.");
		}
		request.Headers.TryAddWithoutValidation(TokenHeaderName, token);
	}

	public static async Task<byte[]> ReadBoundedAsync(
		HttpContent content,
		long maximumBytes,
		CancellationToken cancellationToken = default)
	{
		if (content.Headers.ContentLength is long declaredLength && declaredLength > maximumBytes)
		{
			throw new InvalidDataException($"로컬 TTS 응답이 허용 크기 {maximumBytes:N0}바이트를 초과했습니다.");
		}

		await using Stream source = await content.ReadAsStreamAsync(cancellationToken);
		using MemoryStream destination = new MemoryStream(
			content.Headers.ContentLength is long length && length <= int.MaxValue
				? (int)length
				: 0);
		byte[] buffer = new byte[128 * 1024];
		long total = 0;
		while (true)
		{
			int read = await source.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken);
			if (read == 0)
			{
				break;
			}
			total = checked(total + read);
			if (total > maximumBytes)
			{
				throw new InvalidDataException($"로컬 TTS 응답이 허용 크기 {maximumBytes:N0}바이트를 초과했습니다.");
			}
			destination.Write(buffer, 0, read);
		}
		return destination.ToArray();
	}

	public static void WriteAllTextAtomic(string path, string content, Encoding encoding)
	{
		string directory = Path.GetDirectoryName(Path.GetFullPath(path))
			?? throw new InvalidOperationException("저장 폴더를 확인할 수 없습니다.");
		Directory.CreateDirectory(directory);
		string temporary = Path.Combine(directory, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
		try
		{
			File.WriteAllText(temporary, content, encoding);
			File.Move(temporary, path, overwrite: true);
		}
		finally
		{
			try
			{
				if (File.Exists(temporary))
				{
					File.Delete(temporary);
				}
			}
			catch
			{
			}
		}
	}

	public static void WriteAllBytesAtomic(string path, byte[] content)
	{
		string directory = Path.GetDirectoryName(Path.GetFullPath(path))
			?? throw new InvalidOperationException("저장 폴더를 확인할 수 없습니다.");
		Directory.CreateDirectory(directory);
		string temporary = Path.Combine(directory, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
		try
		{
			File.WriteAllBytes(temporary, content);
			File.Move(temporary, path, overwrite: true);
		}
		finally
		{
			try
			{
				if (File.Exists(temporary))
				{
					File.Delete(temporary);
				}
			}
			catch
			{
			}
		}
	}

	public static string CreateUniqueOutputPath(string directory, string title)
	{
		Directory.CreateDirectory(directory);
		string stem = $"{DateTime.Now:yyyyMMdd_HHmmss_fff}_{title}";
		string candidate = Path.Combine(directory, stem + ".wav");
		for (int suffix = 1; File.Exists(candidate); suffix++)
		{
			candidate = Path.Combine(directory, $"{stem}_{suffix:00}.wav");
		}
		return candidate;
	}

	public static void AppendRotatingLog(string path, string line, long maxBytes = 5L * 1024 * 1024, int backups = 3)
	{
		string? directory = Path.GetDirectoryName(path);
		if (!string.IsNullOrWhiteSpace(directory))
		{
			Directory.CreateDirectory(directory);
		}
		if (File.Exists(path) && new FileInfo(path).Length >= maxBytes)
		{
			for (int index = backups; index >= 1; index--)
			{
				string source = index == 1 ? path : path + "." + (index - 1);
				string target = path + "." + index;
				if (!File.Exists(source))
				{
					continue;
				}
				File.Move(source, target, overwrite: true);
			}
		}
		File.AppendAllText(path, line, Encoding.UTF8);
	}
}
