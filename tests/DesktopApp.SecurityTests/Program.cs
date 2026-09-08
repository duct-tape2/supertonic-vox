using System.Net.Http;
using System.Text;
using TTS_WinForms_App.Services;

static void Assert(bool condition, string message)
{
    if (!condition)
    {
        throw new InvalidOperationException(message);
    }
}

string firstToken = LocalSidecarSecurity.CreateToken();
string secondToken = LocalSidecarSecurity.CreateToken();
Assert(firstToken.Length == 64, "Token must contain 256 bits encoded as hex.");
Assert(firstToken != secondToken, "Tokens must be unique.");
Assert(LocalSidecarSecurity.CreateSessionId().Length == 32, "Session ID must contain 128 bits.");

using HttpRequestMessage request = new();
LocalSidecarSecurity.AddToken(request, firstToken);
Assert(request.Headers.TryGetValues(LocalSidecarSecurity.TokenHeaderName, out var values), "Token header missing.");
Assert(values!.Single() == firstToken, "Token header changed.");

byte[] bounded = await LocalSidecarSecurity.ReadBoundedAsync(
    new ByteArrayContent(Encoding.UTF8.GetBytes("safe")),
    maximumBytes: 4);
Assert(Encoding.UTF8.GetString(bounded) == "safe", "Bounded response changed.");

bool rejected = false;
try
{
    await LocalSidecarSecurity.ReadBoundedAsync(new ByteArrayContent(new byte[5]), maximumBytes: 4);
}
catch (InvalidDataException)
{
    rejected = true;
}
Assert(rejected, "Oversized response was not rejected.");

string root = Path.Combine(Path.GetTempPath(), "SupertonicVoxSecurityTests", Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);
try
{
    string atomicPath = Path.Combine(root, "atomic.txt");
    LocalSidecarSecurity.WriteAllTextAtomic(atomicPath, "first", Encoding.UTF8);
    LocalSidecarSecurity.WriteAllTextAtomic(atomicPath, "second", Encoding.UTF8);
    Assert(File.ReadAllText(atomicPath, Encoding.UTF8) == "second", "Atomic write failed.");

    string output = LocalSidecarSecurity.CreateUniqueOutputPath(root, "sample");
    File.WriteAllBytes(output, []);
    string nextOutput = LocalSidecarSecurity.CreateUniqueOutputPath(root, "sample");
    Assert(output != nextOutput, "Existing output would be overwritten.");

    string log = Path.Combine(root, "server.log");
    LocalSidecarSecurity.AppendRotatingLog(log, "12345", maxBytes: 4, backups: 3);
    LocalSidecarSecurity.AppendRotatingLog(log, "67890", maxBytes: 4, backups: 3);
    Assert(File.Exists(log + ".1"), "Log rotation did not preserve the previous file.");
}
finally
{
    Directory.Delete(root, recursive: true);
}

Console.WriteLine("DesktopApp.SecurityTests: PASS");
