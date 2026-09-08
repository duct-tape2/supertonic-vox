using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace PronunciationEngine;

public sealed record PronunciationResult(
    string OriginalText,
    string StandardPronunciationPreview,
    string TtsRequestText,
    IReadOnlyList<string> RulesApplied);

public sealed class PronunciationOptions
{
    public string BaseDirectory { get; init; } = Path.Combine(AppContext.BaseDirectory, "_internal");
    public bool ApplyNumberReading { get; init; } = true;
    public bool ApplyAcronymReading { get; init; } = true;
    public bool ApplyUserOverrides { get; init; } = true;
    public bool ApplySibilantSafeRewrite { get; init; } = true;
    public bool ApplyAnnouncerPauses { get; init; } = true;
}

public static class KoreanAnnouncerPronunciationNormalizer
{
    public static PronunciationResult NormalizeForTts(string originalText, PronunciationOptions? options = null)
    {
        options ??= new PronunciationOptions();
        var logs = new List<string>();
        string original = originalText ?? "";
        string normalized = TextPreNormalizer.NormalizeWhitespaceAndPunctuation(original);
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return new PronunciationResult(original, "", "", Array.Empty<string>());
        }

        string working = normalized;
        if (options.ApplyNumberReading)
        {
            string before = working;
            working = KoreanNumberReader.Expand(working);
            AddLogIfChanged(logs, "NUMBER_READ", before, working);
        }

        if (options.ApplyAcronymReading)
        {
            string before = working;
            working = DictionaryRewriter.ApplyAcronyms(working, options.BaseDirectory);
            AddLogIfChanged(logs, "ACRONYM_READ", before, working);
        }

        if (options.ApplyUserOverrides)
        {
            string before = working;
            working = DictionaryRewriter.ApplyUserOverrides(working, options.BaseDirectory);
            AddLogIfChanged(logs, "USER_OVERRIDES", before, working);
        }

        string preview = StandardPronunciationRules.ApplyPreview(working, logs);
        preview = DictionaryRewriter.ApplyStandardLexiconPreview(preview, options.BaseDirectory, logs);

        string ttsBase = StandardPronunciationRules.ApplyTtsSafe(working, logs);
        ttsBase = DictionaryRewriter.ApplyStandardLexiconTts(ttsBase, options.BaseDirectory, logs);
        string tts = TtsTextRewriteService.RewriteSafe(ttsBase, options.BaseDirectory, options.ApplySibilantSafeRewrite, logs);
        tts = KoreanNarrationPolisher.Apply(tts, options.BaseDirectory, logs);
        if (options.ApplyAnnouncerPauses)
        {
            string before = tts;
            tts = AnnouncerPauseService.Apply(tts);
            AddLogIfChanged(logs, "ANNOUNCER_PAUSE", before, tts);
        }

        return new PronunciationResult(original, preview, tts, logs);
    }

    private static void AddLogIfChanged(List<string> logs, string rule, string before, string after)
    {
        if (!string.Equals(before, after, StringComparison.Ordinal))
        {
            logs.Add(rule);
        }
    }
}

internal static class TextPreNormalizer
{
    public static string NormalizeWhitespaceAndPunctuation(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return "";
        }
        string normalized = text.Replace("\r\n", "\n").Replace('\r', '\n');
        normalized = Regex.Replace(normalized, "<[^>]+>", " ");
        normalized = Regex.Replace(normalized, @"[ \t]{2,}", " ");
        normalized = Regex.Replace(normalized, @"\n{3,}", "\n\n");
        normalized = Regex.Replace(normalized, @"\s+([,.?!:;])", "$1");
        return normalized.Trim();
    }
}

internal static class KoreanNumberReader
{
    private const string ParticlePattern = "((?:에서|부터|까지|으로|로|은|는|이|가|을|를|에|쯤|경|만|도){0,2})";
    private static readonly string[] SinoDigits = { "영", "일", "이", "삼", "사", "오", "육", "칠", "팔", "구" };
    private static readonly string[] SmallUnits = { "", "십", "백", "천" };
    private static readonly string[] LargeUnits = { "", "만", "억", "조", "경" };
    private static readonly string[] NativeOnes = { "", "한", "두", "세", "네", "다섯", "여섯", "일곱", "여덟", "아홉" };
    private static readonly string[] NativeTeens = { "", "열", "열한", "열두", "열세", "열네", "열다섯", "열여섯", "열일곱", "열여덟", "열아홉" };
    private static readonly string[] NativeTens = { "", "", "스물", "서른", "마흔", "쉰", "예순", "일흔", "여든", "아흔" };
    private static readonly string[] NativeHours = { "", "한", "두", "세", "네", "다섯", "여섯", "일곱", "여덟", "아홉", "열", "열한", "열두" };

    public static string Expand(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return "";
        }

        var protectedTokens = new Dictionary<string, string>();
        text = ProtectCodeTokens(text, protectedTokens);
        text = Regex.Replace(text, @"(?<!\d)(0\d{1,2})[-\s](\d{3,4})[-\s](\d{4})(?!\d)", m => $"{ReadDigits(m.Groups[1].Value)}, {ReadDigits(m.Groups[2].Value)}, {ReadDigits(m.Groups[3].Value)}");
        text = Regex.Replace(text, @"(?<![A-Za-z0-9가-힣])([+-])\s*(\d[\d,]*(?:\.\d+)?)\s*(%|퍼센트)" + ParticlePattern, m => $"{(m.Groups[1].Value == "-" ? "마이너스" : "플러스")} {ReadNumber(m.Groups[2].Value)} 퍼센트{m.Groups[4].Value}");
        text = Regex.Replace(text, @"(?<![A-Za-z0-9가-힣])\$(\d[\d,]*(?:\.\d+)?)", m => $"{ReadNumber(m.Groups[1].Value)} 달러");
        text = Regex.Replace(text, @"(?<![A-Za-z0-9])(\d[\d,]*(?:\.\d+)?)\s*(%|퍼센트)" + ParticlePattern, m => $"{ReadNumber(m.Groups[1].Value)} 퍼센트{m.Groups[3].Value}");
        text = Regex.Replace(text, @"(?<![A-Za-z0-9])(\d{1,2})\s*:\s*(\d{2})" + ParticlePattern + @"(?![A-Za-z0-9가-힣])", m => $"{ReadHour(m.Groups[1].Value)}시 {ReadNumber(m.Groups[2].Value)}분{m.Groups[3].Value}");
        text = Regex.Replace(text, @"(?<![A-Za-z0-9])(\d{1,2})\s*시간\s*(\d{1,2})\s*분?" + ParticlePattern + @"(?![A-Za-z0-9가-힣])", m => $"{ReadNativeCount(m.Groups[1].Value)} 시간 {ReadNumber(m.Groups[2].Value)}분{m.Groups[3].Value}");
        text = Regex.Replace(text, @"(?<![A-Za-z0-9])(\d{1,2})\s*시\s*(\d{1,2})\s*분?" + ParticlePattern + @"(?![A-Za-z0-9가-힣])", m => $"{ReadHour(m.Groups[1].Value)}시 {ReadNumber(m.Groups[2].Value)}분{m.Groups[3].Value}");
        text = ReplaceNativeRange(text);
        text = ReplaceSinoRange(text);
        text = Regex.Replace(text, @"(?<![A-Za-z0-9])(\d{1,2})\s*시" + ParticlePattern + @"(?![A-Za-z0-9가-힣])", m => $"{ReadHour(m.Groups[1].Value)}시{m.Groups[2].Value}");
        text = Regex.Replace(text, @"제\s*(\d[\d,]*)\s*(장|회|차|부|편|번)" + ParticlePattern + @"(?![A-Za-z0-9가-힣])", m => $"제{ReadNumber(m.Groups[1].Value)}{m.Groups[2].Value}{m.Groups[3].Value}");
        text = ReplaceNativeUnit(text);
        text = ReplaceSinoUnit(text, "년|월|일|분|초|원|층|쪽|페이지|번|차|회|위|등|분기|조|억|만");
        text = Regex.Replace(text, @"(?<![A-Za-z0-9])(\d[\d,]*(?:\.\d+)?)\s*(달러)" + ParticlePattern + @"(?![A-Za-z0-9가-힣])", m => $"{ReadNumber(m.Groups[1].Value)} 달러{m.Groups[3].Value}");
        text = Regex.Replace(text, @"(?<![A-Za-z0-9])(\d[\d,]*(?:\.\d+)?)(?![A-Za-z0-9])", m => ReadNumber(m.Groups[1].Value));
        text = RestoreCodeTokens(text, protectedTokens);
        text = Regex.Replace(text, @"[ \t]{2,}", " ");
        return text.Trim();
    }

    private static string ProtectCodeTokens(string text, Dictionary<string, string> protectedTokens)
    {
        return Regex.Replace(text, @"https?://\S+|www\.\S+|[A-Za-z가-힣0-9_\-]+\.[A-Za-z]{1,5}\b|\b[vV]\d+(?:\.\d+)+\b|\b[A-Za-z]+[-_]?\d+(?:\.\d+)*\b", m =>
        {
            string key = ((char)(0xE000 + protectedTokens.Count)).ToString();
            protectedTokens[key] = m.Value;
            return key;
        });
    }

    private static string RestoreCodeTokens(string text, Dictionary<string, string> protectedTokens)
    {
        foreach (var pair in protectedTokens)
        {
            text = text.Replace(pair.Key, pair.Value, StringComparison.Ordinal);
        }
        return text;
    }

    private static string ReplaceNativeRange(string text)
    {
        return Regex.Replace(text, @"(?<![A-Za-z0-9])(\d[\d,]*)\s*(?:~|-|–|—)\s*(\d[\d,]*)\s*(개|명|마리|잔|권|장|배|시간)" + ParticlePattern + @"(?![A-Za-z0-9가-힣])", m => $"{ReadNativeCount(m.Groups[1].Value)} {m.Groups[3].Value}에서 {ReadNativeCount(m.Groups[2].Value)} {m.Groups[3].Value}{m.Groups[4].Value}");
    }

    private static string ReplaceSinoRange(string text)
    {
        text = Regex.Replace(text, @"(?<![A-Za-z0-9])(\d[\d,]*)\s*(?:~|-|–|—)\s*(\d[\d,]*)\s*(년|월|일|분|초|원|층|쪽|페이지|번|차|회|위|등)" + ParticlePattern + @"(?![A-Za-z0-9가-힣])", m => $"{ReadUnitNumber(m.Groups[1].Value, m.Groups[3].Value)}{m.Groups[3].Value}에서 {ReadUnitNumber(m.Groups[2].Value, m.Groups[3].Value)}{m.Groups[3].Value}{m.Groups[4].Value}");
        return Regex.Replace(text, @"(?<![A-Za-z0-9])(\d[\d,]*)\s*(?:~|-|–|—)\s*(\d[\d,]*)(?![A-Za-z0-9가-힣])", m => $"{ReadNumber(m.Groups[1].Value)}에서 {ReadNumber(m.Groups[2].Value)}");
    }

    private static string ReplaceNativeUnit(string text)
    {
        text = Regex.Replace(text, @"(?<![A-Za-z0-9])(\d[\d,]*\.\d+)\s*(개|명|마리|잔|권|장|배|시간)" + ParticlePattern + @"(?![A-Za-z0-9가-힣])", m => $"{ReadNumber(m.Groups[1].Value)} {m.Groups[2].Value}{m.Groups[3].Value}");
        return Regex.Replace(text, @"(?<![A-Za-z0-9])(\d[\d,]*)\s*(개|명|마리|잔|권|장|배|시간)" + ParticlePattern + @"(?![A-Za-z0-9가-힣])", m => $"{ReadNativeCount(m.Groups[1].Value)} {m.Groups[2].Value}{m.Groups[3].Value}");
    }

    private static string ReplaceSinoUnit(string text, string unitPattern)
    {
        return Regex.Replace(text, $@"(?<![A-Za-z0-9])(\d[\d,]*(?:\.\d+)?)\s*({unitPattern}){ParticlePattern}(?![A-Za-z0-9가-힣])", m => $"{ReadUnitNumber(m.Groups[1].Value, m.Groups[2].Value)}{m.Groups[2].Value}{m.Groups[3].Value}");
    }

    private static string ReadUnitNumber(string raw, string unit)
    {
        if (unit == "월" && int.TryParse(raw.Replace(",", ""), out int month))
        {
            return month switch
            {
                6 => "유",
                10 => "시",
                _ => ReadNumber(raw)
            };
        }
        return ReadNumber(raw);
    }

    private static string ReadHour(string raw)
    {
        if (int.TryParse(raw, out int hour) && hour >= 1 && hour < NativeHours.Length)
        {
            return NativeHours[hour];
        }
        return ReadNumber(raw);
    }

    private static string ReadNativeCount(string raw)
    {
        string cleaned = raw.Replace(",", "");
        if (!int.TryParse(cleaned, out int value) || value <= 0)
        {
            return ReadNumber(raw);
        }
        if (value < 10)
        {
            return NativeOnes[value];
        }
        if (value < 20)
        {
            return NativeTeens[value - 9];
        }
        if (value < 100)
        {
            int tens = value / 10;
            int ones = value % 10;
            if (tens == 2 && ones == 0)
            {
                return "스무";
            }
            return NativeTens[tens] + (ones > 0 ? NativeOnes[ones] : "");
        }
        return ReadNumber(raw);
    }

    private static string ReadNumber(string raw)
    {
        string cleaned = raw.Replace(",", "").Trim();
        if (cleaned.Length == 0)
        {
            return raw;
        }
        if (cleaned.Contains('.'))
        {
            string[] parts = cleaned.Split('.', 2);
            string integer = ReadInteger(parts[0]);
            string fraction = parts.Length > 1 ? ReadDigits(parts[1]) : "";
            return string.IsNullOrWhiteSpace(fraction) ? integer : $"{integer} 점 {fraction}";
        }
        if (cleaned.Length > 1 && cleaned.StartsWith("0", StringComparison.Ordinal))
        {
            return ReadDigits(cleaned);
        }
        return ReadInteger(cleaned);
    }

    private static string ReadDigits(string digits)
    {
        var parts = new List<string>();
        foreach (char ch in digits.Where(char.IsDigit))
        {
            parts.Add(ch == '0' ? "공" : SinoDigits[ch - '0']);
        }
        return string.Join(" ", parts);
    }

    private static string ReadInteger(string digits)
    {
        digits = digits.TrimStart('0');
        if (digits.Length == 0)
        {
            return "영";
        }
        var groups = new List<string>();
        int unitIndex = 0;
        for (int end = digits.Length; end > 0; end -= 4)
        {
            int start = Math.Max(0, end - 4);
            string groupText = digits.Substring(start, end - start);
            int groupValue = int.Parse(groupText);
            if (groupValue > 0)
            {
                string group = ReadFourDigits(groupValue);
                string largeUnit = unitIndex < LargeUnits.Length ? LargeUnits[unitIndex] : "";
                if (groupValue == 1 && unitIndex > 0)
                {
                    group = "";
                }
                groups.Insert(0, group + largeUnit);
            }
            unitIndex++;
        }
        return string.Join("", groups);
    }

    private static string ReadFourDigits(int value)
    {
        var sb = new StringBuilder();
        string padded = value.ToString("D4");
        for (int i = 0; i < 4; i++)
        {
            int digit = padded[i] - '0';
            int place = 3 - i;
            if (digit == 0)
            {
                continue;
            }
            if (!(digit == 1 && place > 0))
            {
                sb.Append(SinoDigits[digit]);
            }
            sb.Append(SmallUnits[place]);
        }
        return sb.ToString();
    }
}

internal static class DictionaryRewriter
{
    public static string ApplyAcronyms(string text, string baseDirectory)
    {
        var readings = DefaultAcronyms();
        foreach (var pair in LoadSimpleMap(Path.Combine(baseDirectory, "Data", "acronym_readings.json")))
        {
            readings[pair.Key] = pair.Value;
        }
        foreach (var pair in LoadSimpleMap(Path.Combine(baseDirectory, "Data", "proper_noun_readings.json")))
        {
            readings[pair.Key] = pair.Value;
        }
        foreach (var pair in readings.OrderByDescending(p => p.Key.Length))
        {
            string pattern = $@"(?<![A-Za-z0-9가-힣_.-]){Regex.Escape(pair.Key)}(?![-_.]?\d)(?![A-Za-z0-9가-힣_.-])";
            text = Regex.Replace(text, pattern, pair.Value);
        }
        return text;
    }

    public static string ApplyUserOverrides(string text, string baseDirectory)
    {
        var rules = new List<(string From, string To)>();
        rules.AddRange(LoadOverridePairs(Path.Combine(baseDirectory, "pronunciation_overrides.json"), useTtsText: true));
        rules.AddRange(LoadOverridePairs(Path.Combine(baseDirectory, "Data", "pronunciation_overrides.json"), useTtsText: true));
        foreach (var rule in rules.Where(r => !string.IsNullOrWhiteSpace(r.From) && !string.IsNullOrWhiteSpace(r.To)).OrderByDescending(r => r.From.Length))
        {
            text = text.Replace(rule.From, rule.To, StringComparison.Ordinal);
        }
        return text;
    }

    public static string ApplyStandardLexiconPreview(string text, string baseDirectory, List<string> logs)
    {
        foreach (var rule in LoadOverridePairs(Path.Combine(baseDirectory, "Data", "standard_pronunciation_lexicon.json"), useTtsText: false).OrderByDescending(r => r.From.Length))
        {
            string before = text;
            text = text.Replace(rule.From, rule.To, StringComparison.Ordinal);
            if (!string.Equals(before, text, StringComparison.Ordinal))
            {
                logs.Add("STANDARD_LEXICON: " + rule.From);
            }
        }
        return text;
    }

    public static string ApplyStandardLexiconTts(string text, string baseDirectory, List<string> logs)
    {
        foreach (var rule in LoadOverridePairs(Path.Combine(baseDirectory, "Data", "standard_pronunciation_lexicon.json"), useTtsText: true).OrderByDescending(r => r.From.Length))
        {
            string before = text;
            text = text.Replace(rule.From, rule.To, StringComparison.Ordinal);
            if (!string.Equals(before, text, StringComparison.Ordinal))
            {
                logs.Add("STANDARD_LEXICON_TTS: " + rule.From);
            }
        }
        return text;
    }

    public static List<(string From, string To)> LoadTtsRewriteRules(string baseDirectory)
    {
        return LoadOverridePairs(Path.Combine(baseDirectory, "Data", "tts_rewrite_overrides.json"), useTtsText: true).ToList();
    }

    private static Dictionary<string, string> DefaultAcronyms()
    {
        return new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["AI"] = "에이아이",
            ["API"] = "에이피아이",
            ["TTS"] = "티티에스",
            ["GPU"] = "지피유",
            ["CPU"] = "시피유",
            ["ETF"] = "이티에프",
            ["KOSPI"] = "코스피",
            ["KOSDAQ"] = "코스닥",
            ["OpenAI"] = "오픈에이아이",
            ["NVIDIA"] = "엔비디아",
            ["Supertonic"] = "슈퍼토닉"
        };
    }

    private static Dictionary<string, string> LoadSimpleMap(string path)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        if (!File.Exists(path))
        {
            return result;
        }
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(path, Encoding.UTF8));
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
            {
                return result;
            }
            foreach (var prop in doc.RootElement.EnumerateObject())
            {
                if (prop.Value.ValueKind == JsonValueKind.String)
                {
                    result[prop.Name] = prop.Value.GetString() ?? "";
                }
                else if (prop.Value.ValueKind == JsonValueKind.Object && prop.Value.TryGetProperty("default", out var value))
                {
                    result[prop.Name] = value.GetString() ?? "";
                }
            }
        }
        catch
        {
        }
        return result;
    }

    private static IEnumerable<(string From, string To)> LoadOverridePairs(string path, bool useTtsText)
    {
        if (!File.Exists(path))
        {
            yield break;
        }
        JsonDocument? doc = null;
        try
        {
            doc = JsonDocument.Parse(File.ReadAllText(path, Encoding.UTF8));
            var root = doc.RootElement;
            if (root.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in root.EnumerateArray())
                {
                    string from = ReadString(item, "From", "from", "surface", "surfacePattern");
                    string to = ReadString(item, "To", "to", useTtsText ? "ttsText" : "pronunciation", "preferred", "standardPronunciation");
                    bool enabled = !item.TryGetProperty("enabled", out var enabledProp) || enabledProp.ValueKind != JsonValueKind.False;
                    if (enabled)
                    {
                        yield return (from, to);
                    }
                }
            }
            else if (root.ValueKind == JsonValueKind.Object && root.TryGetProperty("entries", out var entries) && entries.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in entries.EnumerateArray())
                {
                    string from = ReadString(item, "From", "from", "surface", "surfacePattern");
                    string to = ReadString(item, "To", "to", useTtsText ? "ttsText" : "pronunciation", "preferred", "standardPronunciation");
                    bool enabled = !item.TryGetProperty("enabled", out var enabledProp) || enabledProp.ValueKind != JsonValueKind.False;
                    if (enabled)
                    {
                        yield return (from, to);
                    }
                }
            }
        }
        finally
        {
            doc?.Dispose();
        }
    }

    private static string ReadString(JsonElement element, params string[] names)
    {
        foreach (string name in names)
        {
            if (element.TryGetProperty(name, out var prop))
            {
                if (prop.ValueKind == JsonValueKind.String)
                {
                    return prop.GetString() ?? "";
                }
                if (prop.ValueKind == JsonValueKind.Array)
                {
                    var first = prop.EnumerateArray().FirstOrDefault();
                    if (first.ValueKind == JsonValueKind.String)
                    {
                        return first.GetString() ?? "";
                    }
                }
            }
        }
        return "";
    }
}

internal static class StandardPronunciationRules
{
    private static readonly (string From, string To, string Rule)[] ExactRules =
    {
        ("이 버튼을", "이 버트늘", "R030 연음"),
        ("꽃이", "꼬치", "R030 연음"),
        ("꽃을", "꼬츨", "R030 연음"),
        ("부엌이", "부어키", "R030 연음"),
        ("부엌을", "부어클", "R030 연음"),
        ("닭이", "달기", "R030 연음"),
        ("닭을", "달글", "R030 연음"),
        ("값을", "갑쓸", "R030 연음"),
        ("옷", "옫", "R020 받침 대표음화"),
        ("낮", "낟", "R020 받침 대표음화"),
        ("낯", "낟", "R020 받침 대표음화"),
        ("낱", "낟", "R020 받침 대표음화"),
        ("앞", "압", "R020 받침 대표음화"),
        ("부엌", "부억", "R020 받침 대표음화"),
        ("넋", "넉", "R022 겹받침"),
        ("앉다", "안따", "R022 겹받침"),
        ("여덟", "여덜", "R022 겹받침"),
        ("넓다", "널따", "R023 ㄼ 예외"),
        ("닭", "닥", "R022 겹받침"),
        ("흙과", "흑꽈", "R022/R060 겹받침 경음화"),
        ("맑다", "막따", "R025 겹받침 경음화"),
        ("젊다", "점따", "R022 겹받침"),
        ("읊다", "읍따", "R024 겹받침"),
        ("옷 입다", "온닙따", "R090 ㄴ 첨가"),
        ("꽃잎", "꼰닙", "R090 ㄴ 첨가"),
        ("나뭇잎", "나문닙", "R091 사이시옷"),
        ("깻잎", "깬닙", "R091 사이시옷"),
        ("솜이불", "솜니불", "R090 ㄴ 첨가"),
        ("막일", "망닐", "R090 ㄴ 첨가"),
        ("한여름", "한녀름", "R090 ㄴ 첨가"),
        ("직행열차", "지캥녈차", "R090 ㄴ 첨가"),
        ("영업용", "영엄뇽", "R090 ㄴ 첨가"),
        ("식용유", "시굥뉴", "R090 ㄴ 첨가"),
        ("들일", "들릴", "R090 ㄴ 첨가"),
        ("서울역", "서울력", "R090 ㄴ 첨가"),
        ("할 일", "할릴", "R090 ㄴ 첨가"),
        ("송별연", "송벼련", "R090 ㄴ 첨가"),
        ("밭 아래", "바다래", "R031 절음"),
        ("늪 앞", "느밥", "R031 절음"),
        ("맛없다", "마덥따", "R031 절음"),
        ("겉옷", "거돋", "R031 절음"),
        ("꽃 위", "꼬뒤", "R031 절음"),
        ("부엌 안", "부어간", "R031 절음"),
        ("놓고", "노코", "R026 ㅎ 축약"),
        ("좋던", "조턴", "R026 ㅎ 축약"),
        ("쌓지", "싸치", "R026 ㅎ 축약"),
        ("많고", "만코", "R026 ㅎ 축약"),
        ("각하", "가카", "R026 ㅎ 축약"),
        ("먹히다", "머키다", "R026 ㅎ 축약"),
        ("넓히다", "널피다", "R026 ㅎ 축약"),
        ("꽂히다", "꼬치다", "R026 ㅎ 축약"),
        ("닿소", "다쏘", "R026 ㅎ 축약"),
        ("많소", "만쏘", "R026 ㅎ 축약"),
        ("놓는", "논는", "R026 ㅎ 탈락"),
        ("낳은", "나은", "R026 ㅎ 탈락"),
        ("싫어도", "시러도", "R026 ㅎ 탈락"),
        ("굳이", "구지", "R040 구개음화"),
        ("미닫이", "미다지", "R040 구개음화"),
        ("밭이", "바치", "R040 구개음화"),
        ("굳히다", "구치다", "R040 구개음화"),
        ("닫히다", "다치다", "R040 구개음화"),
        ("묻히다", "무치다", "R040 구개음화"),
        ("먹는", "멍는", "R050 비음화"),
        ("국물", "궁물", "R050 비음화"),
        ("닫는", "단는", "R050 비음화"),
        ("짓는", "진는", "R050 비음화"),
        ("있는", "인는", "R050 비음화"),
        ("꽃망울", "꼰망울", "R050 비음화"),
        ("잡는", "잠는", "R050 비음화"),
        ("앞마당", "암마당", "R050 비음화"),
        ("없는", "엄는", "R050 비음화"),
        ("책 넣는다", "챙넌는다", "R050 비음화"),
        ("담력", "담녁", "R052 ㄹ 비음화"),
        ("강릉", "강능", "R052 ㄹ 비음화"),
        ("막론", "망논", "R052 ㄹ 비음화"),
        ("협력", "혐녁", "R052 ㄹ 비음화"),
        ("난로", "날로", "R070 유음화"),
        ("신라", "실라", "R070 유음화"),
        ("칼날", "칼랄", "R070 유음화"),
        ("물난리", "물랄리", "R070 유음화"),
        ("생산량", "생산냥", "R052 ㄹ 비음화"),
        ("결단력", "결딴녁", "R052/R060 경음화"),
        ("국밥", "국빱", "R080 경음화"),
        ("깎다", "깍따", "R080 경음화"),
        ("닭장", "닥짱", "R080 경음화"),
        ("있던", "읻떤", "R080 경음화"),
        ("꽃다발", "꼳따발", "R080 경음화"),
        ("낯설다", "낟썰다", "R080 경음화"),
        ("값지다", "갑찌다", "R080 경음화"),
        ("신고", "신꼬", "R080 경음화"),
        ("삼고", "삼꼬", "R080 경음화"),
        ("닮고", "담꼬", "R080 경음화"),
        ("넓게", "널께", "R080 경음화"),
        ("갈등", "갈뜽", "R080 경음화"),
        ("일시", "일씨", "R080 경음화"),
        ("발전", "발쩐", "R080 경음화"),
        ("할 수는", "할쑤는", "R064 관형사형 경음화"),
        ("할지라도", "할찌라도", "R064 관형사형 경음화"),
        ("냇가", "내까", "R074 사이시옷"),
        ("샛길", "새낄", "R074 사이시옷"),
        ("콧등", "코뜽", "R074 사이시옷"),
        ("햇살", "해쌀", "R074 사이시옷"),
        ("뱃속", "배쏙", "R074 사이시옷"),
        ("콧날", "콘날", "R074 사이시옷"),
        ("아랫니", "아랜니", "R074 사이시옷"),
        ("뱃머리", "밴머리", "R074 사이시옷"),
        ("뒷일", "뒨닐", "R074 사이시옷"),
        ("무늬", "무니", "R007 ㅢ"),
        ("희망", "히망", "R007 ㅢ"),
        ("유희", "유히", "R007 ㅢ")
    };

    public static string ApplyPreview(string text, List<string> logs)
    {
        foreach (var rule in ExactRules.OrderByDescending(r => r.From.Length))
        {
            string before = text;
            text = text.Replace(rule.From, rule.To, StringComparison.Ordinal);
            if (!string.Equals(before, text, StringComparison.Ordinal))
            {
                logs.Add(rule.Rule + ": " + rule.From + " -> " + rule.To);
            }
        }
        text = RestoreNativeUnitWords(text);
        text = Regex.Replace(text, @"(?<=[가-힣])\s+수\s+있습니다", m =>
        {
            logs.Add("R064 관형사형 경음화: 수 있습니다");
            return "쑤 읻씀니다";
        });
        text = text.Replace("있습니다", "읻씀니다", StringComparison.Ordinal);
        text = text.Replace("했습니다", "핻씀니다", StringComparison.Ordinal);
        text = text.Replace("었습니다", "얻씀니다", StringComparison.Ordinal);
        text = text.Replace("았습니다", "앋씀니다", StringComparison.Ordinal);
        text = text.Replace("되었습니다", "되얻씀니다", StringComparison.Ordinal);
        text = text.Replace("겠습니다", "겓씀니다", StringComparison.Ordinal);
        text = text.Replace("됩니다", "됨니다", StringComparison.Ordinal);
        text = Regex.Replace(text, @"([가-힣])습니다\b", "$1씀니다");
        return text;
    }

    public static string ApplyTtsSafe(string text, List<string> logs)
    {
        foreach (var rule in ExactRules.OrderByDescending(r => r.From.Length))
        {
            string before = text;
            text = text.Replace(rule.From, rule.To, StringComparison.Ordinal);
            if (!string.Equals(before, text, StringComparison.Ordinal))
            {
                logs.Add("TTS_" + rule.Rule + ": " + rule.From + " -> " + rule.To);
            }
        }
        return RestoreNativeUnitWords(text);
    }

    private static string RestoreNativeUnitWords(string text)
    {
        return Regex.Replace(text, @"여덜\s+(개|명|마리|잔|권|장|배|시간)(?=에서|부터|까지|으로|로|은|는|이|가|을|를|에|쯤|경|만|도|[\s,.?!]|$)", "여덟 $1");
    }
}

internal static class TtsTextRewriteService
{
    public static string RewriteSafe(string text, string baseDirectory, bool applySibilantSafeRewrite, List<string> logs)
    {
        foreach (var rule in DictionaryRewriter.LoadTtsRewriteRules(baseDirectory).OrderByDescending(r => r.From.Length))
        {
            string before = text;
            text = text.Replace(rule.From, rule.To, StringComparison.Ordinal);
            if (!string.Equals(before, text, StringComparison.Ordinal))
            {
                logs.Add("TTS_REWRITE: " + rule.From);
            }
        }

        string beforeObjection = text;
        text = Regex.Replace(text, @"(?<![가-힣])이의\s+있(?:습|씀|슴)니다(?=[\s,.?!]|$)", "이이 있씀니다");
        text = Regex.Replace(text, @"(?<![가-힣])이의(?=\s*(?:가|는|를|도|만|있|없|제기|신청|[,.?!]|$))", "이이");
        if (!string.Equals(beforeObjection, text, StringComparison.Ordinal))
        {
            logs.Add("OBJECTION_UI_READ");
        }

        if (!applySibilantSafeRewrite)
        {
            return text;
        }

        string beforeAll = text;
        text = Regex.Replace(text, @"(?<=[가-힣])\s+수\s+있습니다", " 쑤 있씀니다");
        text = Regex.Replace(text, @"(?<=[가-힣])\s+수\s+있어요", " 쑤 이써요");
        text = Regex.Replace(text, @"(?<![가-힣])수\s+있습니다(?![가-힣])", "수 있씀니다");
        text = Regex.Replace(text, @"(?<![가-힣])수\s+있어요(?![가-힣])", "수 이써요");
        text = text.Replace("있습니다", "있씀니다", StringComparison.Ordinal);
        text = text.Replace("있어요", "이써요", StringComparison.Ordinal);
        text = text.Replace("했습니다", "했씀니다", StringComparison.Ordinal);
        text = text.Replace("었습니다", "었씀니다", StringComparison.Ordinal);
        text = text.Replace("았습니다", "았씀니다", StringComparison.Ordinal);
        text = text.Replace("되었습니다", "되었씀니다", StringComparison.Ordinal);
        text = text.Replace("겠습니다", "겠씀니다", StringComparison.Ordinal);
        text = text.Replace("됩니다", "됨니다", StringComparison.Ordinal);
        text = Regex.Replace(text, @"(?<![가-힣])습니다\b", "씀니다");
        text = Regex.Replace(text, @"(?<=[가-힣])습니다\b", "씀니다");
        text = Regex.Replace(text, @"[ \t]{2,}", " ");
        if (!string.Equals(beforeAll, text, StringComparison.Ordinal))
        {
            logs.Add("SIBILANT_SAFE");
        }
        return text.Trim();
    }
}

internal static class KoreanNarrationPolisher
{
    public static string Apply(string text, string baseDirectory, List<string> logs)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return "";
        }

        string beforeAll = text;
        text = ApplyUserRules(text, baseDirectory, logs);
        text = ApplySpacingForReading(text, logs);
        text = ApplyHumanNarrationPhrasing(text, logs);
        text = ApplyCommonEndingPronunciation(text, logs);
        text = ApplyLightPhrasePauses(text, logs);
        text = Regex.Replace(text, @"[ \t]{2,}", " ");
        text = Regex.Replace(text, @"\s+([,.?!])", "$1");
        text = Regex.Replace(text, @"\n{3,}", "\n\n");

        if (!string.Equals(beforeAll, text, StringComparison.Ordinal) && !logs.Contains("NARRATION_POLISH"))
        {
            logs.Add("NARRATION_POLISH");
        }
        return text.Trim();
    }

    private static string ApplyUserRules(string text, string baseDirectory, List<string> logs)
    {
        string before = text;
        foreach (var rule in LoadRules(baseDirectory).Where(r => r.Enabled).OrderByDescending(r => r.Match.Length))
        {
            if (string.IsNullOrWhiteSpace(rule.Match) || string.IsNullOrWhiteSpace(rule.Rewrite))
            {
                continue;
            }
            text = text.Replace(rule.Match, rule.Rewrite, StringComparison.Ordinal);
        }
        if (!string.Equals(before, text, StringComparison.Ordinal))
        {
            logs.Add("NARRATION_USER_RULES");
        }
        return text;
    }

    private static string ApplySpacingForReading(string text, List<string> logs)
    {
        string before = text;
        text = Regex.Replace(text, @"(?<stem>[가-힣]+(?:는|은|던|한|할|될|인))(걸|건|게|거)(?=에서|부터|까지|으로|로|은|는|이|가|을|를|에|도|만|[\s,.?!]|$)", "${stem} $1");
        text = Regex.Replace(text, @"(?<stem>[가-힣]+(?:는|은|던|한|할|될|인))것(?=에서|부터|까지|보다|으로|로|은|는|이|가|을|를|에|도|만|[\s,.?!]|$)", "${stem} 것");
        text = text.Replace("할수", "할 수", StringComparison.Ordinal);
        text = text.Replace("수있", "수 있", StringComparison.Ordinal);
        text = Regex.Replace(text, @"(?<=[가-힣])할수(?=[\s,.?!]|$)", "할 수");
        text = Regex.Replace(text, @"(?<=[가-힣])수있", "수 있");
        text = Regex.Replace(text, @"(?<=[가-힣])것같", "것 같");
        text = Regex.Replace(text, @"(?<=[가-힣])거같", "거 같");
        text = text.Replace("좀더", "좀 더", StringComparison.Ordinal);
        text = text.Replace("더이상", "더 이상", StringComparison.Ordinal);
        text = text.Replace("들쑥날쑥", "들쑥 날쑥", StringComparison.Ordinal);
        if (!string.Equals(before, text, StringComparison.Ordinal))
        {
            logs.Add("NARRATION_SPACING");
        }
        return text;
    }

    private static string ApplyCommonEndingPronunciation(string text, List<string> logs)
    {
        string before = text;
        foreach (var pair in EndingRewrites)
        {
            text = Regex.Replace(text, pair.Pattern, pair.Rewrite);
        }
        if (!string.Equals(before, text, StringComparison.Ordinal))
        {
            logs.Add("NARRATION_ENDING_READ");
        }
        return text;
    }

    private static string ApplyHumanNarrationPhrasing(string text, List<string> logs)
    {
        string before = text;

        text = Regex.Replace(
            text,
            @"(?<prefix>[가-힣0-9A-Za-z\s,]+?)\s+(?:있는|인는)\s+걸\s+아시나요\?",
            "${prefix} 있다는 걸 알고 계신가요?");
        text = Regex.Replace(
            text,
            @"(?<prefix>[가-힣0-9A-Za-z\s,]+?)\s+없는\s+걸\s+아시나요\?",
            "${prefix} 없다는 걸 알고 계신가요?");
        text = Regex.Replace(text, @"(?<=\S)\s+건\s+아시나요\?", " 건 알고 계신가요?");
        text = Regex.Replace(text, @"(?<=\S)\s+걸\s+아시나요\?", " 걸 알고 계신가요?");
        text = text.Replace("아시나요?", "알고 계신가요?", StringComparison.Ordinal);

        if (!string.Equals(before, text, StringComparison.Ordinal))
        {
            logs.Add("NARRATION_NATURAL_PHRASE");
        }
        return text;
    }

    private static string ApplyLightPhrasePauses(string text, List<string> logs)
    {
        string before = text;
        text = Regex.Replace(text, @"(?<=[.?!])\s+(매일|하지만|그리고|그런데|그래서|결국|특히)\s+", " $1, ");
        text = Regex.Replace(text, @"(?<![,])\s+(왜냐하면|예를 들어)\s+", ", $1 ");
        if (!string.Equals(before, text, StringComparison.Ordinal))
        {
            logs.Add("NARRATION_LIGHT_PAUSE");
        }
        return text;
    }

    private static readonly (string Pattern, string Rewrite)[] EndingRewrites =
    {
        (@"겁니다(?=[\s,.?!]|$)", "검니다"),
        (@"입니다(?=[\s,.?!]|$)", "임니다"),
        (@"합니다(?=[\s,.?!]|$)", "함니다"),
        (@"갑니다(?=[\s,.?!]|$)", "감니다"),
        (@"옵니다(?=[\s,.?!]|$)", "옴니다"),
        (@"줍니다(?=[\s,.?!]|$)", "줌니다"),
        (@"봅니다(?=[\s,.?!]|$)", "봄니다"),
        (@"드립니다(?=[\s,.?!]|$)", "드림니다"),
        (@"납니다(?=[\s,.?!]|$)", "남니다"),
        (@"씁니다(?=[\s,.?!]|$)", "씀니다")
    };

    private static IEnumerable<(string Match, string Rewrite, bool Enabled)> LoadRules(string baseDirectory)
    {
        foreach (string path in new[]
        {
            Path.Combine(baseDirectory, "Data", "narration_pronunciation_overrides.json"),
            Path.Combine(baseDirectory, "narration_pronunciation_overrides.json")
        })
        {
            if (!File.Exists(path))
            {
                continue;
            }

            JsonDocument? doc = null;
            try
            {
                doc = JsonDocument.Parse(File.ReadAllText(path, Encoding.UTF8));
                JsonElement root = doc.RootElement;
                JsonElement entries = root.ValueKind == JsonValueKind.Array
                    ? root
                    : root.TryGetProperty("entries", out var value) ? value : default;
                if (entries.ValueKind != JsonValueKind.Array)
                {
                    continue;
                }
                foreach (var item in entries.EnumerateArray())
                {
                    bool enabled = !item.TryGetProperty("enabled", out var enabledProp) || enabledProp.ValueKind != JsonValueKind.False;
                    string match = ReadString(item, "match", "surface", "from");
                    string rewrite = ReadString(item, "rewrite", "ttsText", "to");
                    yield return (match, rewrite, enabled);
                }
            }
            finally
            {
                doc?.Dispose();
            }
        }
    }

    private static string ReadString(JsonElement element, params string[] names)
    {
        foreach (string name in names)
        {
            if (element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String)
            {
                return value.GetString() ?? "";
            }
        }
        return "";
    }
}

public enum SibilantMode
{
    Off,
    Light,
    Medium,
    Strong,
    Debug
}

public sealed class SibilantRewriteOptions
{
    public string BaseDirectory { get; init; } = Path.Combine(AppContext.BaseDirectory, "_internal");
    public bool Enabled { get; init; } = true;
    public bool AutoTunePayload { get; init; } = true;
    public int PreferredSteps { get; init; } = 10;
    public double PreferredSilenceDuration { get; init; } = 0.32;
    public int PreferredChunkLength { get; init; } = 180;
}

public sealed record SibilantCandidate(string Id, string Label, string TtsText)
{
    public string? FilePath { get; set; }
}

public sealed record SibilantRewriteResult(
    string OriginalText,
    string TtsText,
    int RiskScore,
    IReadOnlyList<string> AppliedRuleIds,
    IReadOnlyList<SibilantCandidate> Candidates);

public sealed record SibilantPayloadTuning(
    int RiskScore,
    bool ApplyConservativePayload,
    int Steps,
    int MaxChunkLength,
    double SilenceDuration);

public static class SupertonicSibilantRescueNormalizer
{
    private static readonly Regex PatternAsinayo = new(@"(아|하|보|쓰|드|계|오|읽|누르|만드|바꾸|저장하|실행하|확인하)시나요", RegexOptions.Compiled);
    private static readonly Regex PatternSuItsseumnida = new(@"(?<prefix>[가-힣]+(?:\s+)?)?(?:쑤|수)\s*,?\s*(?:있습니다|있씀니다|있슴니다|이씀니다|읻씀니다)", RegexOptions.Compiled);
    private static readonly Regex PatternSeumnidaEnding = new(@"있습니다|있씀니다|있슴니다|했습니다|했씀니다|했슴니다|됩니다|됨니다|습니다|씀니다|슴니다", RegexOptions.Compiled);
    private static readonly Regex PatternJuseyo = new(@"[가-힣]*주세요|있어요|이써요|하셨어요|하셔써요", RegexOptions.Compiled);

    public static SibilantMode ParseMode(string? mode)
    {
        return (mode ?? "Medium").Trim().ToLowerInvariant() switch
        {
            "off" or "끔" or "꺼짐" => SibilantMode.Off,
            "light" or "가볍게" => SibilantMode.Light,
            "strong" or "강하게" => SibilantMode.Strong,
            "debug" or "디버그" => SibilantMode.Debug,
            _ => SibilantMode.Medium
        };
    }

    public static string ToDisplayMode(SibilantMode mode)
    {
        return mode switch
        {
            SibilantMode.Off => "끄기",
            SibilantMode.Light => "가볍게",
            SibilantMode.Strong => "강하게",
            SibilantMode.Debug => "디버그",
            _ => "기본"
        };
    }

    public static SibilantRewriteResult Normalize(string input, string voice, SibilantMode mode, SibilantRewriteOptions? options = null)
    {
        options ??= new SibilantRewriteOptions();
        string original = input ?? "";
        int risk = ComputeSibilantRiskScore(original);
        if (!options.Enabled || mode == SibilantMode.Off || string.IsNullOrWhiteSpace(original) || risk == 0)
        {
            return new SibilantRewriteResult(original, original, risk, Array.Empty<string>(), Array.Empty<SibilantCandidate>());
        }

        var applied = new List<string>();
        string text = ApplyUserOverrides(original, options.BaseDirectory, applied);

        if (mode is SibilantMode.Light or SibilantMode.Medium or SibilantMode.Strong or SibilantMode.Debug)
        {
            text = ApplyPauseRules(text, applied);
        }

        if (mode is SibilantMode.Medium or SibilantMode.Strong)
        {
            text = ApplyConservativeSoftRules(text, voice, risk, options.BaseDirectory, applied);
        }

        if (mode == SibilantMode.Strong)
        {
            text = ApplyStrongSemanticRules(text, applied);
        }

        text = Cleanup(text);
        IReadOnlyList<SibilantCandidate> candidates = mode == SibilantMode.Debug
            ? BuildDebugCandidates(original, voice)
            : Array.Empty<SibilantCandidate>();

        return new SibilantRewriteResult(original, text, risk, applied, candidates);
    }

    public static int ComputeSibilantRiskScore(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return 0;
        }
        int score = 0;
        score += Regex.Matches(text, @"시\s*,?\s*나요|시나요|계셨\s*,?\s*나요|계셨나요").Count * 3;
        score += Regex.Matches(text, @"(?:쑤|수)\s*,?\s*(?:있습니다|있씀니다|있슴니다|이씀니다|읻씀니다)").Count * 4;
        score += PatternSeumnidaEnding.Matches(text).Count * 2;
        score += PatternJuseyo.Matches(text).Count * 2;
        score += (Regex.Matches(text, "[ㅅㅆ]").Count + Regex.Matches(text, "[사서소수스시씨쑤씀]").Count) / 10;
        return Math.Min(score, 10);
    }

    public static SibilantPayloadTuning BuildPayloadTuning(string text, bool enabled, SibilantMode mode, int requestedSteps)
    {
        int risk = ComputeSibilantRiskScore(text);
        bool conservative = enabled && mode != SibilantMode.Off && risk >= 2;
        return new SibilantPayloadTuning(
            risk,
            conservative,
            conservative ? Math.Max(requestedSteps, 10) : requestedSteps,
            conservative ? 180 : 300,
            conservative ? 0.32 : 0.25);
    }

    public static IReadOnlyList<SibilantCandidate> BuildDebugCandidates(string input, string voice)
    {
        var candidates = new List<SibilantCandidate>();
        AddCandidate(candidates, "original", "원본", input);
        AddCandidate(candidates, "pause", "쉼표 분리", ApplyPauseRules(input, new List<string>()));
        AddCandidate(candidates, "space", "어절 분리", ApplySpaceSplitRules(input));
        AddCandidate(candidates, "soft", "부드러운 표기", ApplySoftCandidateRules(input));
        AddCandidate(candidates, "semantic", "의미 보존 대체", ApplyStrongSemanticRules(ApplyPauseRules(input, new List<string>()), new List<string>()));
        return candidates;
    }

    private static string ApplyPauseRules(string text, List<string> applied)
    {
        string before = text;
        text = PatternSuItsseumnida.Replace(text, m =>
        {
            string prefix = m.Groups["prefix"].Value;
            return prefix + "수 있씀니다";
        });
        text = Regex.Replace(text, @"\s+수\s+있씀니다", " 수 있씀니다");
        if (!string.Equals(before, text, StringComparison.Ordinal))
        {
            applied.Add("sibilant.su_isseumnida.safe_read.v2");
        }
        return text;
    }

    private static string ApplyConservativeSoftRules(string text, string voice, int risk, string baseDirectory, List<string> applied)
    {
        bool allowSoft = risk >= 5 || LoadVoiceStrategies(baseDirectory, voice).Contains("soft_seumnida", StringComparer.OrdinalIgnoreCase);
        if (!allowSoft)
        {
            return text;
        }
        string before = text;
        text = text.Replace("있씀니다", "있슴니다", StringComparison.Ordinal);
        text = text.Replace("했씀니다", "했슴니다", StringComparison.Ordinal);
        text = text.Replace("었씀니다", "었슴니다", StringComparison.Ordinal);
        text = text.Replace("았씀니다", "았슴니다", StringComparison.Ordinal);
        text = text.Replace("겠씀니다", "겠슴니다", StringComparison.Ordinal);
        text = text.Replace("되었씀니다", "되었슴니다", StringComparison.Ordinal);
        if (!string.Equals(before, text, StringComparison.Ordinal))
        {
            applied.Add("sibilant.soft_seumnida.voice_profile");
        }
        return text;
    }

    private static string ApplyStrongSemanticRules(string text, List<string> applied)
    {
        string before = text;
        text = text.Replace("아시나요", "알고 계신가요", StringComparison.Ordinal);
        text = text.Replace("하시나요", "하고 계신가요", StringComparison.Ordinal);
        text = text.Replace("계셨나요", "알고 계셨나요", StringComparison.Ordinal);
        text = text.Replace("확인할 수, 있습니다", "확인 가능합니다", StringComparison.Ordinal);
        text = text.Replace("사용할 수, 있습니다", "사용 가능합니다", StringComparison.Ordinal);
        text = text.Replace("저장할 수, 있습니다", "저장 가능합니다", StringComparison.Ordinal);
        text = text.Replace("실행할 수, 있습니다", "실행 가능합니다", StringComparison.Ordinal);
        text = text.Replace("만들 수, 있습니다", "만들 수 있어요", StringComparison.Ordinal);
        if (!string.Equals(before, text, StringComparison.Ordinal))
        {
            applied.Add("sibilant.semantic_safe_replace.v1");
        }
        return text;
    }

    private static string ApplySpaceSplitRules(string text)
    {
        text = PatternSuItsseumnida.Replace(text, m => m.Groups["prefix"].Value + "수 있씀니다");
        return Cleanup(text);
    }

    private static string ApplySoftCandidateRules(string text)
    {
        string result = text;
        result = PatternSuItsseumnida.Replace(result, m => m.Groups["prefix"].Value + "수 있슴니다");
        result = result.Replace("있습니다", "있슴니다", StringComparison.Ordinal);
        result = result.Replace("있씀니다", "있슴니다", StringComparison.Ordinal);
        result = result.Replace("했습니다", "했슴니다", StringComparison.Ordinal);
        result = result.Replace("했씀니다", "했슴니다", StringComparison.Ordinal);
        result = result.Replace("습니다", "슴니다", StringComparison.Ordinal);
        result = result.Replace("씀니다", "슴니다", StringComparison.Ordinal);
        return Cleanup(result);
    }

    private static string ApplyUserOverrides(string text, string baseDirectory, List<string> applied)
    {
        string before = text;
        foreach (var rule in LoadSibilantOverrides(baseDirectory).OrderByDescending(r => r.Match.Length))
        {
            text = text.Replace(rule.Match, rule.Rewrite, StringComparison.Ordinal);
        }
        if (!string.Equals(before, text, StringComparison.Ordinal))
        {
            applied.Add("sibilant.user_overrides");
        }
        return text;
    }

    private static IEnumerable<(string Match, string Rewrite)> LoadSibilantOverrides(string baseDirectory)
    {
        foreach (string path in new[]
        {
            Path.Combine(baseDirectory, "sibilant_rewrite_overrides.json"),
            Path.Combine(baseDirectory, "Data", "sibilant_rewrite_overrides.json")
        })
        {
            if (!File.Exists(path))
            {
                continue;
            }
            JsonDocument? doc = null;
            try
            {
                doc = JsonDocument.Parse(File.ReadAllText(path, Encoding.UTF8));
                var root = doc.RootElement;
                if (root.ValueKind == JsonValueKind.Object && root.TryGetProperty("rules", out var rules))
                {
                    foreach (var item in rules.EnumerateArray())
                    {
                        bool enabled = !item.TryGetProperty("enabled", out var enabledProp) || enabledProp.ValueKind != JsonValueKind.False;
                        string match = ReadString(item, "match", "from", "surface");
                        string rewrite = ReadString(item, "rewrite", "to", "ttsText");
                        if (enabled && !string.IsNullOrWhiteSpace(match) && !string.IsNullOrWhiteSpace(rewrite))
                        {
                            yield return (match, rewrite);
                        }
                    }
                }
            }
            finally
            {
                doc?.Dispose();
            }
        }
    }

    private static HashSet<string> LoadVoiceStrategies(string baseDirectory, string voice)
    {
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string path = Path.Combine(baseDirectory, "SupertonicLocal", "cache", "sibilant_voice_profiles.json");
        if (!File.Exists(path))
        {
            if (voice is "M1" or "F3")
            {
                result.Add("soft_seumnida");
            }
            return result;
        }
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(path, Encoding.UTF8));
            if (doc.RootElement.TryGetProperty("voices", out var voices) &&
                voices.TryGetProperty(voice, out var profile) &&
                profile.TryGetProperty("preferredStrategies", out var strategies) &&
                strategies.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in strategies.EnumerateArray())
                {
                    string? value = item.GetString();
                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        result.Add(value);
                    }
                }
            }
        }
        catch
        {
        }
        return result;
    }

    private static void AddCandidate(List<SibilantCandidate> candidates, string id, string label, string text)
    {
        string cleaned = Cleanup(text);
        if (!candidates.Any(c => string.Equals(c.TtsText, cleaned, StringComparison.Ordinal)))
        {
            candidates.Add(new SibilantCandidate(id, label, cleaned));
        }
    }

    private static string Cleanup(string text)
    {
        text = Regex.Replace(text ?? "", @"\s+,", ",");
        text = Regex.Replace(text, @",{2,}", ",");
        text = Regex.Replace(text, @",\s*([.?!])", "$1");
        text = Regex.Replace(text, @"[ \t]{2,}", " ");
        return text.Trim();
    }

    private static string ReadString(JsonElement element, params string[] names)
    {
        foreach (string name in names)
        {
            if (element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String)
            {
                return value.GetString() ?? "";
            }
        }
        return "";
    }
}

internal static class AnnouncerPauseService
{
    private static readonly string[] Connectors =
    {
        "그러나", "그런데", "따라서", "반면", "다만", "또한", "특히", "결국", "즉", "예를 들어", "한편"
    };

    public static string Apply(string text)
    {
        foreach (string connector in Connectors)
        {
            text = Regex.Replace(text, $@"(^|[\s.!?\n]){Regex.Escape(connector)}(?!,)", m => m.Groups[1].Value + connector + ",");
        }
        text = Regex.Replace(text, @"([가-힣]{18,})(지만|으며|면서)\s+", "$1$2, ");
        text = Regex.Replace(text, @"\s+,", ",");
        text = Regex.Replace(text, @",{2,}", ",");
        return text.Trim();
    }
}
