namespace PostQuantum.CryptographicBillOfMaterials.Knowledge;

/// <summary>
/// A minimal, dependency-free JSON reader for the embedded <c>algorithms.json</c>. It exists so the
/// detection engine (and the analyzer that reuses it) can load the knowledge base WITHOUT pulling in
/// <c>System.Text.Json</c> — a Roslyn analyzer must keep its dependency closure to just the compiler
/// libraries to avoid assembly-load conflicts inside the IDE. The CLI still uses System.Text.Json via
/// <c>KnowledgeBase.LoadDefault</c>; this reader is only for the portable path.
///
/// Supports the JSON subset actually present in <c>algorithms.json</c>: objects, arrays, strings (with
/// the standard escape sequences), numbers, <c>true</c>/<c>false</c>/<c>null</c>. Comments and trailing
/// commas are tolerated to match the System.Text.Json options used elsewhere.
/// </summary>
internal static class MiniJson
{
    /// <summary>Parse JSON text into object graph: <see cref="Dictionary{TKey,TValue}"/> (string→object?),
    /// <see cref="List{T}"/> of object?, <see cref="string"/>, <see cref="double"/>, <see cref="bool"/>, or null.</summary>
    public static object? Parse(string text)
    {
        int pos = 0;
        object? value = ParseValue(text, ref pos);
        SkipTrivia(text, ref pos);
        if (pos != text.Length)
            throw new FormatException($"Unexpected trailing content at position {pos}.");
        return value;
    }

    private static object? ParseValue(string s, ref int pos)
    {
        SkipTrivia(s, ref pos);
        if (pos >= s.Length)
            throw new FormatException("Unexpected end of input.");

        char c = s[pos];
        switch (c)
        {
            case '{': return ParseObject(s, ref pos);
            case '[': return ParseArray(s, ref pos);
            case '"': return ParseString(s, ref pos);
            case 't': Expect(s, ref pos, "true"); return true;
            case 'f': Expect(s, ref pos, "false"); return false;
            case 'n': Expect(s, ref pos, "null"); return null;
            default: return ParseNumber(s, ref pos);
        }
    }

    private static Dictionary<string, object?> ParseObject(string s, ref int pos)
    {
        var obj = new Dictionary<string, object?>(StringComparer.Ordinal);
        pos++; // consume '{'
        SkipTrivia(s, ref pos);
        if (pos < s.Length && s[pos] == '}') { pos++; return obj; }

        while (true)
        {
            SkipTrivia(s, ref pos);
            if (s[pos] != '"')
                throw new FormatException($"Expected property name at position {pos}.");
            string key = ParseString(s, ref pos);
            SkipTrivia(s, ref pos);
            if (s[pos] != ':')
                throw new FormatException($"Expected ':' at position {pos}.");
            pos++; // consume ':'
            obj[key] = ParseValue(s, ref pos);
            SkipTrivia(s, ref pos);
            char d = s[pos];
            pos++; // consume ',' or '}'
            if (d == ',') { SkipTrivia(s, ref pos); if (s[pos] == '}') { pos++; break; } continue; }
            if (d == '}') break;
            throw new FormatException($"Expected ',' or '}}' at position {pos - 1}.");
        }
        return obj;
    }

    private static List<object?> ParseArray(string s, ref int pos)
    {
        var arr = new List<object?>();
        pos++; // consume '['
        SkipTrivia(s, ref pos);
        if (pos < s.Length && s[pos] == ']') { pos++; return arr; }

        while (true)
        {
            arr.Add(ParseValue(s, ref pos));
            SkipTrivia(s, ref pos);
            char d = s[pos];
            pos++; // consume ',' or ']'
            if (d == ',') { SkipTrivia(s, ref pos); if (s[pos] == ']') { pos++; break; } continue; }
            if (d == ']') break;
            throw new FormatException($"Expected ',' or ']' at position {pos - 1}.");
        }
        return arr;
    }

    private static string ParseString(string s, ref int pos)
    {
        pos++; // consume opening quote
        var sb = new System.Text.StringBuilder();
        while (pos < s.Length)
        {
            char c = s[pos++];
            if (c == '"')
                return sb.ToString();
            if (c == '\\')
            {
                char e = s[pos++];
                switch (e)
                {
                    case '"': sb.Append('"'); break;
                    case '\\': sb.Append('\\'); break;
                    case '/': sb.Append('/'); break;
                    case 'b': sb.Append('\b'); break;
                    case 'f': sb.Append('\f'); break;
                    case 'n': sb.Append('\n'); break;
                    case 'r': sb.Append('\r'); break;
                    case 't': sb.Append('\t'); break;
                    case 'u':
                        sb.Append((char)int.Parse(s.Substring(pos, 4), System.Globalization.NumberStyles.HexNumber,
                            System.Globalization.CultureInfo.InvariantCulture));
                        pos += 4;
                        break;
                    default: throw new FormatException($"Invalid escape '\\{e}' at position {pos - 1}.");
                }
            }
            else
            {
                sb.Append(c);
            }
        }
        throw new FormatException("Unterminated string.");
    }

    private static double ParseNumber(string s, ref int pos)
    {
        int start = pos;
        while (pos < s.Length && (char.IsDigit(s[pos]) || s[pos] is '-' or '+' or '.' or 'e' or 'E'))
            pos++;
        return double.Parse(s.Substring(start, pos - start), System.Globalization.CultureInfo.InvariantCulture);
    }

    private static void Expect(string s, ref int pos, string literal)
    {
        if (pos + literal.Length > s.Length || s.Substring(pos, literal.Length) != literal)
            throw new FormatException($"Expected '{literal}' at position {pos}.");
        pos += literal.Length;
    }

    /// <summary>Skip whitespace plus <c>//</c> line and <c>/* */</c> block comments (parity with the CLI's reader).</summary>
    private static void SkipTrivia(string s, ref int pos)
    {
        while (pos < s.Length)
        {
            char c = s[pos];
            if (char.IsWhiteSpace(c)) { pos++; continue; }
            if (c == '/' && pos + 1 < s.Length)
            {
                if (s[pos + 1] == '/')
                {
                    pos += 2;
                    while (pos < s.Length && s[pos] != '\n') pos++;
                    continue;
                }
                if (s[pos + 1] == '*')
                {
                    pos += 2;
                    while (pos + 1 < s.Length && !(s[pos] == '*' && s[pos + 1] == '/')) pos++;
                    pos += 2;
                    continue;
                }
            }
            break;
        }
    }
}
