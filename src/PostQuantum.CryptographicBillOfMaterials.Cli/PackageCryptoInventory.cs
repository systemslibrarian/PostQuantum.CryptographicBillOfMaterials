using System.Text.Json;
using System.Text.RegularExpressions;
using PostQuantum.CryptographicBillOfMaterials.Analysis.Detection;
using PostQuantum.CryptographicBillOfMaterials.Model;

namespace PostQuantum.CryptographicBillOfMaterials.Cli;

/// <summary>
/// Dependency-aware crypto inventory from the package manifest. Static source analysis cannot see crypto
/// performed inside third-party packages, so this complements it: it reads <c>project.assets.json</c> (the
/// restored, fully-resolved graph, including transitive packages) — falling back to <c>&lt;PackageReference&gt;</c> —
/// and records known crypto-bearing packages and their versions. This is an inventory signal (it does not
/// claim the crypto is used a particular way), but it makes the third-party blind spot visible to auditors.
/// </summary>
internal static class PackageCryptoInventory
{
    /// <summary>Rule id for manifest-derived dependency inventory (not a Roslyn detector).</summary>
    public const string RuleId = "CBOM0081";

    private sealed record PackageVerdict(
        string Display, QuantumVulnerability Quantum, ClassicalWeakness Classical, string Basis);

    // Known crypto-bearing packages (matched case-insensitively as a prefix). Versions are reported as found.
    private static readonly (string Prefix, PackageVerdict Verdict)[] Known =
    {
        ("BouncyCastle", new("Bouncy Castle crypto provider", QuantumVulnerability.NotVulnerable, ClassicalWeakness.None,
            "General-purpose crypto provider bundling RSA/EC/DSA (Shor-vulnerable) alongside modern primitives; inventory its actual usage.")),
        ("Portable.BouncyCastle", new("Bouncy Castle crypto provider", QuantumVulnerability.NotVulnerable, ClassicalWeakness.None,
            "General-purpose crypto provider bundling RSA/EC/DSA (Shor-vulnerable); inventory its actual usage.")),
        ("Org.BouncyCastle", new("Bouncy Castle crypto provider", QuantumVulnerability.NotVulnerable, ClassicalWeakness.None,
            "General-purpose crypto provider bundling RSA/EC/DSA (Shor-vulnerable); inventory its actual usage.")),
        ("System.IdentityModel.Tokens.Jwt", new("JWT (System.IdentityModel)", QuantumVulnerability.NotVulnerable, ClassicalWeakness.None,
            "JWT library performing RSA/ECDSA/HMAC signing and validation; confirm algorithms and key strength.")),
        ("Microsoft.IdentityModel.Tokens", new("Microsoft.IdentityModel crypto", QuantumVulnerability.NotVulnerable, ClassicalWeakness.None,
            "Token crypto (RSA/ECDSA/HMAC) for JWT/OIDC; confirm algorithms and key strength.")),
        ("Microsoft.IdentityModel.JsonWebTokens", new("JSON Web Tokens (Microsoft.IdentityModel)", QuantumVulnerability.NotVulnerable, ClassicalWeakness.None,
            "JWT crypto (RSA/ECDSA/HMAC); confirm algorithms and key strength.")),
        ("jose-jwt", new("jose-jwt (JOSE)", QuantumVulnerability.NotVulnerable, ClassicalWeakness.None,
            "JOSE library supporting RSA/ECDSA and (mis)configurable alg=none; confirm a fixed, validated algorithm.")),
        ("NSec.Cryptography", new("NSec (libsodium)", QuantumVulnerability.Vulnerable, ClassicalWeakness.None,
            "Wraps libsodium primitives including Ed25519/X25519, which are elliptic-curve and Shor-vulnerable.")),
        ("Sodium.Core", new("libsodium (Sodium.Core)", QuantumVulnerability.Vulnerable, ClassicalWeakness.None,
            "libsodium binding exposing Ed25519/X25519 (elliptic-curve, Shor-vulnerable).")),
        ("libsodium", new("libsodium", QuantumVulnerability.Vulnerable, ClassicalWeakness.None,
            "libsodium exposes Ed25519/X25519 (elliptic-curve, Shor-vulnerable).")),
        ("Microsoft.AspNetCore.DataProtection", new("ASP.NET Core Data Protection", QuantumVulnerability.NotVulnerable, ClassicalWeakness.None,
            "Key-ring data protection using AES + RSA/ECDH for key wrapping; review configured key algorithms.")),
        ("Konscious.Security.Cryptography", new("Konscious (Argon2/Blake2)", QuantumVulnerability.NotVulnerable, ClassicalWeakness.None,
            "Modern password hashing (Argon2) / Blake2; a positive choice — confirm parameters.")),
    };

    public static IReadOnlyList<CryptoFinding> Inventory(string? projectPathOrDir, string baseDirectory, IList<string> diagnostics)
    {
        if (string.IsNullOrEmpty(projectPathOrDir))
            return Array.Empty<CryptoFinding>();

        var packages = ResolvePackages(projectPathOrDir, diagnostics);
        if (packages.Count == 0)
            return Array.Empty<CryptoFinding>();

        string relManifest = ToRelative(projectPathOrDir, baseDirectory);

        var findings = new List<CryptoFinding>();
        foreach ((string id, string version) in packages)
        {
            PackageVerdict? v = Match(id);
            if (v is null)
                continue;

            if (IsPostQuantumPackage(id))
            {
                findings.Add(BuildPositive(id, version, relManifest));
                continue;
            }

            findings.Add(Build(id, version, v, relManifest));
        }
        return findings;
    }

    private static CryptoFinding Build(string id, string version, PackageVerdict v, string manifest)
    {
        var location = new SourceLocation(manifest, 1);
        string display = $"{v.Display} ({id} {version})";
        var recommendation = new Recommendation(
            "Inventory how this dependency uses crypto and track it for PQC migration.",
            new[]
            {
                new RecommendationOption(
                    "Confirm which algorithms/key sizes this package is configured to use; plan migration of any RSA/EC/DSA usage to NIST PQC (FIPS 203/204/205).",
                    v.Basis, null, v.Quantum == QuantumVulnerability.Vulnerable ? QuantumVulnerability.PostQuantum : null),
            });

        return new CryptoFinding
        {
            RuleId = RuleId,
            Title = "Crypto-bearing dependency",
            Category = RuleCategory.CloudKms,
            AssetType = CryptoAssetType.RelatedCryptoMaterial,
            AlgorithmName = display,
            Primitive = "library",
            QuantumVulnerability = v.Quantum,
            QuantumThreat = v.Quantum == QuantumVulnerability.Vulnerable ? QuantumThreat.Shor : QuantumThreat.None,
            ClassicalWeakness = v.Classical,
            UsageContext = UsageContext.Unknown,
            Confidence = DetectionConfidence.Medium,
            DetectionMethod = DetectionMethod.Config,
            RiskLevel = v.Quantum == QuantumVulnerability.Vulnerable ? RiskLevel.Low : RiskLevel.Informational,
            RiskScore = v.Quantum == QuantumVulnerability.Vulnerable ? 20 : 5,
            RiskBasis = v.Basis,
            Recommendation = recommendation,
            Location = location,
            BomRef = BomRef.Create(display, location, RuleId),
        };
    }

    private static CryptoFinding BuildPositive(string id, string version, string manifest)
    {
        var location = new SourceLocation(manifest, 1);
        string display = $"Post-quantum package ({id} {version})";
        return new CryptoFinding
        {
            RuleId = RuleId,
            Title = "Post-quantum dependency",
            Category = RuleCategory.PostQuantum,
            AssetType = CryptoAssetType.RelatedCryptoMaterial,
            AlgorithmName = display,
            Primitive = "library",
            QuantumVulnerability = QuantumVulnerability.PostQuantum,
            QuantumThreat = QuantumThreat.None,
            ClassicalWeakness = ClassicalWeakness.None,
            UsageContext = UsageContext.Unknown,
            Confidence = DetectionConfidence.Medium,
            DetectionMethod = DetectionMethod.Config,
            RiskLevel = RiskLevel.Informational,
            RiskScore = 0,
            RiskBasis = "Dependency advertises post-quantum algorithm support (positive signal); confirm it is actually wired in.",
            Recommendation = Recommendation.None,
            Location = location,
            BomRef = BomRef.Create(display, location, RuleId),
        };
    }

    private static PackageVerdict? Match(string id)
    {
        if (IsPostQuantumPackage(id))
            return new PackageVerdict("Post-quantum package", QuantumVulnerability.PostQuantum, ClassicalWeakness.None, "PQC package.");
        foreach ((string prefix, PackageVerdict verdict) in Known)
            if (id.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return verdict;
        return null;
    }

    private static bool IsPostQuantumPackage(string id) =>
        id.StartsWith("PostQuantum.", StringComparison.OrdinalIgnoreCase)
        || id.StartsWith("Open.PostQuantum", StringComparison.OrdinalIgnoreCase);

    /// <summary>Resolve (id, version) packages from project.assets.json, else from PackageReference items.</summary>
    private static IReadOnlyList<(string Id, string Version)> ResolvePackages(string projectPathOrDir, IList<string> diagnostics)
    {
        try
        {
            string? assets = FindAssetsFile(projectPathOrDir);
            if (assets is not null)
                return ReadAssets(assets);

            string? csproj = File.Exists(projectPathOrDir) && projectPathOrDir.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase)
                ? projectPathOrDir
                : Directory.Exists(projectPathOrDir)
                    ? Directory.EnumerateFiles(projectPathOrDir, "*.csproj", SearchOption.TopDirectoryOnly).FirstOrDefault()
                    : null;
            if (csproj is not null)
                return ReadPackageReferences(csproj);
        }
        catch (Exception ex)
        {
            diagnostics.Add($"package inventory: {ex.Message}");
        }
        return Array.Empty<(string, string)>();
    }

    private static string? FindAssetsFile(string projectPathOrDir)
    {
        string dir = File.Exists(projectPathOrDir) ? Path.GetDirectoryName(projectPathOrDir) ?? "." : projectPathOrDir;
        string candidate = Path.Combine(dir, "obj", "project.assets.json");
        return File.Exists(candidate) ? candidate : null;
    }

    private static IReadOnlyList<(string, string)> ReadAssets(string assetsPath)
    {
        using FileStream fs = File.OpenRead(assetsPath);
        using JsonDocument doc = JsonDocument.Parse(fs);
        var result = new List<(string, string)>();
        if (doc.RootElement.TryGetProperty("libraries", out JsonElement libs)
            && libs.ValueKind == JsonValueKind.Object)
        {
            foreach (JsonProperty lib in libs.EnumerateObject())
            {
                // Keys are "Name/Version"; only type=="package" entries are NuGet packages.
                if (lib.Value.TryGetProperty("type", out JsonElement t) && t.GetString() != "package")
                    continue;
                int slash = lib.Name.LastIndexOf('/');
                if (slash <= 0)
                    continue;
                result.Add((lib.Name[..slash], lib.Name[(slash + 1)..]));
            }
        }
        return result;
    }

    private static readonly Regex PackageRefRegex = new(
        "<PackageReference\\s+[^>]*Include\\s*=\\s*\"(?<id>[^\"]+)\"(?:[^>]*Version\\s*=\\s*\"(?<ver>[^\"]+)\")?",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static IReadOnlyList<(string, string)> ReadPackageReferences(string csprojPath)
    {
        string text = File.ReadAllText(csprojPath);
        var result = new List<(string, string)>();
        foreach (Match m in PackageRefRegex.Matches(text))
            result.Add((m.Groups["id"].Value, m.Groups["ver"].Success ? m.Groups["ver"].Value : "unspecified"));
        return result;
    }

    private static string ToRelative(string path, string baseDirectory)
    {
        if (string.IsNullOrEmpty(path) || string.IsNullOrEmpty(baseDirectory))
            return path;
        try { return Path.GetRelativePath(baseDirectory, path).Replace('\\', '/'); }
        catch { return path; }
    }
}
