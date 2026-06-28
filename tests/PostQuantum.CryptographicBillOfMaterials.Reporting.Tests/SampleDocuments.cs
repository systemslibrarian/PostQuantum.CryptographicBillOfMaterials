using System;
using System.Collections.Generic;
using PostQuantum.CryptographicBillOfMaterials.Model;

namespace PostQuantum.CryptographicBillOfMaterials.Reporting.Tests;

/// <summary>Builds representative <see cref="CbomDocument"/> instances for renderer tests.</summary>
internal static class SampleDocuments
{
    public static CbomDocument Create()
    {
        var rsa = new CryptoFinding
        {
            RuleId = "CBOM0007",
            Title = "RSA key exchange is quantum-vulnerable",
            Category = RuleCategory.KeyExchange,
            AssetType = CryptoAssetType.Algorithm,
            AlgorithmName = "RSA",
            Primitive = "pke",
            KeySizeBits = 2048,
            ClassicalSecurityLevel = 112,
            NistQuantumSecurityLevel = 0,
            Oid = "1.2.840.113549.1.1.1",
            QuantumVulnerability = QuantumVulnerability.Vulnerable,
            QuantumThreat = QuantumThreat.Shor,
            ClassicalWeakness = ClassicalWeakness.None,
            UsageContext = UsageContext.KeyExchange,
            Confidence = DetectionConfidence.High,
            DetectionMethod = DetectionMethod.Symbol,
            RiskLevel = RiskLevel.High,
            RiskScore = 80,
            RiskBasis = "NIST SP 800-208: RSA is broken by Shor's algorithm.",
            Recommendation = new Recommendation(
                "Migrate to ML-KEM (hybrid during transition).",
                new List<RecommendationOption>
                {
                    new("Adopt ML-KEM-768", "FIPS 203", "Larger keys", QuantumVulnerability.PostQuantum),
                }),
            Location = new SourceLocation("src/Auth/KeyExchange.cs", 42),
            BomRef = "rsa-keyexchange-42",
        };

        var md5 = new CryptoFinding
        {
            RuleId = "CBOM0002",
            Title = "MD5 is cryptographically broken",
            Category = RuleCategory.Hashing,
            AssetType = CryptoAssetType.Algorithm,
            AlgorithmName = "MD5",
            Primitive = "hash",
            QuantumVulnerability = QuantumVulnerability.NotVulnerable,
            QuantumThreat = QuantumThreat.None,
            ClassicalWeakness = ClassicalWeakness.Broken,
            UsageContext = UsageContext.Hashing,
            Confidence = DetectionConfidence.Confirmed,
            DetectionMethod = DetectionMethod.Symbol,
            RiskLevel = RiskLevel.High,
            RiskScore = 75,
            RiskBasis = "MD5 collisions are practical (CVE-2004-2761).",
            Recommendation = new Recommendation(
                "Replace MD5 with SHA-256.",
                new List<RecommendationOption>
                {
                    new("Use SHA-256", "FIPS 180-4"),
                }),
            Location = new SourceLocation("src/Hashing/Legacy.cs", 17),
        };

        var aes = new CryptoFinding
        {
            RuleId = "CBOM0010",
            Title = "AES-256 in use",
            Category = RuleCategory.SymmetricEncryption,
            AssetType = CryptoAssetType.Algorithm,
            AlgorithmName = "AES-256-GCM",
            Primitive = "ae",
            KeySizeBits = 256,
            Mode = "GCM",
            ClassicalSecurityLevel = 256,
            NistQuantumSecurityLevel = 5,
            QuantumVulnerability = QuantumVulnerability.NotVulnerable,
            QuantumThreat = QuantumThreat.None,
            ClassicalWeakness = ClassicalWeakness.None,
            UsageContext = UsageContext.AtRest,
            Confidence = DetectionConfidence.High,
            DetectionMethod = DetectionMethod.Symbol,
            RiskLevel = RiskLevel.Informational,
            RiskScore = 5,
            RiskBasis = "AES-256 is quantum-resistant per NIST.",
            Recommendation = Recommendation.None,
            Location = new SourceLocation("src/Storage/Encryptor.cs", 88),
        };

        var hardcodedKey = new CryptoFinding
        {
            RuleId = "CBOM0020",
            Title = "Hardcoded symmetric key",
            Category = RuleCategory.HardcodedSecret,
            AssetType = CryptoAssetType.RelatedCryptoMaterial,
            AlgorithmName = "Hardcoded key material",
            QuantumVulnerability = QuantumVulnerability.NotVulnerable,
            QuantumThreat = QuantumThreat.None,
            ClassicalWeakness = ClassicalWeakness.Broken,
            UsageContext = UsageContext.AtRest,
            Confidence = DetectionConfidence.Confirmed,
            DetectionMethod = DetectionMethod.Constant,
            RiskLevel = RiskLevel.Critical,
            RiskScore = 95,
            RiskBasis = "Hardcoded secrets are recoverable from binaries (CWE-798).",
            Recommendation = new Recommendation(
                "Move secret to a secure store.",
                new List<RecommendationOption>
                {
                    new("Use a KMS / secret manager", "OWASP ASVS"),
                }),
            Location = new SourceLocation("src/Config/Secrets.cs", 5),
            BomRef = "hardcoded-secret-5",
        };

        var analyzed = new ProjectInventory
        {
            Name = "MyApp.Core",
            FilePath = "src/MyApp.Core/MyApp.Core.csproj",
            Analyzed = true,
            Findings = new[] { rsa, md5, aes, hardcodedKey },
            ReadinessScore = 35,
            ReadinessTrivial = false,
        };

        var failed = new ProjectInventory
        {
            Name = "MyApp.Legacy",
            FilePath = "src/MyApp.Legacy/MyApp.Legacy.csproj",
            Analyzed = false,
            Findings = Array.Empty<CryptoFinding>(),
            ReadinessScore = 0,
            ReadinessTrivial = false,
        };

        return new CbomDocument
        {
            Metadata = new ScanMetadata
            {
                ToolName = "dotnet-cbom",
                ToolVersion = "1.2.3",
                ProfileVersion = "1.0",
                CycloneDxSpecVersion = "1.6",
                Timestamp = new DateTimeOffset(2026, 6, 28, 12, 0, 0, TimeSpan.Zero),
                SolutionName = "MyApp",
                TargetFrameworks = new[] { "net8.0", "net10.0" },
                ProjectsAnalyzed = 1,
                ProjectsFailed = 1,
            },
            Projects = new[] { analyzed, failed },
            SolutionReadinessScore = 35,
        };
    }
}
