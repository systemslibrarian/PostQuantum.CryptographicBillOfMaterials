using System.Collections.Concurrent;
using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Text;
using PostQuantum.CryptographicBillOfMaterials.Analysis.Detection;
using PostQuantum.CryptographicBillOfMaterials.Analysis.Engine;
using PostQuantum.CryptographicBillOfMaterials.Knowledge;
using PostQuantum.CryptographicBillOfMaterials.Model;
using PostQuantum.CryptographicBillOfMaterials.Rules;

namespace PostQuantum.CryptographicBillOfMaterials.Analyzer;

/// <summary>
/// The in-editor face of dotnet-cbom. Reuses the real detector engine (shared-source compiled) to flag
/// quantum-vulnerable and classically-weak cryptography as diagnostics, so the same rules that produce the
/// CBOM also light up squiggles in any Roslyn host (VS, VS Code C# Dev Kit, Rider, command-line build).
/// </summary>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class CryptoDiagnosticAnalyzer : DiagnosticAnalyzer
{
    private const string HelpRoot =
        "https://github.com/systemslibrarian/PostQuantum.CryptographicBillOfMaterials/blob/main/docs/RULES.md";

    // The knowledge base is loaded once via the System.Text.Json-free portable path, then the real detector
    // set is built over it. Detectors are stateless, so a single shared instance is safe under concurrency.
    private static readonly IReadOnlyList<ICryptoDetector> Detectors =
        DetectorRegistry.CreateDefault(KnowledgeBase.LoadPortable()).Detectors;

    // One descriptor per rule id (detector metadata is 1:1 with a rule id).
    private static readonly ImmutableDictionary<string, DiagnosticDescriptor> DescriptorsById = BuildDescriptors();

    // Syntax-kind -> interested detectors, mirroring the engine's dispatch so each node hits only relevant rules.
    private static readonly ImmutableDictionary<SyntaxKind, ImmutableArray<ICryptoDetector>> DetectorsByKind =
        BuildDispatchTable();

    /// <summary>
    /// Reported when a detector throws. A rule that vanished is "unknown, not clean" — the same posture the
    /// CLI already takes, where ScanEngine records a ScanDiagnostic for the identical failure. Warning, not
    /// Informational: Info does not surface at default `dotnet build` verbosity, which is exactly the blind
    /// spot this closes.
    /// </summary>
    private static readonly DiagnosticDescriptor RuleFailure = new(
        id: "CBOM9999",
        title: "CBOM rule failed to run",
        messageFormat: "Rule {0} did not run on this file: it failed with {1} ({2}), so its results are unknown rather than clean",
        category: "Cryptography.Diagnostics",
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description: "A detector threw; findings for that rule are missing from this compilation.",
        helpLinkUri: HelpRoot);

    /// <inheritdoc />
    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } =
        DescriptorsById.Values.Concat(new[] { RuleFailure }).ToImmutableArray();

    /// <inheritdoc />
    public override void Initialize(AnalysisContext context)
    {
        // Generated code is IN scope, deliberately: crypto genuinely lives in generated sources (gRPC/WCF/
        // OpenAPI clients configuring SslProtocols, EF migrations, source-generated config), and the CLI's
        // ScanEngine walks every tree. Skipping it here made the editor disagree with the CBOM. Both flags
        // are required — Analyze alone runs the detectors but swallows their diagnostics. Noise is silenced
        // per-glob in .editorconfig, e.g. [*.g.cs] dotnet_diagnostic.CBOM0002.severity = none.
        context.ConfigureGeneratedCodeAnalysis(
            GeneratedCodeAnalysisFlags.Analyze | GeneratedCodeAnalysisFlags.ReportDiagnostics);
        context.EnableConcurrentExecution();

        // CompilationStart so the "already reported" set is per-compilation state rather than static mutable
        // state shared across the concurrent compilations EnableConcurrentExecution permits.
        context.RegisterCompilationStartAction(start =>
        {
            var reportedFailures = new ConcurrentDictionary<string, byte>();
            start.RegisterSyntaxNodeAction(ctx => AnalyzeNode(ctx, reportedFailures), DetectorsByKind.Keys.ToArray());
        });
    }

    private static void AnalyzeNode(SyntaxNodeAnalysisContext context, ConcurrentDictionary<string, byte> reportedFailures)
    {
        if (!DetectorsByKind.TryGetValue(context.Node.Kind(), out ImmutableArray<ICryptoDetector> detectors))
            return;

        var detection = new DetectionContext(
            context.Node,
            context.SemanticModel,
            context.Node.SyntaxTree.FilePath,
            finding => ReportFinding(context, finding));

        foreach (ICryptoDetector detector in detectors)
        {
            try
            {
                detector.Inspect(detection);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // Isolate a misbehaving detector — but never silently. A rule that vanished is "unknown, not
                // clean", and in the IDE the absence of a squiggle IS the user's clean signal. Once per rule
                // per compilation: reporting per node would be thousands of identical warnings on a real
                // solution. OperationCanceledException must propagate — Roslyn relies on it for cancellation.
                if (reportedFailures.TryAdd(detector.Metadata.RuleId, 0))
                    context.ReportDiagnostic(Diagnostic.Create(
                        RuleFailure, context.Node.GetLocation(),
                        detector.Metadata.RuleId, ex.GetType().Name, ex.Message));
            }
        }
    }

    private static void ReportFinding(SyntaxNodeAnalysisContext context, CryptoFinding finding)
    {
        if (!DescriptorsById.TryGetValue(finding.RuleId, out DiagnosticDescriptor? descriptor) || descriptor is null)
            return;

        Location location = ResolveLocation(context.Node.SyntaxTree, finding.Location, context.Node);
        string message = $"{finding.AlgorithmName}: {finding.Title} ({finding.RiskLevel} risk). {finding.RiskBasis}";

        // Severity is per-finding, not per-rule: one rule (e.g. CBOM0010 "Hash algorithm usage") legitimately
        // produces a High finding for MD5 and an Informational one for SHA-384. Use the risk the engine
        // actually computed, so weak crypto surfaces as a warning while clean usage stays a quiet hint.
        DiagnosticSeverity severity = ToSeverity(finding.RiskLevel);
        context.ReportDiagnostic(Diagnostic.Create(
            id: descriptor.Id,
            category: descriptor.Category,
            message: message,
            severity: severity,
            defaultSeverity: descriptor.DefaultSeverity,
            isEnabledByDefault: true,
            warningLevel: severity == DiagnosticSeverity.Error ? 0 : 1,
            title: descriptor.Title.ToString(),
            description: descriptor.Description.ToString(),
            helpLink: descriptor.HelpLinkUri,
            location: location));
    }

    /// <summary>
    /// Map the finding's 1-based file location back to a precise Roslyn token span for the squiggle, falling
    /// back to the analyzed node when the recorded position can't be resolved.
    /// </summary>
    private static Location ResolveLocation(SyntaxTree tree, SourceLocation source, SyntaxNode fallback)
    {
        try
        {
            SourceText text = tree.GetText();
            if (source.Line < 1 || source.Line > text.Lines.Count)
                return fallback.GetLocation();

            TextLine line = text.Lines[source.Line - 1];
            int column = source.Column.HasValue && source.Column.Value > 0 ? source.Column.Value - 1 : 0;
            int position = Math.Min(line.Start + column, line.End);
            SyntaxToken token = tree.GetRoot().FindToken(position);
            // Only trust the token if the recorded position actually falls inside it; otherwise use the node.
            return token.Span.Contains(position) ? token.GetLocation() : fallback.GetLocation();
        }
        catch
        {
            return fallback.GetLocation();
        }
    }

    private static ImmutableDictionary<string, DiagnosticDescriptor> BuildDescriptors()
    {
        var builder = ImmutableDictionary.CreateBuilder<string, DiagnosticDescriptor>();
        foreach (ICryptoDetector detector in Detectors)
        {
            DetectorMetadata meta = detector.Metadata;
            if (builder.ContainsKey(meta.RuleId))
                continue;

            builder[meta.RuleId] = new DiagnosticDescriptor(
                id: meta.RuleId,
                title: meta.Title,
                messageFormat: "{0}",
                category: $"Cryptography.{meta.Category}",
                defaultSeverity: ToSeverity(meta.DefaultSeverity),
                isEnabledByDefault: true,
                description: meta.Basis,
                helpLinkUri: meta.DocumentationUrl ?? HelpRoot);
        }
        return builder.ToImmutable();
    }

    private static ImmutableDictionary<SyntaxKind, ImmutableArray<ICryptoDetector>> BuildDispatchTable()
    {
        var byKind = new Dictionary<SyntaxKind, List<ICryptoDetector>>();
        foreach (ICryptoDetector detector in Detectors)
        {
            foreach (SyntaxKind kind in detector.SyntaxKinds)
            {
                if (!byKind.TryGetValue(kind, out List<ICryptoDetector>? list))
                    byKind[kind] = list = new List<ICryptoDetector>();
                list.Add(detector);
            }
        }

        var builder = ImmutableDictionary.CreateBuilder<SyntaxKind, ImmutableArray<ICryptoDetector>>();
        foreach (KeyValuePair<SyntaxKind, List<ICryptoDetector>> entry in byKind)
            builder[entry.Key] = entry.Value.ToImmutableArray();
        return builder.ToImmutable();
    }

    /// <summary>Map a CBOM risk level to an editor diagnostic severity. Users can re-tune any rule via .editorconfig.</summary>
    private static DiagnosticSeverity ToSeverity(RiskLevel level) => level switch
    {
        RiskLevel.Critical => DiagnosticSeverity.Warning,
        RiskLevel.High => DiagnosticSeverity.Warning,
        RiskLevel.Medium => DiagnosticSeverity.Warning,
        RiskLevel.Low => DiagnosticSeverity.Info,
        _ => DiagnosticSeverity.Info,
    };
}
