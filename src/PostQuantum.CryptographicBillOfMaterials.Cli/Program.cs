using PostQuantum.CryptographicBillOfMaterials.Model;

namespace PostQuantum.CryptographicBillOfMaterials.Cli;

/// <summary>Entry point and command dispatch for <c>dotnet-cbom</c>.</summary>
internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        try
        {
            if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
            {
                PrintHelp();
                return 0;
            }

            return args[0] switch
            {
                "scan" => await ScanCommand(args[1..]),
                "diff" => DiffCommand(args[1..]),
                "version" or "--version" => PrintVersion(),
                _ => Unknown(args[0]),
            };
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 4;
        }
    }

    private static async Task<int> ScanCommand(string[] args)
    {
        var options = new ScanOptions();

        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i];
            switch (a)
            {
                case "-o":
                case "--output":
                    options.OutputDir = Next(args, ref i);
                    break;
                case "-f":
                case "--format":
                    options.Formats = Next(args, ref i)
                        .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                        .ToList();
                    options.FormatsSet = true;
                    break;
                case "--fail-on":
                    options.FailOn = Levels.ParseFailOn(Next(args, ref i));
                    options.FailOnSet = true;
                    break;
                case "--config":
                    options.ConfigPath = Next(args, ref i);
                    break;
                case "--baseline":
                    options.BaselinePath = Next(args, ref i);
                    break;
                case "--allow-partial":
                    options.AllowPartial = true;
                    break;
                case "-q":
                case "--quiet":
                    options.Quiet = true;
                    break;
                case "-h":
                case "--help":
                    PrintScanHelp();
                    return 0;
                default:
                    if (a.StartsWith('-'))
                    {
                        Console.Error.WriteLine($"Unknown option '{a}'.");
                        return 3;
                    }
                    options.Target = a;
                    break;
            }
        }

        return await ScanRunner.RunAsync(options);
    }

    private static int DiffCommand(string[] args)
    {
        string? baseline = null;
        string? current = null;
        string? output = null;

        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i];
            switch (a)
            {
                case "-o":
                case "--output":
                    output = Next(args, ref i);
                    break;
                case "-h":
                case "--help":
                    Console.WriteLine("usage: dotnet-cbom diff <baseline.cbom.json> <current.cbom.json> [-o out.md]");
                    return 0;
                default:
                    if (baseline is null) baseline = a;
                    else current = a;
                    break;
            }
        }

        if (baseline is null || current is null)
        {
            Console.Error.WriteLine("usage: dotnet-cbom diff <baseline.cbom.json> <current.cbom.json> [-o out.md]");
            return 3;
        }

        using FileStream baselineStream = File.OpenRead(baseline);
        Model.CbomDocument baselineDoc = Reporting.CbomReader.Read(baselineStream);
        using FileStream currentStream = File.OpenRead(current);
        Model.CbomDocument currentDoc = Reporting.CbomReader.Read(currentStream);

        Diff.CbomDiff diff = Diff.DiffEngine.Compare(baselineDoc, currentDoc);

        if (output is not null)
        {
            using FileStream outputStream = File.Create(output);
            Reporting.DiffReporter.Render(diff, outputStream);
            Console.WriteLine($"Wrote {output}");
        }
        else
        {
            using Stream stdout = Console.OpenStandardOutput();
            Reporting.DiffReporter.Render(diff, stdout);
        }

        // Exit 1 on regression so the diff can gate CI.
        return diff.NoRegressions ? 0 : 1;
    }

    private static string Next(string[] args, ref int i)
    {
        if (i + 1 >= args.Length)
            throw new ArgumentException($"Missing value for '{args[i]}'.");
        return args[++i];
    }

    private static int PrintVersion()
    {
        Console.WriteLine(
            $"{ToolInfo.Name} {ToolInfo.Version} (CycloneDX {ToolInfo.CycloneDxSpecVersion}, profile {ToolInfo.ProfileVersion})");
        return 0;
    }

    private static int Unknown(string command)
    {
        Console.Error.WriteLine($"Unknown command '{command}'.");
        PrintHelp();
        return 3;
    }

    private static void PrintHelp()
    {
        Console.WriteLine(
            """
            dotnet-cbom — generate a Cryptographic Bill of Materials for .NET code.

            USAGE
              dotnet-cbom <command> [options]

            COMMANDS
              scan <target>          Analyze a .sln/.csproj/directory and emit a CBOM.
              diff <base> <current>  Compare two CBOMs (progress / regression).
              version                Show tool, profile, and CycloneDX versions.

            Run 'dotnet-cbom scan --help' for scan options.
            """);
    }

    private static void PrintScanHelp()
    {
        Console.WriteLine(
            """
            dotnet-cbom scan — generate a Cryptographic Bill of Materials.

            USAGE
              dotnet-cbom scan <target> [options]

            ARGUMENTS
              <target>   Path to a .sln/.slnx/.csproj, directory, or .cs file. Default: current directory.

            OPTIONS
              -o, --output <dir>     Output directory (default: cbom-out)
              -f, --format <list>    Comma-separated: cyclonedx,sarif,markdown,html,summary (default: cyclonedx,summary)
                  --fail-on <level>  Min level that sets exit 1: critical|high|medium|low|none (default: high)
                  --baseline <file>  Prior CBOM to diff against (writes cbom.diff.md)
                  --config <file>    Path to cbom.config.json (else auto-discovered near target)
                  --allow-partial    Do not return exit 2 when some projects fail to load
              -q, --quiet            Suppress the console summary
              -h, --help             Show this help

            EXIT CODES
              0  ok / below threshold   1  findings at or above --fail-on
              2  partial analysis       3  usage error            4  internal error

            EXAMPLES
              dotnet-cbom scan .\MyApp.sln
              dotnet-cbom scan .\src --format cyclonedx,sarif --fail-on critical
            """);
    }
}
