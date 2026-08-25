// EXPECT: CBOM0040
// Intent: pinning SSL 3.0 is a deprecated, broken protocol version. Should be flagged.
using System.Net.Http;
using System.Security.Authentication;

public class TlsConfig
{
    public HttpClientHandler Make() => new HttpClientHandler { SslProtocols = SslProtocols.Ssl3 };
}
