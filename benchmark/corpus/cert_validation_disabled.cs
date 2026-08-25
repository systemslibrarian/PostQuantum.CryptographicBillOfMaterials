// EXPECT: CBOM0041
// Intent: an accept-all server certificate callback disables TLS authentication (CWE-295). Should be flagged.
using System.Net.Http;

public class InsecureClient
{
    public HttpClient Make() => new HttpClient(new HttpClientHandler
    {
        ServerCertificateCustomValidationCallback = (_, _, _, _) => true
    });
}
