// EXPECT: CBOM0021
// Intent: disabling signed-token enforcement accepts forged JWTs (RFC 8725). The detector matches the
// TokenValidationParameters type by name; a local stub stands in for the real package so the corpus stays
// SDK-only and reproducible.
public class TokenValidationParameters
{
    public bool RequireSignedTokens { get; set; }
    public bool ValidateIssuerSigningKey { get; set; }
}

public class JwtConfig
{
    public TokenValidationParameters Make() =>
        new TokenValidationParameters { RequireSignedTokens = false };
}
