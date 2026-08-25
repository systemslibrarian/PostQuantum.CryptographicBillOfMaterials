// EXPECT-CLEAN
// Intent: ordinary business logic with NO cryptography. Words like "key" (a dictionary key) and "token"
// (a parser token) appear deliberately to trap identifier-name-based false positives. Must produce nothing.
using System.Collections.Generic;

public class Inventory
{
    private readonly Dictionary<string, int> _byKey = new();

    public void Add(string key, int count) => _byKey[key] = count;

    public IEnumerable<string> Tokenize(string token) => token.Split(' ');
}
