// EXPECT: CBOM0050@Low
// Intent: System.Random used for a non-security purpose (a dice roll) should stay LOW-noise — detected as
// inventory but NOT elevated to a security risk. This is the false-positive guard for weak-RNG context.
using System;

public class DiceGame
{
    public int Roll() => new Random().Next(1, 7);
}
