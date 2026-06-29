// netstandard2.0 polyfills for language features the shared-source detector engine uses (init-only
// setters and `required` members). The .NET 8/10 builds of the same source get these from the BCL; the
// analyzer targets netstandard2.0, which predates them, so we supply internal definitions here.

namespace System.Runtime.CompilerServices
{
    /// <summary>Enables <c>init</c>-only setters on netstandard2.0.</summary>
    internal static class IsExternalInit { }

    /// <summary>Marks a member as required (C# 11) for netstandard2.0.</summary>
    [AttributeUsage(AttributeTargets.Field | AttributeTargets.Property, AllowMultiple = false, Inherited = false)]
    internal sealed class RequiredMemberAttribute : Attribute { }

    /// <summary>Indicates a compiler feature requirement (used by the <c>required</c> feature).</summary>
    [AttributeUsage(AttributeTargets.All, AllowMultiple = true, Inherited = false)]
    internal sealed class CompilerFeatureRequiredAttribute : Attribute
    {
        public CompilerFeatureRequiredAttribute(string featureName) => FeatureName = featureName;
        public string FeatureName { get; }
        public bool IsOptional { get; init; }
        public const string RefStructs = nameof(RefStructs);
        public const string RequiredMembers = nameof(RequiredMembers);
    }
}

namespace System.Diagnostics.CodeAnalysis
{
    /// <summary>Lets a constructor satisfy <c>required</c> members on netstandard2.0.</summary>
    [AttributeUsage(AttributeTargets.Constructor, AllowMultiple = false, Inherited = false)]
    internal sealed class SetsRequiredMembersAttribute : Attribute { }
}

namespace System.Collections.Generic
{
    /// <summary>
    /// netstandard2.0 lacks <c>CollectionExtensions.GetValueOrDefault</c>, which the portable knowledge-base
    /// loader uses. Defining it here (in <c>System.Collections.Generic</c>, so it is in scope wherever the
    /// shared source uses dictionaries) keeps that source unchanged. The .NET 8/10 builds use the BCL version;
    /// this file is compiled only into the netstandard2.0 analyzer, so there is no ambiguity there.
    /// </summary>
    internal static class CollectionPolyfills
    {
        public static TValue? GetValueOrDefault<TKey, TValue>(this Dictionary<TKey, TValue> dictionary, TKey key)
            where TKey : notnull =>
            dictionary.TryGetValue(key, out TValue value) ? value : default;
    }
}
