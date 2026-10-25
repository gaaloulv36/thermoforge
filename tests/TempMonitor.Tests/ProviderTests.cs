using TempMonitor.Core.Providers;

namespace TempMonitor.Tests;

public class LibreHardwareSensorProviderTests
{
    [Theory]
    [InlineData("SK Hynix - HMCG78AEBSA095N (#2)", "SK Hynix - HMCG78AEBSA095N (#2)")]
    [InlineData("SK Hynix - HM\u0001\u0002CG78�\u0000 (#0)", "SK Hynix - HMCG78 (#0)")]
    [InlineData("  Intel(R)\tIris(R)   Xe  ", "Intel(R) Iris(R) Xe")]
    public void CleanName_StripsNonPrintableCharacters(string raw, string expected) =>
        Assert.Equal(expected, LibreHardwareSensorProvider.CleanName(raw));
}
