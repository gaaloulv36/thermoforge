using System.Xml.Linq;
using ThermoForge.Core.Platform;

namespace ThermoForge.Tests;

public class AutoStartTests
{
    private static readonly XNamespace Ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
    private const string Sid = "S-1-5-21-1000-2000-3000-1001";

    private static XDocument Task(string exe = @"C:\Program Files\Forge Studio\ThermoForge\ThermoForge.exe") =>
        XDocument.Parse(AutoStart.TaskXml(exe, Sid));

    private static string Value(XDocument task, string element) => task.Descendants(Ns + element).Single().Value;

    [Fact]
    public void StartsInTheTray_AtThisUsersSignIn_WithAdminRights()
    {
        var task = Task();

        Assert.Equal(Sid, task.Descendants(Ns + "LogonTrigger").Single().Element(Ns + "UserId")!.Value);
        Assert.Equal(Sid, task.Descendants(Ns + "Principal").Single().Element(Ns + "UserId")!.Value);
        Assert.Equal("HighestAvailable", Value(task, "RunLevel"));
        Assert.Equal("InteractiveToken", Value(task, "LogonType"));
        Assert.Equal(AutoStart.TrayArgument, Value(task, "Arguments"));
    }

    [Fact]
    public void KeepsRunning_OnBatteryAndBeyondThreeDays()
    {
        var task = Task();

        Assert.Equal("false", Value(task, "DisallowStartIfOnBatteries"));
        Assert.Equal("false", Value(task, "StopIfGoingOnBatteries"));
        Assert.Equal("PT0S", Value(task, "ExecutionTimeLimit"));
        Assert.Equal("IgnoreNew", Value(task, "MultipleInstancesPolicy"));
    }

    [Fact]
    public void CommandRoundTrips_EvenWithSpecialCharacters()
    {
        const string exe = @"C:\Tools & Co\<Thermo>\ThermoForge.exe";

        Assert.Equal(exe, AutoStart.ParseCommand(AutoStart.TaskXml(exe, Sid)));
    }

    [Theory]
    [InlineData("not xml")]
    [InlineData("<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\" />")]
    public void ParseCommand_ReturnsNullWithoutACommand(string xml) =>
        Assert.Null(AutoStart.ParseCommand(xml));

    [Fact]
    public void ParseCommand_StripsQuotes() =>
        Assert.Equal(@"C:\a b\x.exe", AutoStart.ParseCommand(
            """<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Actions><Exec><Command>"C:\a b\x.exe"</Command></Exec></Actions></Task>"""));
}
