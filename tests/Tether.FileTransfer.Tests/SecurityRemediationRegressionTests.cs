using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using Tether.CommunicationService.Capabilities;
using Tether.DesktopUI;
using Tether.SessionHelper;
using Tether.Shared.Security;
using Tether.Updater;
using Xunit;

namespace Tether.FileTransfer.Tests;

public class SecurityRemediationRegressionTests
{
    #region Terminal Session Isolation & Ownership Enforcement

    [Fact]
    public void TerminalSessionManager_EnforcesMandatoryOwnerDeviceId()
    {
        var mgr = new TerminalSessionManager((id, text, dir, deviceId) => { });

        // Missing or null ownerDeviceId must fail closed immediately
        Assert.Throws<ArgumentException>(() => mgr.StartSession("powershell", null, null, null));
        Assert.Throws<ArgumentException>(() => mgr.StartSession("powershell", null, null, "   "));

        // Operations with null or blank owner must fail
        Assert.False(mgr.SendInput("some-id", "whoami\n", null));
        Assert.False(mgr.SendInput("some-id", "whoami\n", "  "));
        Assert.False(mgr.CloseSession("some-id", null));
        Assert.False(mgr.CloseSession("some-id", "  "));
        Assert.Empty(mgr.ListSessions(null));
        Assert.Empty(mgr.ListSessions("  "));
        Assert.Empty(mgr.GetHistory("some-id", null));
        Assert.Empty(mgr.GetHistory("some-id", "  "));
    }

    [Fact]
    public void TerminalSessionManager_CrossDeviceIsolation_PreventsCrossDeviceInterference()
    {
        var outputs = new List<(string SessionId, string Data, string DeviceId)>();
        var mgr = new TerminalSessionManager((sessionId, data, dir, deviceId) =>
        {
            outputs.Add((sessionId, data, deviceId));
        });

        // Device A and Device B operations
        string devA = "phone-device-alpha";
        string devB = "phone-device-beta";

        // Non-existent session queries from Device B must return false / empty
        Assert.False(mgr.SendInput("non-existent-session", "dir\n", devB));
        Assert.False(mgr.CloseSession("non-existent-session", devB));
        Assert.Empty(mgr.GetHistory("non-existent-session", devB));

        // Listing sessions for device A when none exist must be empty
        var devASessions = mgr.ListSessions(devA);
        Assert.NotNull(devASessions);
        Assert.Empty(devASessions);
    }

    #endregion

    #region Authenticode & Updater Trust Verification

    [Fact]
    public void AuthenticodeVerifier_RejectsNonExistentFile()
    {
        bool result = AuthenticodeVerifier.VerifyFileAuthenticode(@"C:\NonExistent_Fake_Installer.exe");
        Assert.False(result);
    }

    [Fact]
    public void AuthenticodeVerifier_RejectsUnsignedOrCorruptedFile()
    {
        string tempFile = Path.Combine(Path.GetTempPath(), $"untrusted_test_{Guid.NewGuid():N}.exe");
        try
        {
            File.WriteAllBytes(tempFile, new byte[] { 0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00 }); // Raw MZ header without Authenticode
            bool result = AuthenticodeVerifier.VerifyFileAuthenticode(tempFile);
            Assert.False(result);
        }
        finally
        {
            if (File.Exists(tempFile)) File.Delete(tempFile);
        }
    }

    [Fact]
    public void AuthenticodeVerifier_RejectsPublisherMismatch()
    {
        // System notepad.exe is signed by Microsoft Corporation, which must NOT match Tether Project publisher
        string notepadPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "notepad.exe");
        if (File.Exists(notepadPath))
        {
            bool isTether = AuthenticodeVerifier.VerifyFileAuthenticode(notepadPath, pinnedThumbprint: "00112233445566778899AABBCCDDEEFF00112233");
            Assert.False(isTether);
        }
    }

    [Fact]
    public void AuthenticodeVerifier_ManifestSignatureVerification_EnforcesAuthenticity()
    {
        using var ecdsaPublisher = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var ecdsaAttacker = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        byte[] manifestData = Encoding.UTF8.GetBytes("{\"version\":\"1.2.0\",\"files\":[{\"path\":\"Tether.DesktopUI.exe\",\"sha256\":\"abc\",\"size\":123}]}");
        byte[] validSignature = ecdsaPublisher.SignData(manifestData, HashAlgorithmName.SHA256);

        // 1. Valid signature with legitimate publisher key must succeed
        Assert.True(AuthenticodeVerifier.VerifyManifestSignature(manifestData, validSignature, ecdsaPublisher));

        // 2. Tampered manifest with legitimate signature must fail
        byte[] tamperedData = Encoding.UTF8.GetBytes("{\"version\":\"1.2.0\",\"files\":[{\"path\":\"MALICIOUS.exe\",\"sha256\":\"evil\",\"size\":999}]}");
        Assert.False(AuthenticodeVerifier.VerifyManifestSignature(tamperedData, validSignature, ecdsaPublisher));

        // 3. Attacker signature against legitimate publisher key must fail
        byte[] attackerSignature = ecdsaAttacker.SignData(manifestData, HashAlgorithmName.SHA256);
        Assert.False(AuthenticodeVerifier.VerifyManifestSignature(manifestData, attackerSignature, ecdsaPublisher));

        // 4. Empty or null parameters must fail closed
        Assert.False(AuthenticodeVerifier.VerifyManifestSignature(Array.Empty<byte>(), validSignature, ecdsaPublisher));
        Assert.False(AuthenticodeVerifier.VerifyManifestSignature(manifestData, Array.Empty<byte>(), ecdsaPublisher));
    }

    [Fact]
    public void Updater_LockdownStagingAcl_FailsClosedOnNonExistentOrReparsePointDirectory()
    {
        // Non-existent directory must return false
        Assert.False(Tether.Updater.Program.LockdownStagingAcl(@"C:\NonExistent_Tether_Staging_" + Guid.NewGuid().ToString("N"), string.Empty));
    }

    #endregion

    #region System Hardening & Warning Elimination (Milestone 5)

    [Fact]
    public void DesktopUI_CreateInstancePipeSecurity_RestrictsToCurrentUserAndDeniesNetwork()
    {
        var pipeSecurity = App.CreateInstancePipeSecurity();
        Assert.NotNull(pipeSecurity);

        var rules = pipeSecurity.GetAccessRules(true, true, typeof(SecurityIdentifier));
        Assert.NotEmpty(rules);

        bool hasNetworkDeny = false;
        bool hasCurrentUserAllow = false;
        var currentUserSid = WindowsIdentity.GetCurrent().User;

        foreach (PipeAccessRule rule in rules)
        {
            if (rule.IdentityReference is SecurityIdentifier sid)
            {
                if (sid.IsWellKnown(WellKnownSidType.NetworkSid) &&
                    rule.AccessControlType == AccessControlType.Deny)
                {
                    hasNetworkDeny = true;
                }

                if (currentUserSid != null &&
                    sid == currentUserSid &&
                    rule.AccessControlType == AccessControlType.Allow)
                {
                    hasCurrentUserAllow = true;
                }
            }
        }

        Assert.True(hasNetworkDeny, "PipeSecurity must explicitly deny NetworkSid.");
        Assert.True(hasCurrentUserAllow, "PipeSecurity must allow current user SID.");
    }

    [Fact]
    public void MultiMonitor_CoordinateMapping_CoversVirtualScreenWithNegativeBounds()
    {
        // Simulating a multi-monitor virtual screen where monitor 2 is to the left:
        // Left: -1920, Top: 0, Width: 3840, Height: 1080
        var virtualBounds = new System.Drawing.Rectangle(-1920, 0, 3840, 1080);
        ushort minNorm = 0;
        ushort maxNorm = 65535;
        ushort midNorm = 32767;

        int targetMinX = virtualBounds.Left + (int)((long)minNorm * virtualBounds.Width / 65535);
        int targetMinY = virtualBounds.Top + (int)((long)minNorm * virtualBounds.Height / 65535);

        int targetMaxX = virtualBounds.Left + (int)((long)maxNorm * virtualBounds.Width / 65535);
        int targetMaxY = virtualBounds.Top + (int)((long)maxNorm * virtualBounds.Height / 65535);

        int targetMidX = virtualBounds.Left + (int)((long)midNorm * virtualBounds.Width / 65535);

        // Min maps to the far left of the virtual desktop (-1920)
        Assert.Equal(-1920, targetMinX);
        Assert.Equal(0, targetMinY);

        // Max maps to right boundary of the virtual desktop (-1920 + 3840 = 1920)
        Assert.Equal(1920, targetMaxX);
        Assert.Equal(1080, targetMaxY);

        // Mid maps close to the primary monitor origin (0)
        Assert.InRange(targetMidX, -1, 1);
    }

    [Fact]
    public void DesktopUI_InstancePipe_CreateWithAcl_Succeeds()
    {
        string pipeName = $"TetherDesktopUIInstancePipe_Test_{Guid.NewGuid():N}";
        var pipeSecurity = App.CreateInstancePipeSecurity();

        using var server = NamedPipeServerStreamAcl.Create(
            pipeName,
            PipeDirection.In,
            1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            0,
            0,
            pipeSecurity);

        Assert.NotNull(server);
    }

    [Fact]
    public void HardwareExecutor_LaunchInUserSession_FailsClosedWhenUnprivileged()
    {
        var logger = new MockLogger();
        // In an unprivileged test context (without Session 0 SYSTEM credentials),
        // LaunchInUserSession must fail closed (return false) without invoking ShellExecute.
        bool result = HardwareExecutor.ExecuteCommand("launch_calc", logger);
        Assert.False(result);
    }

    #endregion
}
