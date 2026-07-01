using System;
using System.Security.Principal;

namespace Tether.DesktopUI.Services;

public class ElevationService
{
    public bool IsAdministrator => new WindowsPrincipal(WindowsIdentity.GetCurrent())
        .IsInRole(WindowsBuiltInRole.Administrator);
}