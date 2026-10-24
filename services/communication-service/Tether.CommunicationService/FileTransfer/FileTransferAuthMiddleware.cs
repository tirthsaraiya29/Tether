using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;
using System.Security.Claims;
using System.Net;

namespace Tether.CommunicationService.FileTransfer;

public class FileTransferAuthMiddleware
{
    private readonly RequestDelegate _next;
    private readonly TokenStore _tokenStore;

    public FileTransferAuthMiddleware(RequestDelegate next, TokenStore tokenStore)
    {
        _next = next;
        _tokenStore = tokenStore;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Allow local loopback connections (e.g. from Tether.DesktopUI) to bypass token auth
        if (context.Connection.RemoteIpAddress != null && IPAddress.IsLoopback(context.Connection.RemoteIpAddress))
        {
            var identity = new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, "LocalWpfClient") }, "Loopback");
            context.User = new ClaimsPrincipal(identity);
            await _next(context);
            return;
        }

        if (context.Request.Headers.TryGetValue("Authorization", out var authValues))
        {
            var authHeader = authValues.ToString();
            if (authHeader.StartsWith("Bearer ", System.StringComparison.OrdinalIgnoreCase))
            {
                var token = authHeader.Substring("Bearer ".Length).Trim();
                if (_tokenStore.ValidateToken(token))
                {
                    var identity = new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, "TetherClient") }, "Bearer");
                    context.User = new ClaimsPrincipal(identity);
                    await _next(context);
                    return;
                }
            }
        }

        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        await context.Response.WriteAsync("Unauthorized");
    }
}
