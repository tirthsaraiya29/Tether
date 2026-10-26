using Microsoft.AspNetCore.Http;
using System.Security.Claims;
using System.Threading.Tasks;

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
        // Require explicit Bearer token authentication for ALL clients (both remote and local loopback)
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
