using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Tether.CommunicationService.FileTransfer;
using Xunit;

namespace Tether.Tests;

public class TETH_SEC_004_BoundedPayloadTests
{
    [Fact]
    public async Task ReadBoundedJsonBodyAsync_SmallValidPayload_ReturnsSuccess()
    {
        var context = new DefaultHttpContext();
        string json = "{\"path\": \"C:\\\\Users\\\\Test\"}";
        byte[] bytes = Encoding.UTF8.GetBytes(json);
        context.Request.Body = new MemoryStream(bytes);
        context.Request.ContentLength = bytes.Length;

        var (success, content, errorResult) = await FileTransferServer.ReadBoundedJsonBodyAsync(context, 1024);

        Assert.True(success);
        Assert.Equal(json, content);
        Assert.Null(errorResult);
    }

    [Fact]
    public async Task ReadBoundedJsonBodyAsync_ContentLengthExceedingLimit_Returns413()
    {
        var context = new DefaultHttpContext();
        byte[] bytes = new byte[70 * 1024]; // 70 KB
        context.Request.Body = new MemoryStream(bytes);
        context.Request.ContentLength = bytes.Length;

        var (success, content, errorResult) = await FileTransferServer.ReadBoundedJsonBodyAsync(context, 64 * 1024);

        Assert.False(success);
        Assert.Null(content);
        Assert.NotNull(errorResult);
    }

    [Fact]
    public async Task ReadBoundedJsonBodyAsync_StreamingBodyExceedingLimit_Returns413()
    {
        var context = new DefaultHttpContext();
        byte[] bytes = new byte[70 * 1024]; // 70 KB
        context.Request.Body = new MemoryStream(bytes);
        context.Request.ContentLength = null; // No Content-Length specified (chunked/streaming)

        var (success, content, errorResult) = await FileTransferServer.ReadBoundedJsonBodyAsync(context, 64 * 1024);

        Assert.False(success);
        Assert.Null(content);
        Assert.NotNull(errorResult);
    }
}
