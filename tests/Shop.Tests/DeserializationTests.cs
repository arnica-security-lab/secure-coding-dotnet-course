using System.Net;
using System.Net.Http;
using System.Text;
using dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Domain;
using Xunit;

namespace dev.kaldiroglu.SecureCoding.Shop.Tests;

public class DeserializationTests
{
    private static StringContent Json(string s) => new(s, Encoding.UTF8, "application/json");
    private static StringContent Xml(string s) => new(s, Encoding.UTF8, "application/xml");

    // Documents the gadget side-effect directly so coverage is retained after TypeNameHandling is disabled.
    [Fact]
    public void ImportGadget_writes_file_when_trigger_set()
    {
        var sentinel = Path.Combine(Path.GetTempPath(), "scc-gadget-direct.txt");
        if (File.Exists(sentinel)) File.Delete(sentinel);

        var gadget = new ImportGadget { Trigger = sentinel };

        Assert.True(File.Exists(sentinel));
        Assert.Equal("pwned-by-deser", File.ReadAllText(sentinel));
        Assert.Equal(sentinel, gadget.Trigger);
        File.Delete(sentinel);
    }

    [Fact]
    public async Task Vulnerable_json_ignores_type_directives()
    {
        var sentinel = Path.Combine(Path.GetTempPath(), "scc-deser-vuln.txt");
        if (File.Exists(sentinel)) File.Delete(sentinel);
        var payload = "{\"$type\":\"dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Domain.ImportGadget, dev.kaldiroglu.SecureCoding.Shop.Vulnerable\",\"Trigger\":\""
                      + sentinel.Replace("\\", "\\\\") + "\"}";

        using var f = new VulnerableFactory();
        var c = f.CreateClient();
        await c.PostAsync("/import/json", Json(payload));

        Assert.False(File.Exists(sentinel));
    }

    [Fact]
    public async Task Vulnerable_json_accepts_known_dto()
    {
        using var f = new VulnerableFactory();
        var c = f.CreateClient();
        var resp = await c.PostAsync("/import/json", Json("{\"Name\":\"ok\"}"));
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Fixed_json_ignores_type_directives()
    {
        var sentinel = Path.Combine(Path.GetTempPath(), "scc-deser-fixed.txt");
        if (File.Exists(sentinel)) File.Delete(sentinel);
        var payload = "{\"$type\":\"dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Domain.ImportGadget, dev.kaldiroglu.SecureCoding.Shop.Vulnerable\",\"Trigger\":\""
                      + sentinel.Replace("\\", "\\\\") + "\"}";

        using var f = new FixedFactory();
        var c = f.CreateClient();
        await c.PostAsync("/import/json", Json(payload));

        Assert.False(File.Exists(sentinel));
    }

    [Fact]
    public async Task Vulnerable_xml_rejects_dtd()
    {
        var secret = Path.Combine(Path.GetTempPath(), "scc-xxe-secret.txt");
        File.WriteAllText(secret, "XXE-SECRET-9999");
        var xml = "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file://" + secret + "\">]><foo>&xxe;</foo>";

        using var f = new VulnerableFactory();
        var c = f.CreateClient();
        var resp = await c.PostAsync("/import/xml", Xml(xml));

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        var body = await resp.Content.ReadAsStringAsync();
        Assert.DoesNotContain("XXE-SECRET-9999", body);
    }

    [Fact]
    public async Task Vulnerable_xml_parses_safe_document()
    {
        using var f = new VulnerableFactory();
        var c = f.CreateClient();
        var resp = await c.PostAsync("/import/xml", Xml("<foo>safe-content</foo>"));
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("safe-content", await resp.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Fixed_xml_rejects_dtd()
    {
        var secret = Path.Combine(Path.GetTempPath(), "scc-xxe-secret.txt");
        File.WriteAllText(secret, "XXE-SECRET-9999");
        var xml = "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file://" + secret + "\">]><foo>&xxe;</foo>";

        using var f = new FixedFactory();
        var c = f.CreateClient();
        var resp = await c.PostAsync("/import/xml", Xml(xml));

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }
}
