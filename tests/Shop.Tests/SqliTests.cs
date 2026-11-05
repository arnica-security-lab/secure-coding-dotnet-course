using System.Net.Http.Json;
using Xunit;

namespace dev.kaldiroglu.SecureCoding.Shop.Tests;

public class SqliTests
{
    // Tautology injection that, if interpreted, returns ALL products regardless of the filter.
    // Treated as a literal search string after parameterization; matches nothing.
    private const string Payload = "zzz%' OR 1=1 --";

    [Fact]
    public async Task Vulnerable_search_is_not_injectable()
    {
        using var factory = new VulnerableFactory();
        var client = factory.CreateClient();
        var results = await client.GetFromJsonAsync<List<ProductDto>>($"/products/search?q={Uri.EscapeDataString(Payload)}");
        Assert.NotNull(results);
        Assert.Empty(results!);             // payload treated as a literal; matches nothing
    }

    [Fact]
    public async Task Vulnerable_search_returns_matching_products()
    {
        using var factory = new VulnerableFactory();
        var client = factory.CreateClient();
        var results = await client.GetFromJsonAsync<List<ProductDto>>("/products/search?q=Laptop");
        Assert.NotNull(results);
        Assert.NotEmpty(results!);
        Assert.All(results!, p => Assert.Contains("Laptop", p.Name, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Fixed_search_is_not_injectable()
    {
        using var factory = new FixedFactory();
        var client = factory.CreateClient();
        var results = await client.GetFromJsonAsync<List<ProductDto>>($"/products/search?q={Uri.EscapeDataString(Payload)}");
        Assert.NotNull(results);
        Assert.Empty(results!);             // payload treated as a literal; matches nothing
    }

    public record ProductDto(int Id, string Name, string Description, decimal Price);
}
