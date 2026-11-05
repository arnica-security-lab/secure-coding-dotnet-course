using dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Data;
using dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Domain;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Controllers;

[ApiController]
[Route("products")]
public class ProductsController(ShopDbContext db) : ControllerBase
{
    // Parameterized via LINQ — input can never alter the query structure.
    [HttpGet("search")]
    public async Task<List<Product>> Search(string q) =>
        await db.Products.Where(p => p.Name.Contains(q)).ToListAsync();
}
