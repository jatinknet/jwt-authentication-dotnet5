using JwtAuthentication.Entities;
using Microsoft.EntityFrameworkCore;

namespace JwtAuthentication.Context
{
    public class ApplicationDbContext :DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {

        }
        public DbSet<User> Users { get; set; }
    }
}
