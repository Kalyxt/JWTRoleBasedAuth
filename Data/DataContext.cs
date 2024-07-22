using Microsoft.EntityFrameworkCore;
using JWTRoleBasedAuth.Data.Models.Logs;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

namespace JWTRoleBasedAuth.Data
{
    public class DataContext : IdentityDbContext<Models.Users.UserDataModel,
                                                 Models.Users.RoleDataModel,
                                                 long>
    {

        /// <summary>
        /// Database name.
        /// </summary>
        public const string DATABASE_NAME = "jwtrolebasedauth";

        public DataContext(DbContextOptions<DataContext> options) : base(options)
        {
            try
            {
                this.Database.EnsureCreated();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }

        public DbSet<LogDataModel> SysLogs { get; set; }

    }
}
