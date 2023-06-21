using Example.AuthorizationService.Common.Entities;
using Example.AuthorizationService.Common.Enums;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Example.AuthorizationService.Dal.Contexts;

public class ApplicationDbContext : IdentityDbContext<ApplicationUser, IdentityRole<int>, int>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
        Database.EnsureCreated();
    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        // Customize the ASP.NET Identity model and override the defaults if needed.
        // For example, you can rename the ASP.NET Identity table names and more.
        // Add your customizations after calling base.OnModelCreating(builder);

        builder.Entity<ApplicationUser>().HasData(new[]
        {
            new ApplicationUser
            {
                Id = 1,
                UserName = "yark",
                Gender = Gender.Male,
                BirthDate = new DateTime(2002, 5, 5),
                GivenName = "Givenname",
                FamilyName = "Familyname",
                MiddleName = "Middlename",
                Email = "yark@test.com",
                EmailConfirmed = true,
                PasswordHash = @"AQAAAAEAACcQAAAAEOfMjMmVj+Dqpa4HTSSTJzrexgkXyQ8I72pIRgkCzgPYQa1sO6qcxnSM7jYwK7UGhA==",
            },
        });
    }
}
