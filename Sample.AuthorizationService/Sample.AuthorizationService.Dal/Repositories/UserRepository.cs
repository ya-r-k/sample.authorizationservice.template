using Sample.AuthorizationService.Common.Enums;
using Sample.AuthorizationService.Common.RequestModels;
using Sample.AuthorizationService.Common.ResponseModels;
using Sample.AuthorizationService.Dal.Contexts;
using Microsoft.EntityFrameworkCore;

namespace Sample.AuthorizationService.Dal.Repositories;

public class UserRepository : IUserRepository
{
    private readonly IDbContextFactory<ApplicationDbContext> contextFactory;

    public UserRepository(IDbContextFactory<ApplicationDbContext> contextFactory)
    {
        this.contextFactory = contextFactory;
    }

    public IQueryable<UserDetails> GetUsers(GetUsersByRequestModel model)
    {
        var dbContext = contextFactory.CreateDbContext();

        return dbContext.Users.Where(user => model.UsersIds.Contains(user.Id))
            .Select(user => new UserDetails
            {
                Id = user.Id,
                GivenName = user.GivenName,
                MiddleName = user.MiddleName,
                FamilyName = user.FamilyName,
                Nickname = user.Nickname,
                PicturePath = user.PicturePath,
                BackgroundPicturePath = user.BackgroundPicturePath,
                PhoneNumber = user.PhoneNumber,
                Email = user.Email,
                BirthDate = user.BirthDate,
                Gender = user.Gender,
                Role = (Role)dbContext.UserRoles.FirstOrDefault(item => item.UserId == user.Id).RoleId,
                Locale = user.Locale,
                ZoneInfo = user.ZoneInfo,
            });
    }
}
