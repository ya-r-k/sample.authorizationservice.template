using Sample.AuthorizationService.Common.RequestModels;
using Sample.AuthorizationService.Common.ResponseModels;

namespace Sample.AuthorizationService.Dal.Repositories;

public interface IUserRepository
{
    IQueryable<UserDetails> GetUsers(GetUsersByRequestModel model);
}
