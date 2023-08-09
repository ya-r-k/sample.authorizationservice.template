using Sample.AuthorizationService.Common.RequestModels;
using Sample.AuthorizationService.Common.ResponseModels;

namespace Sample.AuthorizationService.Bll.Services;

public interface IUserService
{
    IQueryable<UserDetails> GetUsers(GetUsersByRequestModel model);
}
