using Sample.AuthorizationService.Bll.Services;
using Sample.AuthorizationService.Common.RequestModels;
using Sample.AuthorizationService.Common.ResponseModels;

namespace Sample.AuthorizationService.Web.GraphQl;

public class UserQuery
{
    private readonly IUserService userService;

    public UserQuery(IUserService userService)
    {
        this.userService = userService;
    }

    [UseProjection]
    public IQueryable<UserDetails> GetUsers(GetUsersByRequestModel model)
    {
        return userService.GetUsers(model);
    }
}
