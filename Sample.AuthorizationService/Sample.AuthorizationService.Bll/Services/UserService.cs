using Sample.AuthorizationService.Common.RequestModels;
using Sample.AuthorizationService.Common.ResponseModels;
using Sample.AuthorizationService.Dal.Repositories;

namespace Sample.AuthorizationService.Bll.Services;

public class UserService : IUserService
{
    private readonly IUserRepository userRepository;

    public UserService(IUserRepository userRepository)
    {
        this.userRepository = userRepository;
    }

    public IQueryable<UserDetails> GetUsers(GetUsersByRequestModel model)
    {
        return userRepository.GetUsers(model);
    }
}
