namespace Sample.AuthorizationService.Common.RequestModels;

public class GetUsersByRequestModel
{
    public IEnumerable<int> UsersIds { get; set; }
}
