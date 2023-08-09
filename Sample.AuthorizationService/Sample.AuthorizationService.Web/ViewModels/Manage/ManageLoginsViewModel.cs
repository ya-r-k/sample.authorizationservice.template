using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;

namespace Sample.AuthorizationService.Web.ViewModels.Manage;

public class ManageLoginsViewModel
{
    public IList<UserLoginInfo> CurrentLogins { get; set; }

    public IList<AuthenticationScheme> OtherLogins { get; set; }
}
