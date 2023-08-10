using System.ComponentModel.DataAnnotations;

namespace Sample.AuthorizationService.Web.ViewModels.Account;

public class ForgotPasswordViewModel
{
    [Required]
    [EmailAddress]
    public string Email { get; set; }
}
