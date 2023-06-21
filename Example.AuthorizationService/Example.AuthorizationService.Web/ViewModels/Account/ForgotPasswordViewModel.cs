using System.ComponentModel.DataAnnotations;

namespace Example.AuthorizationService.Web.ViewModels.Account;

public class ForgotPasswordViewModel
{
    [Required]
    [EmailAddress]
    public string Email { get; set; }
}
