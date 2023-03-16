using System.ComponentModel.DataAnnotations;

namespace AuthorizationServiceExample.Web.ViewModels.Account;

public class ForgotPasswordViewModel
{
    [Required]
    [EmailAddress]
    public string Email { get; set; }
}
