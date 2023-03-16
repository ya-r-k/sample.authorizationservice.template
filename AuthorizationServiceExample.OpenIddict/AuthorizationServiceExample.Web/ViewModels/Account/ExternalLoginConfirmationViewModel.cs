using System.ComponentModel.DataAnnotations;

namespace AuthorizationServiceExample.Web.ViewModels.Account;

public class ExternalLoginConfirmationViewModel
{
    [Required]
    [EmailAddress]
    public string Email { get; set; }
}
