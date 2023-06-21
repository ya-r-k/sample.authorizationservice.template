using System.ComponentModel.DataAnnotations;

namespace Example.AuthorizationService.Web.ViewModels.Account;

public class ExternalLoginConfirmationViewModel
{
    [Required]
    [EmailAddress]
    public string Email { get; set; }
}
