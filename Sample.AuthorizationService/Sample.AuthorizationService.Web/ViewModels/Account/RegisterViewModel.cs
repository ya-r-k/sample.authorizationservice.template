using Sample.AuthorizationService.Common.Enums;
using System.ComponentModel.DataAnnotations;

namespace Sample.AuthorizationService.Web.ViewModels.Account;

public class RegisterViewModel
{
    [Required]
    [Display(Name = "Given name")]
    public string GivenName { get; set; }

    [Required]
    [Display(Name = "Family name")]
    public string FamilyName { get; set; }

    [Display(Name = "Middle name")]
    public string MiddleName { get; set; }

    [Required]
    public string Nickname { get; set; }

    [EnumDataType(typeof(Gender))]
    public Gender Gender { get; set; }

    [Display(Name = "Birth date")]
    public DateTime BirthDate { get; set; }

    [Display(Name = "Your country")]
    public string Locale { get; set; }

    [Required]
    [EmailAddress]
    public string Email { get; set; }

    [Phone]
    [Display(Name = "Phone number")]
    public string PhoneNumber { get; set; }

    [Required]
    [StringLength(100, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 6)]
    [DataType(DataType.Password)]
    [Display(Name = "Password")]
    public string Password { get; set; }

    [Required]
    [DataType(DataType.Password)]
    [Display(Name = "Confirm password")]
    [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
    public string ConfirmPassword { get; set; }
}
