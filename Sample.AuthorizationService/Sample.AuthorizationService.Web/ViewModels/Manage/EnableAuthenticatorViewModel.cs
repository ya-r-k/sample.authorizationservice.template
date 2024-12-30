using System.ComponentModel.DataAnnotations;

public class EnableAuthenticatorViewModel
{
    [Required]
    [StringLength(7, ErrorMessage = "Код должен содержать 6 цифр", MinimumLength = 6)]
    [DataType(DataType.Text)]
    [Display(Name = "Код подтверждения")]
    public string Code { get; set; }

    public string SharedKey { get; set; }

    public string AuthenticatorUri { get; set; }
}

public class ShowRecoveryCodesViewModel
{
    public IEnumerable<string> RecoveryCodes { get; set; }
} 