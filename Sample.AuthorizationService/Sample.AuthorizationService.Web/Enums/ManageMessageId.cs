namespace Sample.AuthorizationService.Web.Enums;

/// <summary>
/// Manage message ids.
/// </summary>
public enum ManageMessageId
{
    AddPhoneSuccess = 1,
    AddLoginSuccess = 2,
    ChangePasswordSuccess = 4,
    SetTwoFactorSuccess = 8,
    SetPasswordSuccess = 16,
    RemoveLoginSuccess = 32,
    RemovePhoneSuccess = 64,
    Error = 128,
}
