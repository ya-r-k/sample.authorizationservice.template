namespace Example.AuthorizationService.Bll.Services;

public interface IEmailSender
{
    Task SendEmailAsync(string email, string subject, string message);
}
