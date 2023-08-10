namespace Sample.AuthorizationService.Common.Helpers;

public static class EnvironmentHelper
{
    public static bool IsApplicationRunningInContainer()
    {
        var isInContainer = Environment.GetEnvironmentVariable("DOTNET_RUNNING_IN_CONTAINER");

        if (bool.TryParse(isInContainer, out bool result))
        {
            return result;
        }

        return false;
    }
}
