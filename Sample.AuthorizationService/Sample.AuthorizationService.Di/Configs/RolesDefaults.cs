using Sample.AuthorizationService.Common.Enums;

namespace Sample.AuthorizationService.Common.Defaults;

internal static class RolesDefaults
{
    internal static IEnumerable<string> Roles = Enum.GetValues(typeof(Role))
            .Cast<Role>()
            .Select(role => role.ToString());
}
