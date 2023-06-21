using Example.AuthorizationService.Common.Enums;
using Microsoft.AspNetCore.Identity;

namespace Example.AuthorizationService.Common.Entities;

public class ApplicationUser : IdentityUser<int>
{
    public string GivenName { get; set; }

    public string FamilyName { get; set; }

    public string MiddleName { get; set; }

    public string Nickname { get; set; }

    public string Locale { get; set; }

    public string ZoneInfo { get; set; }

    public string BackgroundPicturePath { get; set; }

    public string PicturePath { get; set; }

    public Gender Gender { get; set; }

    public DateTime BirthDate { get; set; }
}
