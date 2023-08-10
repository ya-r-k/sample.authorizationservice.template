using Sample.AuthorizationService.Common.Enums;
using HotChocolate.Authorization;

namespace Sample.AuthorizationService.Common.ResponseModels;

public class UserDetails
{
    /// <summary>
    /// Gets or sets the user unique identifier.
    /// </summary>
    public int Id { get; set; }

    /// <summary>
    /// Gets or sets the email address for the user.
    /// </summary>
    public string Email { get; set; }

    /// <summary>
    /// Gets or sets a telephone number for the user.
    /// </summary>
    public string PhoneNumber { get; set; }

    /// <summary>
    /// Gets or sets given name.
    /// </summary>
    public string GivenName { get; set; }

    /// <summary>
    /// Gets or sets middle name.
    /// </summary>
    public string MiddleName { get; set; }

    /// <summary>
    /// Gets or sets family name.
    /// </summary>
    public string FamilyName { get; set; }

    /// <summary>
    /// Gets or sets nickname.
    /// </summary>
    public string Nickname { get; set; }

    /// <summary>
    /// Gets or sets locale.
    /// </summary>
    public string Locale { get; set; }

    /// <summary>
    /// Gets or sets zone info.
    /// </summary>
    public string ZoneInfo { get; set; }

    /// <summary>
    /// Gets or sets background picture path.
    /// </summary>
    public string BackgroundPicturePath { get; set; }

    /// <summary>
    /// Gets or sets picture path.
    /// </summary>
    public string PicturePath { get; set; }

    /// <summary>
    /// Gets or sets gender.
    /// </summary>
    public Gender Gender { get; set; }

    /// <summary>
    /// Gets or sets role.
    /// </summary>
    public Role Role { get; set; }

    /// <summary>
    /// Gets or sets birth date.
    /// </summary>
    public DateTime BirthDate { get; set; }
}
