using System.Security.Claims;

namespace Sample.AuthorizationService.Bll.Services;

/// <summary>
/// 
/// </summary>
public interface IClaimDestinationResolver
{
    /// <summary>
    /// 
    /// </summary>
    /// <param name="claim"></param>
    /// <returns></returns>
    IEnumerable<string> GetDestinations(Claim claim);
}
