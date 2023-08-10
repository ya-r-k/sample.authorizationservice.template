using System.Text;

namespace Sample.AuthorizationService.Web.Middlewares.Csp;

public class CspOptions
{
    private static readonly string[] CspNotIncludedDirectives = new string[]
    {
        CspDirectives.ReportDirective,
    };
    private static readonly string[] CspReportOnlyNotIncludedDirectives = new string[]
    {
        CspDirectives.UpgrateInsecureRequestsDirective
    };

    private readonly IDictionary<string, List<string>> directivesValues;

    public string CspHeaderValue { get; private set; }

    public string CspReportOnlyHeaderValue { get; private set; }

    public CspOptions()
    {
        directivesValues = new Dictionary<string, List<string>>();
    }

    public void AddDirective(string directive, params string[] values)
    {
        if (!directivesValues.TryGetValue(directive, out var directiveValues))
        {
            directiveValues = new List<string>();

            directivesValues.Add(directive, directiveValues);
        }

        directiveValues.AddRange(values);
    }

    public void ApplyCspConfiguration()
    {
        CspHeaderValue = ToCspValue(directive => !CspNotIncludedDirectives.Contains(directive));
        CspReportOnlyHeaderValue = ToCspValue(directive => !CspReportOnlyNotIncludedDirectives.Contains(directive));
    }

    private string ToCspValue(Predicate<string> predicate)
    {
        var result = new StringBuilder();

        foreach (var item in directivesValues)
        {
            if (predicate.Invoke(item.Key))
            {
                var directiveValue = item.Value.Count > 0
                ? $"{item.Key} {string.Join(" ", item.Value)};"
                : $"{item.Key};";

                result.Append(directiveValue);
            }
        }

        return result.ToString();
    }
}
