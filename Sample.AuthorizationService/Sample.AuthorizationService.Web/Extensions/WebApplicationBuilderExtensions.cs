using Microsoft.AspNetCore.Hosting;
using System.Security.Cryptography.X509Certificates;

namespace Sample.AuthorizationService.Web.Extensions;

internal static class WebApplicationBuilderExtensions
{
    internal static void AddKestrel(this IWebHostBuilder builder, IConfiguration configuration)
    {
        builder.ConfigureKestrel((context, serverOptions) =>
        {
            serverOptions.ListenAnyIP(443, listenOptions =>
            {
                listenOptions.UseHttps(httpsOptions =>
                {
                    var appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

                    var certs = Environment.OSVersion.Platform switch
                    {
                        PlatformID.Unix => new Dictionary<string, X509Certificate2>(StringComparer.OrdinalIgnoreCase)
                            {
                                ["localhost"] = new X509Certificate2(configuration["Kestrel:Certificates:LinuxLocal:Path"], configuration["Kestrel:Certificates:LinuxLocal:Password"]),
                                ["sample-authorizationservice"] = new X509Certificate2(configuration["Kestrel:Certificates:LinuxRemote:Path"], configuration["Kestrel:Certificates:LinuxRemote:Password"]),
                            },
                        PlatformID.Win32NT => new Dictionary<string, X509Certificate2>(StringComparer.OrdinalIgnoreCase)
                            {
                                ["localhost"] = new X509Certificate2(System.IO.Path.Combine(appDataPath, configuration["Kestrel:Certificates:WindowsLocal:Path"]), configuration["Kestrel:Certificates:WindowsLocal:Password"]),
                                ["sample-authorizationservice"] = new X509Certificate2(System.IO.Path.Combine(appDataPath, configuration["Kestrel:Certificates:WindowsRemote:Path"]), configuration["Kestrel:Certificates:WindowsRemote:Password"]),
                            },
                        _ => throw new NotImplementedException(),
                    };

                    httpsOptions.ServerCertificateSelector = (connectionContext, name) =>
                    {
                        if (name is not null && certs.TryGetValue(name, out var cert))
                        {
                            return cert;
                        }

                        return certs["localhost"];
                    };
                });
            });
        });
    }
}
