using Sample.AuthorizationService.Di;
using Sample.AuthorizationService.Web.GraphQl;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using OpenIddict.Abstractions;
using Prometheus;
using Quartz;
using Serilog;
using System.Security.Cryptography.X509Certificates;
using Sample.AuthorizationService.Web.Options;
using Sample.AuthorizationService.Web.Middleware;

var builder = WebApplication.CreateBuilder(args);
var isRunningInContainer = bool.TryParse(Environment.GetEnvironmentVariable("DOTNET_RUNNING_IN_CONTAINER"), out var result) && result;
var configuration = builder.Configuration;

// Configure Serilog
builder.Logging.ClearProviders();
builder.Logging.AddSerilog(new LoggerConfiguration()
    .ReadFrom.Configuration(configuration)
    .CreateLogger());

// Configure connection to database
var connectionString = isRunningInContainer
    ? configuration.GetConnectionString("Docker")
    : configuration.GetConnectionString("Default");

// Add services to the container.
builder.Services.AddRazorPages();
builder.Services.AddControllersWithViews();
builder.Services.AddServices();

builder.Services.ConfigureAspNetCoreIdentity();
builder.Services.ConfigureOpenIddict(builder.Configuration, builder.Environment, isRunningInContainer);

builder.Services.AddHealthChecks()
    .AddSqlServer(connectionString, timeout: TimeSpan.FromSeconds(5))
    .AddCheck("example", () => HealthCheckResult.Healthy("Example check is healthy"), new[] { "example" });

if (builder.Environment.IsDevelopment())
{
    builder.Services.AddDatabaseDeveloperPageExceptionFilter();
}

if (builder.Environment.IsDevelopment())
{
    builder.Services.AddCors(options =>
    {
        options.AddDefaultPolicy(builder =>
        {
            builder.AllowAnyOrigin()
                   .AllowAnyMethod()
                   .AllowAnyHeader();
        });
    });
}

builder.Services.Configure<TokenCleanupOptions>(
    builder.Configuration.GetSection("TokenCleanup"));

builder.Services.AddQuartz(options =>
{
    options.UseSimpleTypeLoader();
    options.UseInMemoryStore();

    var tokenCleanupOptions = builder.Configuration
        .GetSection("TokenCleanup")
        .Get<TokenCleanupOptions>();

    var jobKey = JobKey.Create(nameof(RemoveExpiredTokensJob));
    options.AddJob<RemoveExpiredTokensJob>(jobBuilder => jobBuilder
        .WithIdentity(jobKey)
        .DisallowConcurrentExecution());

    options.AddTrigger(triggerBuilder => triggerBuilder
        .ForJob(jobKey)
        .WithIdentity($"{nameof(RemoveExpiredTokensJob)}-trigger")
        .WithSimpleSchedule(scheduleBuilder => scheduleBuilder
            .WithInterval(tokenCleanupOptions?.Interval ?? TimeSpan.FromHours(12))
            .RepeatForever())
        .StartNow());
});

builder.Services.AddQuartzHostedService(options => options.WaitForJobsToComplete = true);

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("HasAccessToProfileInfo", policy =>
        policy.RequireAssertion(context =>
            context.User.HasScope(OpenIddictConstants.Scopes.Profile)));

    options.AddPolicy("HasAccessToRolesInfo", policy =>
        policy.RequireAssertion(context =>
            context.User.HasScope(OpenIddictConstants.Scopes.Roles)));

    options.AddPolicy("HasAccessToEmail", policy =>
        policy.RequireAssertion(context =>
            context.User.HasScope(OpenIddictConstants.Scopes.Email)));

    options.AddPolicy("HasAccessToPhoneNumber", policy =>
        policy.RequireAssertion(context =>
            context.User.HasScope(OpenIddictConstants.Scopes.Phone)));
});

builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
});

builder.Services.AddGraphQLServer()
    .AddAuthorization()
    .AddQueryType<UserQuery>()
    .AddProjections();

builder.Services.Configure<IdentityOptions>(options =>
{
    // Password settings
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequireUppercase = true;
    options.Password.RequiredLength = 8;
    options.Password.RequiredUniqueChars = 1;

    // Lockout settings
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;

    // User settings
    options.User.RequireUniqueEmail = true;
});

builder.Services.Configure<CaptchaOptions>(
    builder.Configuration.GetSection("Captcha"));

builder.Services.AddHttpClient();
builder.Services.AddScoped<CaptchaService>();

// Add Prometheus metrics
builder.Services.AddMetricServer(options =>
{
    options.Port = 9090;
});

// Configure the HTTP request pipeline.
var app = builder.Build();

app.FillAuthorizationServiceDatabase(app.Environment);

if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.UseMigrationsEndPoint();
}
else
{
    app.UseStatusCodePagesWithReExecute("~/error");
    //app.UseExceptionHandler("~/error");

    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

// Configure Prometheus
app.UseMetricServer();
app.UseHttpMetrics();
app.UseMiddleware<HttpMetricsMiddleware>();

app.UseStaticFiles();

app.UseCors();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapGraphQL();
app.MapControllers();
app.MapDefaultControllerRoute();
app.MapRazorPages();
app.MapMetrics();
app.MapHealthChecks("/health");

app.Run();
