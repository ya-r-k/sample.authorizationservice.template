using Sample.AuthorizationService.Di;
using Sample.AuthorizationService.Web.GraphQl;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using OpenIddict.Abstractions;
using Quartz;
using Serilog;
using Sample.AuthorizationService.Web.Extensions;

var builder = WebApplication.CreateBuilder(args);

// Configure Serilog
builder.Host.UseSerilog(new LoggerConfiguration()
    .Enrich.WithThreadId()
    .Enrich.WithProcessId()
    .Enrich.WithMachineName()
    .Enrich.WithEnvironmentUserName()
    .Enrich.WithEnvironmentName()
    .WriteTo.Console(
        outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff} [{Level:u3}] (Environment: [{MachineName} {EnvironmentUserName}] {EnvironmentName}, Process: {ProcessId}, Thread: {ThreadId}) {Message} {Properties}{NewLine}{Exception}")
    .WriteTo.File(
        path: @"/Logs/Sample/Sample.AuthorizationService/logs-.txt",
        rollingInterval: RollingInterval.Day,
        outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff} [{Level:u3}] (Environment: [{MachineName} {EnvironmentUserName}] {EnvironmentName}, Process: {ProcessId}, Thread: {ThreadId}) {Message} {Properties}{NewLine}{Exception}")
    .CreateLogger());

builder.WebHost.AddKestrel(builder.Configuration);

builder.Services.AddControllersWithViews();
builder.Services.AddRazorPages();

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

builder.Services.AddQuartz(options =>
{
    options.UseMicrosoftDependencyInjectionJobFactory();

    options.UseSimpleTypeLoader();

    options.UseInMemoryStore();
});

builder.Services.AddQuartzHostedService(options => options.WaitForJobsToComplete = true);

builder.Services.ConfigureAspNetCoreIdentity();

builder.Services.ConfigureOpenIddict(builder.Configuration, builder.Environment);

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

builder.Services.AddServices();

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

app.UseStaticFiles();

app.UseCors();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.UseSerilogRequestLogging();

app.MapGraphQL();
app.MapControllers();
app.MapDefaultControllerRoute();
app.MapRazorPages();

app.Run();
