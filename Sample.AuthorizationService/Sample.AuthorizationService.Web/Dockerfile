#See https://aka.ms/customizecontainer to learn how to customize your debug container and how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
EXPOSE 5234
EXPOSE 7178

# Install curl for healthcheck
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY ["Sample.AuthorizationService.Web/Sample.AuthorizationService.Web.csproj", "Sample.AuthorizationService.Web/"]
COPY ["Sample.AuthorizationService.Bll/Sample.AuthorizationService.Bll.csproj", "Sample.AuthorizationService.Bll/"]
COPY ["Sample.AuthorizationService.Dal/Sample.AuthorizationService.Dal.csproj", "Sample.AuthorizationService.Dal/"]
COPY ["Sample.AuthorizationService.Common/Sample.AuthorizationService.Common.csproj", "Sample.AuthorizationService.Common/"]
RUN dotnet restore "Sample.AuthorizationService.Web/Sample.AuthorizationService.Web.csproj"
COPY . .
WORKDIR "/src/Sample.AuthorizationService.Web"
RUN dotnet build "Sample.AuthorizationService.Web.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Sample.AuthorizationService.Web.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
USER $APP_UID
ENTRYPOINT ["dotnet", "Sample.AuthorizationService.Web.dll"]
