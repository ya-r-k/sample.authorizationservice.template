#See https://aka.ms/customizecontainer to learn how to customize your debug container and how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY ["Sample.AuthorizationService.Web/Sample.AuthorizationService.Web.csproj", "Sample.AuthorizationService.Web/"]
COPY ["Sample.AuthorizationService.Bll/Sample.AuthorizationService.Bll.csproj", "Sample.AuthorizationService.Bll/"]
COPY ["Sample.AuthorizationService.Common/Sample.AuthorizationService.Common.csproj", "Sample.AuthorizationService.Common/"]
COPY ["Sample.AuthorizationService.Di/Sample.AuthorizationService.Di.csproj", "Sample.AuthorizationService.Di/"]
COPY ["Sample.AuthorizationService.Dal/Sample.AuthorizationService.Dal.csproj", "Sample.AuthorizationService.Dal/"]
COPY . .
WORKDIR "/src/Sample.AuthorizationService.Web"
RUN dotnet restore
RUN dotnet build "Sample.AuthorizationService.Web.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Sample.AuthorizationService.Web.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Sample.AuthorizationService.Web.dll"]
