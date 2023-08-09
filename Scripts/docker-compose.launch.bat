@echo off

rem Navigate to the directory where your docker-compose.yml file is located
cd "../Sample.AuthorizationService/"

rem Launch Docker Compose
docker-compose -f "docker-compose.yml" build
docker-compose -f "docker-compose.yml" up -d

rem Wait user action
set /p WAITTEXT=Press Any key to continue...
