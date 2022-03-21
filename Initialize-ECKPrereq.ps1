<#
.SYNOPSIS
Bootstrapper that Initialize environement to properly download script from Powershell Gallery.
Then download EnpointCloudkit module plus any other module you like

.DESCRIPTION
Performs a silent initialisation of  PowershellGet and the download and install EnpointCloudKit module.  
It can also load your favorit modules from the Powershell Gallery and your scripts from Gist/GitHub.
Each module is checked for latest version before being eventually downloaded 

.PARAMETER Module
List of modules (Ex: "Module1","Module2"...) to install and import

.PARAMETER LogPath
Path to log file. If not specified will default to "$env:temp\ECK-Init.log"
Use EndPointCloudKit (ECK) if present

.PARAMETER NugetDevTool
set to $true to download and install Nuget.exe. Disabled by defaut, requiered if you publish module to the powershell Gallery

.PARAMETER ScriptToLoad
List of url script to download from Gist/Github. If parameter $ScriptPath is not set all scripts are saved to "$env:temp\ECK-Content" 

.PARAMETER ScriptPath
Specify local path where downloaded script will be stored.  

.PARAMETER ScriptToImport
List of url script to download from Gist/Github and the to import and execute in the current powershell session. Use at you own risks
Intended to be used with scripts that only contains functions.  

.OUTPUTS
all action are logged to the log file specified by the log parameter

.EXAMPLE
C:\PS> Initialize-ECKPrereq -Module "Evergreen","Az.Accounts" -LogPath "c:\Windows\logs\Init-ECK.log" -ScriptToImport "https://github.com/DanysysTeam/PS-SFTA/blob/master/SFTA.ps1" -ScriptToLoad "https://gist.github.com/Diagg/756d7564f342b8cfcae26ccead235f08","https://gist.github.com/Diagg/f4b696aa5cd482f672477dffa0712d87"

Initialize PowershellGet, Import EndpointCloudKit, EverGreen dans Az.Account modules, 
Log anything to c:\Windows\logs\Init-ECK.log.
Download and exectute SFTA.ps1 from Github.
Download ans store in "$env:temp\ECK-Content" two scripts from Gist ! 
#>

##############
# Product Name: Initialize-ECKPrereq.ps1
# Publisher: OSD-Couture.com
# Product Code: a2638c6c-8168-4c8e-a9df-1dbb1397ba58
# Auto Update: NO3
# By Diagg/OSD-Couture.com
# 
# Version 1.1 - 17/03/2022 - Added check for Internt connection, Nuget.exe is now an option.
# Version 1.2 - 18/03/2022 - Added support for loading scripts in bulk, Added support for Importing (executing) scripts in bulk. 
# Version 1.3 - 20/03/2022 - Changed default logging to file.
# Version 1.4 - 21/03/2022 - Fixed a lot of bugs !


Function Initialize-ECKPrereq
    {
        Param (
                [String[]]$Module, #List of module to import separated by coma
                [string]$LogPath = "$env:temp\ECK-Init.log", #Defaut log file path
                [bool]$NugetDevTool = $false, #allow installation of nuget.exe, 
                [Parameter(ParameterSetName="Scriptload")][String[]]$ScriptToLoad, # download scripts form Github and place them in $ScriptPath folder
                [Parameter(ParameterSetName="Scriptload")][String]$ScriptPath = "$env:temp\ECK-Content", # Path where script are downloaded
                [String[]]$ScriptToImport # download scripts from Github and import them in the current Powershell session.
            )
        
        If (-not (Test-Path $ScriptPath)){New-Item $ScriptPath -ItemType Directory -Force|Out-Null}

        ## Set Tls to 1.2
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        ## Add Scripts path to $env:PSModulePath
        $CurrentValue = [Environment]::GetEnvironmentVariable("PSModulePath", "Machine")
        If ($CurrentValue -notlike "*C:\Program Files\WindowsPowerShell\scripts*") {[Environment]::SetEnvironmentVariable("PSModulePath", $CurrentValue + [System.IO.Path]::PathSeparator + "C:\Program Files\WindowsPowerShell\Scripts", "Machine")}

        Try 
            {
                ##Log with previous version if any
                If ((Get-Module endpointcloudkit -ListAvailable).Name -eq 'EndpointCloudkit'){Import-Module EndpointCloudkit ; $ECK = $true} Else {$ECK = $False}
         
                ## install providers
                If (-not(Test-path "C:\Program Files\PackageManagement\ProviderAssemblies\nuget\2.8.5.208\Microsoft.PackageManagement.NuGetProvider.dll"))
                    {
                        Try{Install-PackageProvider -Name 'nuget' -Force -ErrorAction stop |Out-Null}
                        Catch
                            {
                                $Message = "[ERROR] No internet connection available, Unable to Download Nuget Provider, Aborting !!"
                                If ($ECK -eq $true){Write-ECKlog -Path $LogPath -Message $Message} else {$Message|Out-file -FilePath $LogPath -Encoding UTF8 -Append -ErrorAction SilentlyContinue}
                                Exit 1
                            }
                    }
                $Message = "Nuget provider installed version: $(((Get-PackageProvider -Name 'nuget'|Sort-Object|Select-Object -First 1).version.tostring()))"
                If ($ECK -eq $true){Write-ECKlog -Path $LogPath -Message $Message} else {$Message|Out-file -FilePath $LogPath -Encoding UTF8 -Append -ErrorAction SilentlyContinue}


                ## Trust PSGallery
                If ((Get-PSRepository -Name "PsGallery").InstallationPolicy -ne "Trusted"){Set-PSRepository -Name 'PSGallery' -InstallationPolicy 'Trusted' -SourceLocation 'https://www.powershellgallery.com/api/v2'} 

                ## Import Powershell Get
                If (-not (Get-Module PowershellGet)) {Import-Module PowershellGet}
                $Message = "PowershellGet module installed version: $(((Get-Module PowerShellGet|Sort-Object|Select-Object -First 1).version.tostring()))"
                If ($ECK -eq $true){Write-ECKlog -Path $LogPath -Message $Message} else {$Message|Out-file -FilePath $LogPath -Encoding UTF8 -Append -ErrorAction SilentlyContinue}

                ##Install Nuget.Exe
                If ($NugetDevTool -eq $true)
                    {
                        $NugetPath = 'C:\ProgramData\Microsoft\Windows\PowerShell\PowerShellGet'
                        If (-not (test-path $NugetPath)){New-item $NugetPath -ItemType Directory -Force -Confirm:$false -ErrorAction SilentlyContinue | Out-Null}
                        If (-not (test-path "$NugetPath\Nuget.exe")){Invoke-WebRequest -Uri 'https://aka.ms/psget-nugetexe' -OutFile "$NugetPath\Nuget.exe" -ErrorAction SilentlyContinue}
                    }
                
                # Installing Endpoint Cloud Kit
                $Module += "endpointcloudkit"
                $Module = $Module[-1..0]

                # Installing modules
                Foreach ($mod in $Module)
                    {
                        $ModStatus = Get-ModuleNewVersion -modulename $Mod -LogPath $LogPath -ECK $ECK
                        If ($ModStatus -eq $true)
                            {
                                Import-Module $Mod -Force
                                If ($Mod -eq 'endpointcloudkit'){$ECK = $true} 
                                $Message = "$Mod module installed version: $(((Get-Module $mod|Sort-Object|Select-Object -last 1).version.tostring()))"
                                If ($ECK -eq $true){Write-ECKlog -Path $LogPath -Message $Message} else {$Message|Out-file -FilePath $LogPath -Encoding UTF8 -Append -ErrorAction SilentlyContinue}
                            }
                        Else
                            {
                                $Message = "[Error] Unable to install Module $Mod, Aborting!!!"
                                If ($ECK -eq $true){Write-ECKlog -Path $LogPath -Message $Message} else {$Message|Out-file -FilePath $LogPath -Encoding UTF8 -Append -ErrorAction SilentlyContinue}
                                Exit 1
                            }
                    }


                # Download Script and execute
                Foreach ($cript in $ScriptToImport)
                    {
                        $ScriptURI = Format-GitHubURL -URI $cript -LogPath $LogPath -ECK $ECK
                        Try 
                            {
                                $Fileraw = (Invoke-WebRequest -URI $ScriptURI -UseBasicParsing -ErrorAction Stop).content
                                $Message = "Running script $($ScriptURI.split("/")[-1]) !!!" 
                                If ($ECK -eq $true){Write-ECKlog -Path $LogPath -Message $Message} else {$Message|Out-file -FilePath $LogPath -Encoding UTF8 -Append -ErrorAction SilentlyContinue}
                                Invoke-expression $Fileraw -ErrorAction stop 
                            }
                        Catch
                            {
                                $Message = "[ERROR] Unable to get script content or error in execution, Aborting !!!" 
                                If ($ECK -eq $true){Write-ECKlog -Path $LogPath -Message $Message} else {$Message|Out-file -FilePath $LogPath -Encoding UTF8 -Append -ErrorAction SilentlyContinue}
                                Exit 1
                            }
                    }

                
                # Download Script and store them
                Foreach ($cript in $ScriptToLoad)
                    {
                        $ScriptURI = Format-GitHubURL -URI $cript -LogPath $LogPath -ECK $ECK
                        Try 
                            {
                                $Fileraw = (Invoke-WebRequest -URI $ScriptURI -UseBasicParsing -ErrorAction Stop).content
                                $Message = "Saving script to $scriptPath\$($ScriptURI.split("/")[-1]) !!!" 
                                If ($ECK -eq $true){Write-ECKlog -Path $LogPath -Message $Message} else {$Message|Out-file -FilePath $LogPath -Encoding UTF8 -Append -ErrorAction SilentlyContinue}
                                $Fileraw | Out-File -FilePath "$scriptPath\$($ScriptURI.split("/")[-1])" -Encoding utf8 -force
                            }
                        Catch
                            {
                                $Message = "[ERROR] Unable to get script content, Aborting !!!" 
                                If ($ECK -eq $true){Write-ECKlog -Path $LogPath -Message $Message} else {$Message|Out-file -FilePath $LogPath -Encoding UTF8 -Append -ErrorAction SilentlyContinue}
                                Exit 1
                            }
                    }

                $Message = "All operation finished, Endpoint Cloud Kit and other dependencies initialized sucessfully!!!"
                If ($ECK -eq $true){Write-ECKlog -Path $LogPath -Message $Message} else {$Message|Out-file -FilePath $LogPath -Encoding UTF8 -Append -ErrorAction SilentlyContinue}
            } 
        Catch 
            {
                $Message = "[Error] Unable to install default providers, Aborting!!!"
                If ($ECK -eq $true){Write-ECKlog -Path $LogPath -Message $Message} else {$Message|Out-file -FilePath $LogPath -Encoding UTF8 -Append -ErrorAction SilentlyContinue}
                Exit 1
            }
    }


Function Get-ModuleNewVersion
    {
        # Most code by https://blog.it-koehler.com/en/Archive/3359
        # Version 1.1 - 10/03/2022 - Added check for Internt connection

        Param(
                [Parameter(Mandatory = $true)][String]$ModuleName,
                [String]$LogPath,
                [String]$ECK=$false
            )

        #getting version of installed module
        $version = (Get-Module -ListAvailable $ModuleName) | Sort-Object Version -Descending  | Select-Object Version -First 1
        If (-not ($null -eq $version))
            {
                $stringver = $version | Select-Object @{n='ModuleVersion'; e={$_.Version -as [string]}}
                $a = $stringver | Select-Object Moduleversion -ExpandProperty Moduleversion
            }
        Else 
            {$a = "0.0"}
          
        #getting latest module version from ps gallery 
        Try {$psgalleryversion = Find-Module -Name $ModuleName -ErrorAction stop| Sort-Object Version -Descending | Select-Object Version -First 1}
        Catch 
            {
                If (-not ($null -eq $version)) 
                    {
                        $Message = "[Warning] No internet connection available, continuing with local version $version of $ModuleName"
                        If ($ECK -eq $true){Write-ECKlog -Path $LogPath -Message $Message -type 2} else {$Message|Out-file -FilePath $LogPath -Encoding UTF8 -Append -ErrorAction SilentlyContinue}
                    }
                Else
                    {
                        $Message = "[ERROR] No internet connection available, unable to load module $ModuleName, Aborting !!!"
                        If ($ECK -eq $true){Write-ECKlog -Path $LogPath -Message $Message -type 3} else {$Message|Out-file -FilePath $LogPath -Encoding UTF8 -Append -ErrorAction SilentlyContinue}
                        Exit 1
                    }  
            }
        
        
        If (-not ($null -eq $psgalleryversion))
            {
                $onlinever = $psgalleryversion | Select-Object @{n='OnlineVersion'; e={$_.Version -as [string]}}
                $b = $onlinever | Select-Object OnlineVersion -ExpandProperty OnlineVersion
            }
        Else
            {$b = "0.0"}
 
        if ([version]"$a" -ge [version]"$b") 
            {
                $Message = "Module $ModuleName Local version [$a] is equal or greater than online version [$b], no update requiered"
                If ($ECK -eq $true){Write-ECKlog -Path $LogPath -Message $Message} else {$Message|Out-file -FilePath $LogPath -Encoding UTF8 -Append -ErrorAction SilentlyContinue}
                return $true
            }
        else 
            {
                If ($b -ne "0")
                    {
                        $Message =  "Module $ModuleName Local version [$a] is lower than online version [$b], Updating Module !"
                        If ($ECK -eq $true){Write-ECKlog -Path $LogPath -Message $Message} else {$Message|Out-file -FilePath $LogPath -Encoding UTF8 -Append -ErrorAction SilentlyContinue}
                        If ($a -eq "0.0"){Install-Module -Name $ModuleName -Force}
                        Else {Update-Module -Name $ModuleName -Force}
                        return $true
                    }
                Else
                    {
                        $message = "[ERROR] Module $ModuleName not found online, unable to download, aborting!"
                        If ($ECK -eq $true){Write-ECKlog -Path $LogPath -Message $Message -level 3} else {$Message|Out-file -FilePath $LogPath -Encoding UTF8 -Append -ErrorAction SilentlyContinue}
                        return $false
                    }
            }
    }

function Format-GitHubURL
    {
        Param(
                [Parameter(Mandatory = $true)][String]$URI,
                [String]$LogPath,
                [String]$ECK
            )
                
        If($URI -like '*/gist.github.com*') ##This is a Gist
            {
                $URI = $URI.replace("gist.github.com","gist.githubusercontent.com")
                If ($URI.Split("/")[$_.count-1] -notlike '*raw*'){$URI = "$URI/raw"}
            }
        ElseIf($URI -like '*/github.com*') ##This is a Github repo
            {$URI = $URI -replace "github.com","raw.githubusercontent.com" -replace "blob/",""} 
        Else
            {
                If ($URI -notlike "*/raw.githubusercontent.com*" -and $URI -notlike "*//gist.githubusercontent.com*") 
                    {
                        $Message = "[ERROR] Unsupported Gist/Github URI $URI, Aborting !!!"
                        If ($ECK -eq $true){Write-ECKlog -Path $LogPath -Message $Message} else {$Message|Out-file -FilePath $LogPath -Encoding UTF8 -Append -ErrorAction SilentlyContinue}
                        Exit 1
                    }
            }
        Return $URI
    }
