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

.PARAMETER ContentToLoad
List of url script to download from Gist/Github. If parameter $ContentPath is not set all scripts are saved to "$env:temp\ECK-Content" 

.PARAMETER ContentPath
Specify local path where downloaded script will be stored.  

.PARAMETER ScriptToImport
List of url script to download from Gist/Github and the to import and execute in the current powershell session. Use at you own risks
Intended to be used with scripts that only contains functions.  

.OUTPUTS
all action are logged to the log file specified by the log parameter

.EXAMPLE
C:\PS> Initialize-ECKPrereq -Module "Evergreen","Az.Accounts" -LogPath "c:\Windows\logs\Init-ECK.log" -ScriptToImport "https://github.com/DanysysTeam/PS-SFTA/blob/master/SFTA.ps1" -ContentToLoad "https://gist.github.com/Diagg/756d7564f342b8cfcae26ccead235f08","https://gist.github.com/Diagg/f4b696aa5cd482f672477dffa0712d87"

Initialize PowershellGet, Import EndpointCloudKit, EverGreen and Az.Account modules, 
Log anything to c:\Windows\logs\Init-ECK.log.
Download and exectute SFTA.ps1 from Github.
Download ans store in "$env:temp\ECK-Content" two scripts from Gist ! 
#>

##############
# Product Name: Initialize-ECKPrereq.ps1
# Publisher: OSD-Couture.com
# Product Code: a2638c6c-8168-4c8e-a9df-1dbb1397ba58
# Auto Update: NO
# By Diagg/OSD-Couture.com
# 
# Version 1.1 - 17/03/2022 - Added check for Internt connection, Nuget.exe is now an option.
# Version 1.2 - 18/03/2022 - Added support for loading scripts in bulk, Added support for Importing (executing) scripts in bulk. 
# Version 1.3 - 20/03/2022 - Changed default logging to file.
# Version 1.4 - 21/03/2022 - Fixed a lot of bugs !
# Version 1.5 - 22/03/2022 - Fixed a bug in Format-GitHubURL that produced non working URI
# Version 1.6.1 - 22/03/2022 - Added Policy to block more that one update per day for modules.
# version 1.7 - 24/03/2023 - Added download of Hiddenw.exe 
# version 1.8.2 - 30/03/2023 - Added download of ServiceUI.exe 
# version 1.9.1 - 05/04/2022 - Changed default Log path, use Set-ECKEnvironment
# version 2.0 - 11/04/2022 - Now fully working under system account

Function Initialize-ECKPrereq
    {
        Param (
                [String[]]$Module,                                                                          # List of module to import separated by coma
                [string]$LogPath = "C:\Windows\Logs\ECK\ECK-Init.log",                                      # Defaut log file path
                [bool]$NugetDevTool = $false,                                                               # Allow installation of nuget.exe, 
                [Parameter(ParameterSetName="Contentload")][String[]]$ContentToLoad,                        # Download scripts form Github and place them in $ContentPath folder
                [Parameter(ParameterSetName="Contentload")][String]$ContentPath = "$env:temp\ECK-Content",  # Path where script are downloaded
                [String[]]$ScriptToImport                                                                   # download scripts from Github and import them in the current Powershell session.
            )

        ## Create Folders and registry keys
        If (-not (Test-Path $ContentPath)){New-Item $ContentPath -ItemType Directory -Force|Out-Null}
        If (-not (Test-Path $(Split-Path $LogPath ))){New-Item $(Split-Path $LogPath) -ItemType Directory -Force|Out-Null}
        If (-not (test-path "HKLM:\SOFTWARE\ECK\DependenciesCheck")){New-item -Path "HKLM:\SOFTWARE\ECK\DependenciesCheck" -Force|Out-Null} 

        ## Set Tls to 1.2
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        ## Add Scripts path to $env:PSModulePath
        $CurrentValue = [Environment]::GetEnvironmentVariable("PSModulePath", "Machine")
        If ($CurrentValue -notlike "*C:\Program Files\WindowsPowerShell\scripts*") {[Environment]::SetEnvironmentVariable("PSModulePath", $CurrentValue + [System.IO.Path]::PathSeparator + "C:\Program Files\WindowsPowerShell\Scripts", "Machine")}

        Try 
            {
                ##Log with previous version if any
                If ((Get-Module 'endpointcloudkit' -ListAvailable).Name -eq 'EndpointCloudkit')
                    {
                        Remove-module 'endpointcloudkit' -ErrorAction SilentlyContinue
                        Get-Module 'endpointcloudkit' -ListAvailable | Sort-Object Version -Descending  | Select-Object -First 1|Import-module
                        Set-ECKEnvironment -FullGather -LogPath $LogPath
                        $ModECK = $true
                    } 
                Else {$ModECK = $False}
         
                ## install Nuget provider
                If (-not(Test-path "C:\Program Files\PackageManagement\ProviderAssemblies\nuget\2.8.5.208\Microsoft.PackageManagement.NuGetProvider.dll"))
                    {
                        Try{Install-PackageProvider -Name 'nuget' -Force -ErrorAction stop |Out-Null}
                        Catch
                            {
                                $Message = "[ERROR] No internet connection available, Unable to Download Nuget Provider, Aborting !!"
                                If ($ModECK -eq $true){Write-ECKlog -Message $Message} else {$Message|Out-file -FilePath $LogPath -Encoding UTF8 -Append -ErrorAction SilentlyContinue}
                                Exit 1
                            }
                    }
                $Message = "Nuget provider installed version: $(((Get-PackageProvider -Name 'nuget'|Sort-Object|Select-Object -First 1).version.tostring()))"
                If ($ModECK -eq $true){Write-ECKlog -Message $Message} else {$Message|Out-file -FilePath $LogPath -Encoding UTF8 -Append -ErrorAction SilentlyContinue}

                ## Install Packagemangment Module dependencie of Powershell Get if we are under system account
                IF ((get-module PackageManagement -ListAvailable|Select-Object -first 1).version -notlike "1.4*" -and $env:UserProfile -eq 'C:\Windows\system32\config\systemprofile')
                    {
                        Try
                            {
                                $FileURI = "https://psg-prod-eastus.azureedge.net/packages/packagemanagement.1.4.7.nupkg"
                                $Nupkg = "$ContentPath\$(($FileURI.split("/")[-1]).replace(".nupkg",".zip"))"
                                Invoke-WebRequest -URI $FileURI -UseBasicParsing -ErrorAction Stop -OutFile $Nupkg
                                Unblock-File -Path $Nupkg
                            }
                        Catch
                            {
                                $Message = "[ERROR] No internet connection available, Unable to Download Nuget Provider, Aborting !!"
                                If ($ModECK -eq $true){Write-ECKlog -Message $Message} else {$Message|Out-file -FilePath $LogPath -Encoding UTF8 -Append -ErrorAction SilentlyContinue}
                                Exit 1
                            }

                        ## Create Destination folder structure
                        $ModulePath = "C:\Program Files\WindowsPowerShell\Modules\PackageManagement\1.4.7"
                        If (-not(test-path $ModulePath)){New-item -Path $ModulePath -ItemType Directory -Force|Out-Null} 

                        ## Uniziping File
                        Expand-Archive -LiteralPath $Nupkg -DestinationPath $ModulePath -Force
                        Remove-Item $Nupkg -Force -ErrorAction SilentlyContinue|Out-Null
                        
                        ## Clean bloatwares
                        Remove-Item "$ModulePath\_rels" -Recurse -Force -ErrorAction SilentlyContinue|Out-Null
                        Remove-Item "$ModulePath\package" -Recurse -Force -ErrorAction SilentlyContinue|Out-Null
                        Remove-Item "$ModulePath\``[Content_Types``].xml"  -Force -ErrorAction SilentlyContinue|Out-Null
                        Remove-Item "$ModulePath\PackageManagement.nuspec"  -Force -ErrorAction SilentlyContinue|Out-Null
                    }

                ## Import Powershell Get
                If (-not (Get-Module PowershellGet)) {Get-Module 'PowershellGet' -ListAvailable | Sort-Object Version -Descending  | Select-Object -First 1|Import-module}
                $Message = "PowershellGet module installed version: $(((Get-Module PowerShellGet|Sort-Object|Select-Object -First 1).version.tostring()))"
                If ($ModECK -eq $true){Write-ECKlog -Message $Message} else {$Message|Out-file -FilePath $LogPath -Encoding UTF8 -Append -ErrorAction SilentlyContinue}

                ## Trust PSGallery
                If ((Get-PSRepository -Name "PsGallery").InstallationPolicy -ne "Trusted"){Set-PSRepository -Name 'PSGallery' -InstallationPolicy 'Trusted' -SourceLocation 'https://www.powershellgallery.com/api/v2'} 

                # Installing Endpoint Cloud Kit
                $Module += "endpointcloudkit"
                $Module = $Module[-1..0]

                # Installing modules
                Foreach ($mod in $Module)
                    {
                        $ModStatus = Get-ECKNewModuleVersion -modulename $Mod -LogPath $LogPath
                        If ($ModStatus -ne $false)
                            {
                                Remove-module $mod -ErrorAction SilentlyContinue
                                $LoadedMod = Get-Module $mod -ListAvailable | Sort-Object Version -Descending  | Select-Object -First 1|Import-module -passthru
                                If ($Mod -eq 'endpointcloudkit' -and $ModECK -ne $true){Set-ECKEnvironment -FullGather -LogPath $LogPath ; $ModECK = $true} 
                                Write-ECKlog -Message "$Mod module installed version: $($LoadedMod.version.tostring())"
                            }
                        Else
                            {Write-ECKlog -Message "[Error] Unable to install Module $Mod, Aborting!!!" ; Exit 1}
                    }


                ##Install Nuget.Exe
                If ($NugetDevTool -eq $true)
                    {
                        $NugetPath = 'C:\ProgramData\Microsoft\Windows\PowerShell\PowerShellGet'
                        If (-not (test-path $NugetPath)){New-item $NugetPath -ItemType Directory -Force -Confirm:$false -ErrorAction SilentlyContinue | Out-Null}
                        If (-not (test-path "$NugetPath\Nuget.exe")){Invoke-WebRequest -Uri 'https://aka.ms/psget-nugetexe' -OutFile "$NugetPath\Nuget.exe" -ErrorAction SilentlyContinue}
                    }
                
                ##Install Hiddenw.exe
                $PowershellwPath = 'C:\Windows\System32\WindowsPowerShell\v1.0\Powershellw.exe'
                If (-not (test-path $PowershellwPath)){Invoke-WebRequest -Uri 'https://github.com/SeidChr/RunHiddenConsole/releases/download/1.0.0-alpha.2/hiddenw.exe' -OutFile $PowershellwPath -ErrorAction SilentlyContinue}
                If (test-path $PowershellwPath){Write-ECKlog -Message "Successfully Downloaded $PowershellwPath !"}    

                ##Install SerciceUI_X64.exe
                $SrvUIPath = 'C:\Windows\System32\ServiceUI.exe'
                If (-not (test-path $SrvUIPath)){Invoke-WebRequest -Uri $(Format-GitHubURL 'https://github.com/Diagg/EndPoint-CloudKit-Bootstrap/blob/master/ServiceUI/ServiceUI_x64.exe') -OutFile $SrvUIPath -ErrorAction SilentlyContinue}
                If (test-path $SrvUIPath){Write-ECKlog -Message "Successfully Downloaded $SrvUIPath !"} 

                ##Install SerciceUI_X86.exe                
                $SrvUIPath = 'C:\Windows\SysWOW64\ServiceUI.exe'
                If (-not (test-path $SrvUIPath)){Invoke-WebRequest -Uri $(Format-GitHubURL 'https://github.com/Diagg/EndPoint-CloudKit-Bootstrap/blob/master/ServiceUI/ServiceUI_x86.exe') -OutFile $SrvUIPath -ErrorAction SilentlyContinue}
                If (test-path $SrvUIPath){Write-ECKlog -Message "Successfully Downloaded $SrvUIPath !"} 

                # Download Script and execute
                Foreach ($cript in $ScriptToImport)
                    {
                        $ScriptURI = Format-GitHubURL -URI $cript -LogPath $LogPath
                        Try 
                            {
                                $Fileraw = (Invoke-WebRequest -URI $ScriptURI -UseBasicParsing -ErrorAction Stop).content
                                Write-ECKlog -Message "Running script $($ScriptURI.split("/")[-1]) !!!"
                                Invoke-expression $Fileraw -ErrorAction stop 
                            }
                        Catch
                            {Write-ECKlog -Message "[ERROR] Unable to get script content or error in execution, Aborting !!!" ; Exit 1}
                    }

                
                # Download Script and store them
                Foreach ($File in $ContentToLoad)
                    {
                        $FiletURI = Format-GitHubURL -URI $File -LogPath $LogPath
                        Try 
                            {
                                $Fileraw = (Invoke-WebRequest -URI $FiletURI -UseBasicParsing -ErrorAction Stop).content
                                Write-ECKlog -Message "Succesfully downloaded content to $ContentPath\$($FiletURI.split("/")[-1]) !!!"
                                $Fileraw | Out-File -FilePath "$ContentPath\$($FiletURI.split("/")[-1])" -Encoding utf8 -force
                            }
                        Catch
                            {Write-ECKlog -Message "[ERROR] Unable to get content, Aborting !!!" ; Exit 1}
                    }

                Write-ECKlog -Message "All initialization operations finished, Endpoint Cloud Kit and other dependencies staged sucessfully!!!"
            } 
        Catch 
            {
                $Message = $_.Exception.Message.ToString()
                If ($ModECK -eq $true){Write-ECKlog -Message $Message -Type 3} else {$Message|Out-file -FilePath $LogPath -Encoding UTF8 -Append -ErrorAction SilentlyContinue}
                $Message =  $_.InvocationInfo.PositionMessage.ToString()
                If ($ModECK -eq $true){Write-ECKlog -Message $Message -Type 3} else {$Message|Out-file -FilePath $LogPath -Encoding UTF8 -Append -ErrorAction SilentlyContinue}
                $Message = "[Error] Unable to install default providers, Enpdoint Cloud Kit or Dependencies, Aborting!!!"
                If ($ModECK -eq $true){Write-ECKlog -Message $Message -Type 3} else {$Message|Out-file -FilePath $LogPath -Encoding UTF8 -Append -ErrorAction SilentlyContinue}
                Exit 1
            }
    }


Function Get-ECKNewModuleVersion
    {
        # Most code by https://blog.it-koehler.com/en/Archive/3359
        # Version 1.1 - 10/03/2022 - Added check for Internet connection
        # Version 1.2 - 14/04/2022 - Module version is now returned 

        Param(
                [Parameter(Mandatory = $true)][String]$ModuleName,
                [String]$LogPath
            )

        # Check if we need to update today
        $lastEval = (Get-ItemProperty "HKLM:\SOFTWARE\ECK\DependenciesCheck" -name $ModuleName -ErrorAction SilentlyContinue).$ModuleName
        If (![String]::IsNullOrWhiteSpace($lastEval)){If ((Get-date -Date $LastEval) -eq ((get-date).date)){Return $true}}
        

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
                        If ($null -ne $ECK){Write-ECKlog -Message $Message -type 2} else {$Message|Out-file -FilePath $LogPath -Encoding UTF8 -Append -ErrorAction SilentlyContinue}
                    }
                Else
                    {
                        $Message = "[ERROR] No internet connection available, unable to load module $ModuleName, Aborting !!!"
                        If ($null -ne $ECK){Write-ECKlog -Message $Message -type 3} else {$Message|Out-file -FilePath $LogPath -Encoding UTF8 -Append -ErrorAction SilentlyContinue}
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
                If ($null -ne $ECK){Write-ECKlog -Message $Message} else {$Message|Out-file -FilePath $LogPath -Encoding UTF8 -Append -ErrorAction SilentlyContinue}
                return $version
            }
        else 
            {
                If ($b -ne "0")
                    {
                        $Message =  "Module $ModuleName Local version [$a] is lower than online version [$b], Updating Module !"
                        If ($null -ne $ECK){Write-ECKlog -Message $Message} else {$Message|Out-file -FilePath $LogPath -Encoding UTF8 -Append -ErrorAction SilentlyContinue}
                        If ($a -eq "0.0"){Install-Module -Name $ModuleName -Force}
                        Else {Update-Module -Name $ModuleName -Force}
                        Set-ItemProperty "HKLM:\SOFTWARE\ECK\DependenciesCheck" -Name $ModuleName -value $((get-date).date)    
                        return $psgalleryversion
                    }
                Else
                    {
                        $message = "[ERROR] Module $ModuleName not found online, unable to download, aborting!"
                        If ($null -ne $ECK){Write-ECKlog -Message $Message -level 3} else {$Message|Out-file -FilePath $LogPath -Encoding UTF8 -Append -ErrorAction SilentlyContinue}
                        return $false
                    }
            }
    }

function Format-GitHubURL
    {
        Param(
                [Parameter(Mandatory = $true, Position=0)]
                [String]$URI,
                [String]$LogPath
            )
                
        If($URI -like '*/gist.github.com*') ##This is a Gist
            {
                $URI = $URI.replace("gist.github.com","gist.githubusercontent.com")
                If ($URI.Split("/")[$_.count-1] -notlike '*raw*'){$URI = "$URI/raw"}
            }
        ElseIf($URI -like '*/github.com*') ##This is a Github repo
            {$URI = $URI -replace "blob/","raw/"} 
        Else
            {
                If ($URI -notlike "*//gist.githubusercontent.com*") 
                    {
                        $Message = "[ERROR] Unsupported Gist/Github URI $URI, Aborting !!!"
                        If ($null -ne $ECK){Write-ECKlog -Message $Message} else {$Message|Out-file -FilePath $LogPath -Encoding UTF8 -Append -ErrorAction SilentlyContinue}
                        Exit 1
                    }
            }
        Return $URI
    }

Initialize-ECKPrereq -Module "Evergreen" -LogPath "c:\Temp\logs\Init-ECK.log" -ContentToLoad "https://github.com/DanysysTeam/PS-SFTA/blob/master/SFTA.ps1"