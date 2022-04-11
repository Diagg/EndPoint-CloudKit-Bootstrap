# Endpoint Cloud Kit Bootstrap
[Endpoint Cloud Kit](https://github.com/Diagg/EndPoint-CloudKit) Module (ECK) is a set of cmdlet to help building scripts or applications deployed by your MDM (Intune/Workspace One...)

That's being said, before using any Powershell module on an endpoint, There are few things that need to be configured on the PC to allow download from the Powershell Gallery! This is the purpose of this bootstrap ! The script also allow downloading additional content from the interweb, and is a good starting point (whether or not you use ECK) if you are planning to use  Powershell modules within the cloud on managed endpoints !

## Description
This set of functions will do the following:
- Enable TLS 1.2.
- Silently Install version 2.8.5.208 of Nuget Package Provider. 
- Make the Powershell Gallery a trusted source.
- Import PowershellGet Module.
- Download and install Nuget.exe (optional).
- Install and import EndpointCloudKit Module.
- Install and import any module of your choice from Powershell Gallery.
- Copy locally  any script/file from Github or Gist
- Download and execute any Powershell script from Github or Gist


## Installation
If you just wish to install Endpoint Cloud Kit on your development environment, the Bootstrap (Initialize-ECKPrereq.ps1) is perhaps a bit to much. You can simply run the following commands:
```powershell
Install-Module EndpointCloudKit 
Import-module EndpointCloudKit
```
I you need to install Endpoint Cloud Kit on an MDM managed device, the bootstrap is what you need! There is no need to do the traditional download and then create a package. 
The idea here is to retrieve the script from github wherever you are. To do this, you should embed those lines at the beginning of your own scripts:
```powershell
try
    {
        If ([string]::IsNullOrWhiteSpace($ECK.ModVersion))
            {
                $URI = "https://raw.githubusercontent.com/Diagg/EndPoint-CloudKit-Bootstrap/master/Initialize-ECKPrereq.ps1"
                $Bootstrap  = (Invoke-WebRequest  -URI $URI -UseBasicParsing  -ErrorAction Stop).content
                Invoke-Expression ("<#" + $Bootstrap) -ErrorAction stop
                Initialize-ECKPrereq
            }
    }
catch
    { Write-Error  "[ERROR] Unable to load ECK, Aborting !" ; Exit  1}
```
That's all, now you are ready to use Endpoint Cloud Kit, now you are ready to install anything from the Powershell Gallery !

## Options

If you need to install more modules, you can launch the script using the ``` -module ``` parameter:
```powershell
Initialize-ECKPrereq -Module "Evergreen","DellBIOSProvider","Carbon"
```
 You can run any script from Gist/Github using the ```  -ScriptToImport``` parameter:
 ```powershell
Initialize-ECKPrereq -ScriptToImport 'https://github.com/DanysysTeam/PS-SFTA/blob/master/SFTA.ps1'
```

a few notes about this parameter:
- You can execute as many scripts as you want using coma separators.  
- Scripts are executed after module import.
- To save on bandwidth and time processing, Modules are downloaded/updated one time per day.  
- Executed scripts can harm/break/nuke your system. Be very careful about what you run! At first this option was developpes to run scripts filled out only with functions like [this one](https://github.com/DanysysTeam/PS-SFTA/blob/master/SFTA.ps1). Of course you can run anything, but using 'Function's script' give you back control on what and when to run your code.

You can download locally any script from Gist/Github using the ``` -ScriptToLoad``` parameter:
 ```powershell
Initialize-ECKPrereq -ScriptToLoad 'https://gist.github.com/Diagg/f4b696aa5cd482f672477dffa0712d87','https://gist.github.com/Diagg/756d7564f342b8cfcae26ccead235f08'
```
Scripts are stored in ``` "$env:temp\ECK-Content" ``` by default, you can set your own path using parameter ``` -ScriptPath``` :
 ```powershell
Initialize-ECKPrereq -ScriptToLoad 'https://gist.github.com/Diagg/f4b696aa5cd482f672477dffa0712d87'-scriptToLoad 'C:\temp'
```

The script log his own execution in ```C:\Windows\Logs\ECK\ECK-Init.log``` you can log to anywhere else using the ```-LogPath``` parameter.

Diagg/OSD-Couture.com

