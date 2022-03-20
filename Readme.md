# Endpoint Cloud Kit Bootstrap
Endpoint Cloud Kit Module (ECK), a set of cmdlet to help building scripts or application deployed by your MDM (Intune/Workspace One...)

That's being said, before using any module, you need to setup a few things on your local PC to allow download from the Powershell Gallery! This is the purpose of this bootstrap, but wait ! there's also a few goodies to make life easier:

## Description
This set of functions will do the following:
- Enable TLS 1.2.
- Silently Install version 2.8.5.208 of Nuget Package Provider. 
- Make the Powershell Gallery a trusted source.
- Import PowershellGet Module.
- Download and install Nuget.exe (optional).
- Install and import EndpointCloudKit Module.
- Install and import any module of your choice from Powershell Gallery.
- Copy localy  any script/file from Github or Gist
- Download and execute any Powershell script from Github or Gist


## Installation
If you just wish to install Endpoint Cloud Kit on your devellopment environment, the Bootstrapper is perhaps a bit to much. You can simply run the following commands:
```powershell
Install-Module EndpointCloudKit 
Import-module EndpointCloudKit
```
I you need to install Endpoint Cloud Kit on an MDM managed device you should embbed those lines at the begining of own script:
```powershell
try
	{
		$URI = "https://raw.githubusercontent.com/Diagg/EndPoint-CloudKit-Bootstrap/master/Initialize-ECKPrereq.ps1"
		$Bootstrap  = (Invoke-WebRequest  -URI $URI -UseBasicParsing  -ErrorAction Stop).content
		Invoke-Command  $Bootstrap   -ErrorAction stop
		Initialize-ECKPrereq
	}
catch
	{ Write-Error  "[ERROR] Unable to load ECK, Aborting !" ; Exit  1}
```

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
- You can execute as many scrip as you want using coma separator.  
- Scripts are executed after module import.
- Executed scripts can harm/break/nuke your system. Be very carefull about what you want to run ! At first this option was devellopped to run scripts mades of function like [this one](https://github.com/DanysysTeam/PS-SFTA/blob/master/SFTA.ps1). Of course you can run anything, but this kind of script give you back control on what and when to run your stuffs.

You can download locally any script from Gist/Github using the ``` -ScriptToLoad``` parameter:
 ```powershell
Initialize-ECKPrereq -ScriptToLoad 'https://gist.github.com/Diagg/f4b696aa5cd482f672477dffa0712d87','https://gist.github.com/Diagg/756d7564f342b8cfcae26ccead235f08'
```
Scripts are stored in ``` "$env:temp\ECK-Content" ``` by default, you set your own path using parameter ``` -ScriptPath``` :
 ```powershell
Initialize-ECKPrereq -ScriptToLoad 'https://gist.github.com/Diagg/f4b696aa5cd482f672477dffa0712d87'-scriptToLoad 'C:\temp'
```

The script log his own execution in ```"$env:temp\ECK-Init.log"``` you log to somewhere else using the ```-LogPath``` parameter.

