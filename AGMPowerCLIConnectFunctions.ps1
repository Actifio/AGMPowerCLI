# Copyright 2022 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

function psfivecerthandler
{
    if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type)
    {
    $certCallback = @"  
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    public class ServerCertificateValidationCallback
    {
        public static void Ignore()
        {
            if(ServicePointManager.ServerCertificateValidationCallback ==null)
            {
                ServicePointManager.ServerCertificateValidationCallback += 
                    delegate
                    (
                        Object obj, 
                        X509Certificate certificate, 
                        X509Chain chain, 
                        SslPolicyErrors errors
                    )
                    {
                        return true;
                    };
            }
        }
    }
"@
    Add-Type $certCallback
    }
    [ServerCertificateValidationCallback]::Ignore()
    
    # ensure TLS12 is in use.  We set it back when disconnect-act is run
    $env:CUR_PROTS = [System.Net.ServicePointManager]::SecurityProtocol
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;
}

function Connect-AGM
{
    <#
    .SYNOPSIS
    Connects to AGM to create a Session ID

    .DESCRIPTION
    The Connect-AGM connects to AGM to get a session ID to use on all subsequent calls

    .NOTES
    Written by Anthony Vandewerdt

    .EXAMPLE
    Google Cloud Backup and DR only:
    Connect-AGM -agmip agm-12345678.backupdr.actifiogo.com -agmuser apiuser@project1.iam.gserviceaccount.com -oauth2ClientId 123456789-fimdb0rbeamc17l3akilabcdefgh.apps.googleusercontent.com

    Connects to a Google Cloud Backup and DR Management Console.  The key difference is that rather than a password, an oauth2ClientId is specified instead
    Note the AGMIP is not a URL.  It is the host name portion of the endpoint without either https:// at the start or /actifio at the end

    .EXAMPLE
    Actifio only:
    Connect-AGM -agmip 172.24.1.117 -agmuser admin
    This will connect to AGM with a username of "admin" to the IP address 172.24.1.117.
    The prompt will request a secure password.

    .EXAMPLE
    Actifio only:
    Connect-AGM -agmip 172.24.1.117 -agmuser admin -i
    This will connect to AGM with a username of "admin" to the IP address 172.24.1.117.
    The prompt will securely request a password.
    Because -i is specified certificate validation of the AGM is ignored

    .EXAMPLE
    Actifio only:
    Connect-AGM -agmip 172.24.1.117 -agmuser admin -passwordfile av.key
    This will connect to AGM with a username of "admin" to the IP address 172.24.1.117.
    The password will be provided by using a previously created password file using Save-AGMPassword

    #>

    
    Param([String]$agmip,[String]$agmuser,[String]$agmpassword,[String]$oauth2ClientId,[String]$passwordfile,[switch][alias("q")]$quiet, [switch][alias("p")]$printsession,[switch][alias("i")]$ignorecerts,[int]$actmaxapilimit,[int]$agmtimeout)

    # max objects returned will be unlimited.   Otherwise user can supply a limit
    if (!($agmmaxapilimit))
    {
        $agmmaxapilimit = 0
    }
    $GLOBAL:agmmaxapilimit = $agmmaxapilimit

    if (!($agmip))
    {
    $agmip = Read-Host "IP or Name of AGM"
    }
    if ($agmip | select-string "/")
    {
        Get-AGMErrorMessage -messagetoprint "AGMIP is possibly a URL.  Use the FQDN portion of the URL without either https:// or /actifio"
        return
    }
    
    if (!($agmuser))
    {
    $agmuser = Read-Host "AGM user"
    }

    if (!($agmtimeout))
    {
        [int]$agmtimeout = 300
    }

    $agmipsniff = $agmip.Substring(0,4)
    if ($agmipsniff = "bmc-")
    {
        $accesstoken = $true
    }

    if ((!($agmpassword)) -and (!($passwordfile)) -and (!($oauth2ClientId)) -and (!($accesstoken)))
    {
        if ($agmipsniff = "agm-")
        {
            $oauth2ClientId = Read-Host "oauth2ClientId"
        }
    }

    # based on the action, do the right thing.
    if ( $certaction -eq "i" -or $certaction -eq "I" )
    {
        $hostVersionInfo = (get-host).Version.Major
        if ( $hostVersionInfo -lt "6" )
        {
            psfivecerthandler
        }
        else 
        {
            # set IGNOREAGMCERTS so that we ignore self-signed certs
            $GLOBAL:IGNOREAGMCERTS = "y"
        }
    }

    # OAUTH handling
    if (($oauth2ClientId) -or ($accesstoken))
    {
        if (((get-host).Version.Major -eq 7) -and ((get-host).Version.Minor -eq 3))
        {
            $PSNativeCommandArgumentPassing = "Legacy"
        }
        # first we get a token
        if ($oauth2ClientId)
        {
             $Url = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/$agmuser" +":generateIdToken"
             $body = '{"audience": "' +$oauth2ClientId +'", "includeEmail":"true"}'
        }
        else
        {
             $Url = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/$agmuser" +":generateAccessToken"
             $body = '{"scope":["https://www.googleapis.com/auth/cloud-platform","https://www.googleapis.com/auth/userinfo.email"],"lifetime":"3600s"}'
        }
        $RestError = $null
        Try
        {
            $resp = Invoke-RestMethod -Method POST -Headers @{ Authorization = "Bearer $(gcloud auth print-access-token)" }  -body $body -ContentType "application/json" -Uri $url
        }
        Catch
        {
            $RestError = $_
        }
        if ($RestError)
        {
            $loginfailedsniff = Test-AGMJSON $RestError
            $loginfailedsniff
            return
        }
        elseif ($resp.token)
        {
            $token = $resp.token
        }
        elseif ($resp.accessToken)
        {
            $token = $resp.accessToken
        }
        else 
        {
            Get-AGMErrorMessage -messagetoprint "Failed to get a token"
            return
        }
        # now we get a sessionID

        $Url = "https://" +$agmip +"/actifio/session"
        Try
        {
            $resp = Invoke-RestMethod -Method POST -Headers @{ Authorization = "Bearer $token" } -Uri $Url
        }
        Catch
        {
            $RestError = $_
        }
        if ($RestError)
        {
            $loginfailedsniff = Test-AGMJSON $RestError
            $loginfailedsniff
            return
        }
        elseif ($resp.id)
        {
            $GLOBAL:AGMSESSIONID = $resp.id
            $GLOBAL:AGMIP = $agmip
            $GLOBAL:AGMTimezone = "local"
            $GLOBAL:AGMToken = $token
            $GLOBAL:AGMTIMEOUT = $agmtimeout
            if ($quiet)
            {
                return
            }
            elseif ($printsession)
            {
                Write-Host "$agmsessionid"
                return
            }
            else 
            {
                Write-Host "Login Successful!"
                return
            }
        }
        else 
        {
            Get-AGMErrorMessage -messagetoprint "Failed to get a sessionid"
            return
        }
    }

    # start 10.x AGM from below
    if ($ignorecerts)
    {
        $hostVersionInfo = (get-host).Version.Major
        if ( $hostVersionInfo -lt "6" )
        {
            psfivecerthandler
        }
        else 
        {
            $GLOBAL:IGNOREAGMCERTS = "y"
        }
    }
    else
    {
        Try
        {
            $resp = Invoke-RestMethod -Uri https://$agmip -TimeoutSec 60
        }
        Catch
        {
            $RestError = $_
        }
        if ($RestError -like "The operation was canceled.")
        {
            Get-AGMErrorMessage -messagetoprint "No response was received from $agmip after $agmtimeout seconds"
            return;
        }
        elseif ($RestError -like "Connection refused")
        {
            Get-AGMErrorMessage -messagetoprint "Connection refused received from $agmip"
            return;
        }
        elseif ($RestError)
        {
            Write-Host -ForeGroundColor Yellow "The SSL certificate from https://$agmip is not trusted. Please choose one of the following options";
            Write-Host -ForeGroundColor Yellow "(I)gnore & continue";
            Write-Host -ForeGroundColor Yellow "(C)ancel";
            $validresp = ("i", "I", "c", "C");
            $certaction = $null

            # prompt until we get a proper response.
            while ( $validresp.Contains($certaction) -eq $false )
            {
                $certaction = Read-Host "Please select an option";
            }
            # based on the action, do the right thing.
            if ( $certaction -eq "i" -or $certaction -eq "I" )
            {
                $hostVersionInfo = (get-host).Version.Major
                if ( $hostVersionInfo -lt "6" )
                {
                    psfivecerthandler
                }
                else 
                {
                    $GLOBAL:IGNOREAGMCERTS = "y"
                }
            }
            elseif ( $certaction -eq "c" -or $certaction -eq "C" )
            {
                # just exit
                return;
            }
        }
    }




    if (!($passwordfile))
    {
        if (!($agmpassword))
        {
            # prompt for a password
            [SecureString]$passwordenc = Read-Host -AsSecureString "Password";
        }
        else
        {
            [SecureString]$passwordenc = (ConvertTo-SecureString $agmpassword -AsPlainText -Force)
        }
    }
    else
    {
        # if the password file provided is relative or absolute doesn't matter. Test for it first
        if ( Test-Path $passwordfile )
        {
            [SecureString]$passwordenc = Get-Content $passwordfile | ConvertTo-SecureString;
        }
        else
        {
            Get-AGMErrorMessage -messagetoprint "Password file: $passwordfile could not be opened."
            return;
        }
    }

    $Url = "https://$agmip/actifio/session"
    $creds = New-Object System.Management.Automation.PSCredential ("$agmuser", $passwordenc)

    $RestError = $null
    Try
    {
        $hostVersionInfo = (get-host).Version.Major
        if ( $hostVersionInfo -lt "6" )
        {
            $resp = Invoke-RestMethod -Method POST -Uri $Url -Credential $creds -TimeoutSec 60
        }
        else 
        {
            $resp = Invoke-RestMethod -SkipCertificateCheck -Method POST -Uri $Url -Credential $creds -TimeoutSec 60
        }
    }
    Catch
    {
        $RestError = $_
    }
    if ($RestError -like "The operation was canceled.")
    {
        Get-AGMErrorMessage -messagetoprint "No response was received from $agmip after 60 seconds"
        return;
    }
    elseif ($RestError -like "Connection refused")
    {
        Get-AGMErrorMessage -messagetoprint "Connection refused received from $agmip"
        return;
    }
    elseif ($RestError)
    {
        $loginfailedsniff = Test-AGMJSON $RestError
        if ($loginfailedsniff.err_code -eq "10011")
        {
            $agmerror = @()
            $agmerrorcol = "" | Select-Object err_code,errormessage
            [int]$agmerrorcol.err_code = "10011"
            $agmerrorcol.errormessage = "Login failed.  Check your username and password."
            $agmerror = $agmerror + $agmerrorcol
            $agmerror
            return
        }
        elseif ($loginfailedsniff.errorcode -eq "10017")
        {
            $agmerror = @()
            $agmerrorcol = "" | Select-Object err_code,errormessage
            [int]$agmerrorcol.err_code = "10017"
            $agmerrorcol.errormessage = "Login failed.  You appear to be logging into a VDP Appliance, rather than an AGM."
            $agmerror = $agmerror + $agmerrorcol
            $agmerror
            return
        }
        else
        {
            $loginfailedsniff
            return
        }
    }
    else
    {
        $GLOBAL:AGMSESSIONID = $resp.session_id
        $GLOBAL:AGMIP = $agmip
        $GLOBAL:AGMTimezone = "local"
        $GLOBAL:AGMTIMEOUT = $agmtimeout
        if ($quiet)
        {
            return
        }
        elseif ($printsession)
        {
            Write-Host "$agmsessionid"
            return
        }
        else 
        {
            Write-Host "Login Successful!"
            return
        }
    }
}

function Disconnect-AGM
{
    <#  
    .SYNOPSIS
    Connects to AGM to delete a Session ID

    .DESCRIPTION
    The Disconnect-AGM connects to AGM to delete a session ID

    .NOTES
    Written by Anthony Vandewerdt

    .EXAMPLE
    Disconnect-AGM
    

    #>


    Param([switch][alias("q")]$quiet,[switch][alias("p")]$printsession)


    if ( (!($AGMSESSIONID)) -or (!($AGMIP)) )
    {
        Get-AGMErrorMessage -messagetoprint "Not logged in or session expired. Please login using Connect-AGM"
        return
    }
    
    $RestError = $null
    Try
    {
        if ($GLOBAL:IGNOREAGMCERTS)
        {
            $resp = Invoke-RestMethod -Method DELETE -SkipCertificateCheck -Headers @{ Authorization = "Actifio $AGMSESSIONID" } -Uri "https://$AGMIP/actifio/session/$AGMSESSIONID"
        }
        else 
        {
            if ($AGMToken)
            {
                $resp = Invoke-RestMethod -Method DELETE -Headers @{ Authorization = "Bearer $AGMToken"; "backupdr-management-session" = "Actifio $AGMSESSIONID" } -Uri "https://$AGMIP/actifio/session/$AGMSESSIONID"
            }
            else 
            {
                $resp = Invoke-RestMethod -Method DELETE -Headers @{ Authorization = "Actifio $AGMSESSIONID" } -Uri "https://$AGMIP/actifio/session/$AGMSESSIONID"
            }
        }
    }
    Catch
    {
        $RestError = $_
    }
    if ($RestError) 
    {
        Test-AGMJSON "$RestError"
    }
    else
    {
        if ($quiet)
        {
            $GLOBAL:AGMSESSIONID = ""
            return
        }
        elseif ($printsession) 
        {
            Write-Host "Successfully deleted session ID $AGMSESSIONID"   
            $GLOBAL:AGMSESSIONID = ""
            return         
        }
        else 
        {
            Write-Host "Success!"   
            $GLOBAL:AGMSESSIONID = ""
            return 
        }
    }
} 

Function Save-AGMPassword([string]$filename,[string]$password)
{
	<#
	.SYNOPSIS
	Save credentials so that scripting is easy and interactive login is no longer needed.

	.EXAMPLE
	Save-AGMPassword -filename admin-pass.key
	Save the password for use later.

    .EXAMPLE
    Save-AGMPassword -filename ./5b-admin-pass -password "passw0rd"
    Save the specified plaintext password to the specified file name

	.DESCRIPTION
	Store the credentials in a file which can be used to login to AGM.

	Providing a AGM IP and a AGM User will prompt for a password which will then be 
	stored in the file location provided.

	To change the credentials, simply re-run the cmdlet.

	.PARAMETER filename
	Required. Absolute or relative location where the file should be saved. 
	example: .\actpass
	example: C:\Users\admin\actpass

    #>


	# if no file is provided, prompt for one
	if (!($filename))
	{
		$filename = Read-Host "Filename";
	}

	# if the filename already exists. don't overwrite it. error and exit.
	if ( Test-Path $filename ) 
	{
		Get-AGMErrorMessage -messagetoprint "The file: $filename already exists. Please delete it first.";
		return;
	}

	# prompt for password 
    if (!($password))
    {
	    $passwordenc = Read-Host -AsSecureString "Password"
	    $passwordenc | ConvertFrom-SecureString | Out-File $filename
    }
    else 
    {
        $passwordenc = $password | ConvertTo-SecureString -AsPlainText -Force
        $passwordenc | ConvertFrom-SecureString | Out-File $filename
    }


	if ( $? )
	{
		write-host "Password saved to $filename."
		write-host "You may now use -passwordfile with Connect-AGM to provide a saved password file."
	}
	else 
	{
		Get-AGMErrorMessage -messagetoprint "An error occurred in saving the password";
	}
}



# offer a way to limit the maximum number of results in a single lookup
function Set-AGMAPILimit([Parameter(Mandatory = $true)]
[ValidateRange(0, [int]::MaxValue)][int]$userapilimit )
{
     <#  
    .SYNOPSIS
    Offers a way to globally limit the number of objects returned by any API get request.

    .DESCRIPTION
    The AGM GUI by default displays a fixed number of objects per page,  limiting the amount of data fetched when a page is displayed.
    By default the PowerShell module will get every object available for the Get being used, unless the user specifies a limit with that get command.
    For object types like job history this can result in possibly millions of objects (jobs) being returned.
    So if you are exploring the API then setting a global limit can allow you to issue gets without concern about how many objects will be fetched.

    .NOTES
    Written by Anthony Vandewerdt

    .EXAMPLE
    Set-AGMAPILimit 10
    This means that every Get command supplied by the base module will only return 10 objects maxium, unless the -limit option is used
 
    .EXAMPLE
    Set-AGMAPILimit 0
    This resets the global limit to 0 which is unlimited, meaning AGM will return every object that it has for the relevant Get.

    #>

    $GLOBAL:agmmaxapilimit = $userapilimit
}

function Get-AGMAPILimit
{
    $agmmaxapilimit
}


# offer a way to control timezone used in output.  By default we use User local time for all data
function Set-AGMTimeZoneHandling ([switch][alias("l")]$local,[switch][alias("u")]$utc)
{
     <#  
    .SYNOPSIS
    Offers a way to change which timezone timestamps are shown in.

    .DESCRIPTION
    By default the PowerShell module shows all timestamp in the local timezone of the powershell session.   
    You can validate which timezone that is with:  Get-TimeZone
    You can validate whether the AGM Module is using local or UTC with:  Get-AGMTimeZoneHandling

    .NOTES
    Written by Anthony Vandewerdt

    .EXAMPLE
    Set-AGMTimeZoneHandling -l
    Show all timestamps in the local timezone of the PowerShell session.
 
    .EXAMPLE
    Set-AGMTimeZoneHandling -u
    Show all timestamps in UTC (GMT).

    #>
    if ((!($local)) -and (!($utc)))
    {
        Get-AGMErrorMessage -messagetoprint "Please specify either -local or -utc"
    }



    if ($utc)
    {
        $GLOBAL:AGMTimezone = "UTC"
    }
    if ($local)
    {
        $GLOBAL:AGMTimezone = "local"
    }
}

function Get-AGMTimeZoneHandling 
{
    <#  
    .SYNOPSIS
    Offers a way to display how timezones are being handled.

    .DESCRIPTION
    By default the PowerShell module shows all timestamp in the local timezone of the powershell session.   
    You can validate which timezone that is with:  Get-TimeZone
    You can change whether the AGM Module is using local or UTC with:  Set-AGMTimeZoneHandling

    .NOTES
    Written by Anthony Vandewerdt

    .EXAMPLE
    Get-AGMTimeZoneHandling
    Show whether the AGM Module is using local or UTC
 
    #>

    if (($AGMTimezone -eq "local") -or (!($AGMTimezone)))
    {
        $currentlocal = Get-TimeZone
        Write-Host "Currently timezone in use is local timezone which is $currentlocal"
    }
    else 
    {
        Write-Host "Currently timezone in use is $GLOBAL:AGMTimezone"
    }
}

function Get-GoogleCloudBackupDRConsole ([string]$project,[string]$location)
{
    <#  
    .SYNOPSIS
    Displays details of Google Cloud Backup and DR Management Console

    .DESCRIPTION
    The user needs to specify a project ID and region

    .NOTES
    Written by Anthony Vandewerdt

    .EXAMPLE
    Get-GoogleCloudBackupDRConsole -project project1 -location asia-southeast1
 
    #>

    if (!($project))
    {
        Get-AGMErrorMessage -messagetoprint "Please specify project with -project"
    }
    if (!($location))
    {
        Get-AGMErrorMessage -messagetoprint "Please specify -location"
    }
    
    Try
    {
        $resp = Invoke-RestMethod -Method GET -Headers @{ Authorization = "Bearer $(gcloud auth print-access-token)" } -Uri "https://backupdr.googleapis.com/v1/projects/$project/locations/$location/managementServers"
    }
    Catch
    {
        $RestError = $_
    }
    if ($RestError) 
    {
        Test-AGMJSON "$RestError"
    }
    elseif ($resp.managementServers)
    {
        $resp.managementServers
    }
}

<#
.SYNOPSIS
Log into the vCenter.
This function will read the password from the masked standard input or a specified password file. You can use `Save-vCenterPassword` before calling this function.
If the specified password file does not exist, it will prompt to ask the password and save the inputed password into the password file.

.EXAMPLE
Connect-vCenter -vCenterHostName abcd-112233.e123abc45.southamerica-east1.abc.com -User user-01@abc.com -PassFilePath '.vcenter_pass'

# If .vcenter_pass does not exists, will prompt
Password: ************

.EXAMPLE
Save-vCenterPassword -FileName '.vcenter_pass'
Connect-vCenter -vCenterHostName abcd-112233.e123abc45.southamerica-east1.abc.com -User user-01@abc.com -PassFilePath '.vcenter_pass'

.EXAMPLE
Connect-vCenter -vCenterHostName abcd-112233.e123abc45.southamerica-east1.abc.com -User user-01@abc.com

.EXAMPLE
Connect-vCenter -vCenterHostId 6880886 -User user-01@abc.com
#>
function Connect-vCenter {
    [CmdletBinding()]
    param (
        # The host name of the vCenter, e.g. abcd-112233.e123abc45.southamerica-east1.abc.com
        [Parameter(Mandatory = $true, ParameterSetName = "LogInByHostName")]
        [string]
        $vCenterHostName,

        # The `id` of the vCenter host, you can find the `id` by `(Get-AGMHost -filtervalue "isvcenterhost=true") | Select-Object id,name`
        [Parameter(Mandatory = $true, ParameterSetName = "LogInByHostId")]
        [int]
        $vCenterId,

        # The user name for logging into the vCenter
        [Parameter(Mandatory = $true, ParameterSetName = "LogInByHostName")]
        [Parameter(Mandatory = $true, ParameterSetName = "LogInByHostId")]
        [string]
        $UserName,

        # File that saves the encrypted password
        [Parameter(Mandatory = $false)]
        [string]
        $PassFilePath
    )

    # If specified vCenterId, we will try to find the host name by this parameter
    if ($vCenterId) {
        $vCenterHostName = Find-vCenterHostName $vCenterId
    }

    Write-Output "Connecting vCenter, hostname: $vCenterHostName, user: $UserName"
    
    # Clean up the stale server configuration
    # `Invoke-CreateSession` will fail if we don't perform this step since the user credentials will be cleared after
    # retrieving the api session.
    Disconnect-vCenter

    try {
        # Check if the user passes -PassFilePath option,
        # If uses, read from the password file if exists, otherwise prompt for password and save it into the `PassFilePath`
        # If not uses, read the password from the standard input
        if ($PassFilePath) {
            if (Test-Path $PassFilePath) {
                $password_enc = Get-Content $PassFilePath | ConvertTo-SecureString;
            }
            else {
                $password_enc = Save-vCenterPassword -FileName $PassFilePath
            }
        }
        else {
            # Read credentials from the standard input
            $password_enc = Read-Host -AsSecureString -Prompt "Password"
        }

        # Create vSphere Server Configuration with the provided Credentials.
        $serverConfiguration = New-vSphereServerConfiguration -Server $vCenterHostName -User $UserName -Password $password_enc

        # Creates a Session with the vSphere API if we don't have a session.
        $apiSession = Invoke-CreateSession -WithHttpInfo -ErrorAction Stop

        # Set the API Key in the vSphere Server Configuration, received with the API Session.
        # This step will celar the user credentials and will only keep the API Session ID
        $serverConfiguration = $serverConfiguration | Set-vSphereServerConfigurationApiKey -SessionResponse $apiSession

        Write-Output "vCenter connected"
    }
    catch {
        Write-Error "Failed to connect to the vCenter, please double check the credentials."
    }
}

<#
.SYNOPSIS
Disconnect from vCenter and delete the API session. You will need to call `Connect-vCenter` next time.
#>
function Disconnect-vCenter {
    $serverConfiguration = Get-vSphereServerConfiguration
    if ($null -ne $serverConfiguration) {
        Remove-vSphereServerConfiguration $serverConfiguration
    }
}

<#
.SYNOPSIS
Encrypt and save the password of the vCenter into a file.
#>
function Save-vCenterPassword {
    [CmdletBinding()]
    param (
        # Absolute or relative location where the file should be saved.
        [Parameter(Mandatory = $true)]
        [string]
        $FileName,

        # Encrypted password
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [SecureString]
        $PasswordEnc
    )

    # if no file is provided, prompt for one
    if (!$FileName) {
        $FileName = Read-Host "File Name";
    }

    # if the filename already exists. don't overwrite it. error and exit.
    if ( Test-Path $FileName ) {
        Get-AGMErrorMessage -messagetoprint "The file: $FileName already exists. Please delete it first.";
        return;
    }

    # prompt for password 
    if (!($PasswordEnc)) {
        $PasswordEnc = Read-Host -AsSecureString "Password"
    }
    
    try {
        $PasswordEnc | ConvertFrom-SecureString | Out-File $FileName -ErrorAction Stop

        Write-Host "Password saved to $FileName."
        Write-Host "You may now use -PassFilePath with `Connect-vCenter` to provide a saved password file."

        return $PasswordEnc
    }
    catch {
        Get-AGMErrorMessage -messagetoprint "An error occurred in saving the password"
    }
}