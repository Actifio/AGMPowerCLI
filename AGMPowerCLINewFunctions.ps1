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

Function New-AGMAppDiscovery ([string]$hostid,[string]$ipaddress,[string]$applianceid) 
{
    <#
    .SYNOPSIS
    Runs discovery against a host 

    .EXAMPLE
    New-AGMAppDiscovery -hostid 5678 -applianceid 1415071155
    
    Runs application discovery against the host with ID 5678 for appliance with ID 1415071155

    .DESCRIPTION
    A function to run application discovery

    #>

    if ((!($hostid)) -and (!($ipaddress)))
    {
        [string]$hostid = Read-Host "Host to perform discovery on (press enter to use IP)"
        if (!($hostid))
        {
            [string]$ipaddress = Read-Host "Host IP to perform discovery on"
        }
    }
    
    if (!($applianceid))
    {
        [string]$applianceid = Read-Host "Appliance to perform discovery on"
    }
    
    if ($hostid)
    {
        $body = [ordered]@{
            host = [ordered]@{
                id=$hostid
                sources= @(
                    @{ 
                        clusterid=$applianceid
                    }
                )
            }
        }
    }
    if ($ipaddress)
    {
        $body = [ordered]@{
            cluster=$applianceid;
            type="standard";
            ipaddress=$ipaddress
        }
    }

    $jsonbody = $body | ConvertTo-Json -depth 4

    Post-AGMAPIData  -endpoint /host/discover -body $jsonbody
}

Function New-AGMAppliance ([string]$ipaddress,[string]$username,[string]$password,[SecureString]$passwordenc,[switch]$dryrun) 
{
    <#
    .SYNOPSIS
    Adds a new appliance to AGM

    .EXAMPLE
    New-AGMAppliance ipaddress 10.194.0.38 -username admin -password password -dryrun | select-object approvaltoken,cluster,report
    This performs a dryrun to test if Appliance add will work.   Pay close attention to the errcode in the report field and that the cluster field contains a clusterid.
    You also need to see an approval token.    If everything looks good, run the command again without specifying -dryrun
    If you are feeling lucky you can choose to skip running the command without -dryrun

    .EXAMPLE
    New-AGMAppliance ipaddress 10.194.0.38 -username admin -password password
    This adds the Appliance and includes a dryrun.   
    After it runs, then run Get-AGMAppliance to confirm the appliance has been added.
    
    .DESCRIPTION
    A function to add Appliances
    
    For password handling there are two parameters you can use:
    -password     This is the Appliance password in plain text
    -passwordenc  This is the Appliance password as a secure string.  This can be used with Powershell 7
    If you don't use either parameter you will be prompted to enter the password in a secure fashion. This can be used with Powershell 7

    #>

    if (!($ipaddress))
    {
        [string]$ipaddress = Read-Host "Appliance IP Address"
    }
    
    if (!($username))
    {
        [string]$username = Read-Host "Appliance username"
    }

    if ((!($password)) -and (!($passwordenc)))
    {
        # prompt for a password
        [SecureString]$passwordenc = Read-Host "Password" -AsSecureString
        [string]$password = (Convertfrom-SecureString $passwordenc -AsPlainText)
    }
    if ($passwordenc)
    {
        [string]$password = (Convertfrom-SecureString $passwordenc -AsPlainText)
    }

    $body = [ordered]@{
        ipaddress=$ipaddress;
        username=$username;
        password=$password
    }
    $jsonbody = $body | ConvertTo-Json 

    $dryrungrab = Post-AGMAPIData  -endpoint /cluster/dryrun -body $jsonbody
    if ($dryrun)
    {
        $dryrungrab
        return
    }

    if ($dryrungrab.approvaltoken)
    {
        $body = [ordered]@{
            ipaddress=$ipaddress;
            username=$username;
            password=$password;
            approvaltoken=$dryrungrab.approvaltoken
        }
        $jsonbody = $body | ConvertTo-Json 
        Post-AGMAPIData  -endpoint /cluster -body $jsonbody
    }
    else {
        $dryrun
    }
}



Function New-AGMCloudVM ([string]$zone,[string]$id,[string]$credentialid,[string]$clusterid,[string]$applianceid,[string]$projectid,[string]$instanceid) 
{
    <#
    .SYNOPSIS
    Adds new Cloud VMs

    .EXAMPLE
    New-AGMCloudVM -credentialid 1234 -zone australia-southeast1-c -clusterid 144292692833 -instanceid 4240202854121875692

    Adds VM with ID 4240202854121875692 to specified appliance 

    .DESCRIPTION
    A function to add Cloud VMs
    Multiple vmids should be comma separated

    #>


    if (($applianceid) -and ($clusterid))
    {
        Get-AGMErrorMessage -messagetoprint "Do not specify both applianceid and clusterid. Only clusterid is neeeed."
        return
    }
    if ($id) { $credentialid = $id }
    if (!($credentialid))
    {
        [string]$credentialid = Read-Host "Credential ID"
    }

    if ($applianceid) { [string]$clusterid = $applianceid}

    if (!($clusterid))
    {
        $clusterid = Read-Host "Cluster ID"
    }
    if (!($projectid))
    {
        [string]$projectid = Read-Host "Project ID"
    }   

    #if user doesn't specify name and zone, then learn them
    $credentialgrab = Get-AGMCredential -credentialid $credentialid
    if (!($credentialgrab.id))
    {
        if ($credentialgrab.errormessage)
        {
            $credentialgrab
        }
        else 
        {
            Get-AGMErrorMessage -messagetoprint "The credential ID $credentialid could not be found using Get-AGMCredential"
        }
        return
    } else {
        if (!($zone))
        {
            $zone = $credentialgrab.region
        }
    }

    if (!($zone))
    {
        [string]$zone = Read-Host "Zone Name"
    } 
    if (!($instanceid))
    {
        [string]$instanceid = Read-Host "Instance IDs (Comma separated)"
    } 

    $cluster = @{ clusterid = $clusterid}
    $body = [ordered]@{}
    if ($AGMToken)
    {
        $body += @{ cluster = $cluster;
        region = $zone;
        listonly = $false;
        vmids = $($instanceid.Split(","))
        projectid = $projectid;
        }
    }
    else 
    {
        $body += @{ cluster = $cluster;
            region = $zone;
            listonly = $false;
            vmids = $($instanceid.Split(","))
            project = $projectid;
            }
    }



    $json = $body | ConvertTo-Json
    
    Post-AGMAPIData  -endpoint /cloudcredential/$credentialid/discovervm/addvm -body $json
}


Function New-AGMConsistencyGroup ([string]$clusterid,[string]$applianceid,[string]$hostid,[string]$description,[string]$groupname) 
{
    <#
    .SYNOPSIS
    Adds new Consistency Group (CG)

    .EXAMPLE
    New-AGMConsistencyGroup -clusterid 144292692833 -groupname "prodhost1" -description "this is a CG" -hostid 12344

    To learn applianceid, use this command:  Get-AGMAppliance and use the clusterid as clusterid. 
    To learn host ID, use this command:  Get-AGMHost
    
    Once you have created the Consistency Group you can add applications to it with Set-AGMConsistencyGroupMember 
    Once you have created the Consistency Group you can change the name and description with Set-AGMConsistencyGroup

    .DESCRIPTION
    A function to add a Consistency Group 

    #>
    
    if (($applianceid) -and ($clusterid))
    {
        Get-AGMErrorMessage -messagetoprint "Do not specify both applianceid and clusterid. Only clusterid is needed."
        return
    }

    if ($applianceid) { [string]$clusterid = $applianceid}

    if (!($clusterid))
    {
        $clusterid = Read-Host "Cluster ID"
    }
    if (!($hostid))
    {
        [string]$hostid = Read-Host "Host ID"
    }   
    if (!($groupname))
    {
        [string]$groupname = Read-Host "Group Name"
    }

    # cluster needs to be like:  sources":[{"clusterid":"144488110379"},{"clusterid":"143112195179"}]
    $sources = @()
    foreach ($cluster in $clusterid.Split(","))
    {
        $sources += [ordered]@{ id = $cluster }
    } 

    #  {"groupname":"testme","description":"description","cluster":{"id":"70194"},"host":{"id":"70631"}}
    
    $body = [ordered]@{}
    $body += [ordered]@{ groupname = $groupname;
    cluster = $sources;
    host = [ordered]@{ id = $hostid }
    }
    if ($description)
    { 
        $body += @{ description = $description }
    }

    $json = $body | ConvertTo-Json

    Post-AGMAPIData  -endpoint /consistencygroup -body $json 
}


Function New-AGMCredential ([string]$name,[string]$zone,[string]$clusterid,[string]$applianceid,$filename,[string]$projectid,[string]$organizationid,[string]$udsuid) 
{
    <#
    .SYNOPSIS
    Creates a cloud credential

    .EXAMPLE
    This is an example for release 11.0.1
    New-AGMCredential -name cred1 -zone australia-southeast1-c -clusterid 144292692833 -filename keyfile.json

    .EXAMPLE
    This is an example for release 11.0.2
    New-AGMCredential -name cred1 -zone australia-southeast1-c -clusterid 145666187717 -udsuid 1196377951

    To learn the Cluster ID, use this command and use the clusterid value: Get-AGMAppliance | select clusterid,name
    Comma separate the Cluster IDs if you have multiple appliances.  Note you cannot specify multiple appliances from release 11.0.2 or higher

    You can add org IDs with -organizationid     To learn the Org IDs, use this command:   
    Get-AGMOrg | select-object id,name
    Comma separate the Org IDs if you have multiple orgs

    To add an onvault pool, use -udsuid  
    To learn the udsid use this command:
    Get-AGMDiskPool -filtervalue pooltype=vault | select-object name,udsuid,@{N='appliancename'; E={$_.cluster.name}},@{N='applianceid'; E={$_.cluster.clusterid}}
    Ensure the pool exists on all the appliances you are adding the credential to.

    .DESCRIPTION
    A function to create cloud credentials

    #>

    if (($applianceid) -and ($clusterid))
    {
        Get-AGMErrorMessage -messagetoprint "Do not specify both applianceid and clusterid. Only clusterid is needed."
        return
    }
    if (!($name))
    {
        [string]$name = Read-Host "Credential Name"
    }
    if (!($zone))
    {
        [string]$zone = Read-Host "Default zone"
    }
    if ($applianceid) { [string]$clusterid = $applianceid}
    if (!($clusterid))
    {
        [string]$clusterid = Read-Host "Cluster IDs (comma separated)"
    }

    if ($filename)
    {
        if ( Test-Path $filename )
        {
            $jsonkey = Get-Content -Path $filename -raw
            $jsonkey = $jsonkey.replace("\n","\\n")
            $jsonkey = $jsonkey.replace("`n","\n ")
            $jsonkey = $jsonkey.replace('"','\"')
        }
        else
        {
            Get-AGMErrorMessage -messagetoprint "The file named $filename could not be found."
            return
        }
        if (!($projectid))
        {
            $jsongrab = Get-Content -Path $filename | ConvertFrom-Json
            if (!($jsongrab.project_id))
            {
                Get-AGMErrorMessage -messagetoprint "The file named $filename does not contain a valid project ID."
                return
            } else {
                $projectid = $jsongrab.project_id
            }
        }   
    }

    # cluster needs to be like:  sources":[{"clusterid":"144488110379"},{"clusterid":"143112195179"}] or "appliance":{"clusterid":"145666187717"}
    
   if ($filename) 
   {
        $sources = @()
        foreach ($cluster in $clusterid.Split(","))
        {
            $sources += [ordered]@{ clusterid = $cluster }
        }
    } 
    else
    {
        if ($clusterid.Split(",").count -gt 1)
        {
            Get-AGMErrorMessage -messagetoprint "From release 11.0.2 and higher please specify only one appliance at a time"
            return
        }
        $clusterdetails += [ordered]@{ clusterid = $clusterid }
    }
    $orglist = @()
    if ($organizationid)
    {
        foreach ($org in $organizationid.Split(","))
        {
            $orglist += [ordered]@{ id = $org }
        } 
    }
    $body = [ordered]@{}
    $body += [ordered]@{ name = $name;
    cloudtype = "GCP";
    region  = $zone;
    endpoint = "";
    orglist = $orglist
    }
    if ($sources)
    {
        $body += [ordered]@{ $projectid = $projectid }
        $body += [ordered]@{ sources = $sources }
    }
    if ($clusterdetails)
    {
        $body += [ordered]@{ appliance = $clusterdetails }
    }
    if ($udsuid)
    {
        $body += [ordered]@{ vault_udsuid = $udsuid }
    }

    $json = $body | ConvertTo-Json -compress
    # this section is post editing the JSON to add in the credential.  Ideally we should do this using a PS Object rather than an edit like this.
   if ($jsonkey)
    {
        $json = $json.Substring(0,$json.Length-1)
        $json = $json + ',"credential":"' + $jsonkey +'"}'
    }
    # first we test it
    $testcredential = Post-AGMAPIData  -endpoint /cloudcredential/testconnection -body $json
    if ($testcredential.errors)
    {
        $testcredential
        return
    }
    Post-AGMAPIData  -endpoint /cloudcredential -body $json
    
    return
}

Function New-AGMHost ([string]$clusterid,[string]$applianceid,[string]$hostname,[string]$friendlyname,[string]$description,[string]$ipaddress,[string]$alternateip,[string]$hosttype,[string]$organizationid,[string]$secret) 
{
    <#
    .SYNOPSIS
    Adds new Hosts

    .EXAMPLE
    New-AGMHost -clusterid 144292692833 -hostname "prodhost1" -ipaddress "10.0.0.1"

    Adds Host with name prodhost1 and IP address 10.0.0.1 to specified appliance 

    .EXAMPLE
    New-AGMHost -clusterid "143112195179,144488110379" -hostname "prodhost1" -ipaddress "10.0.0.1" -friendlyname "mainprod" -description "this is prod, be nice" -alternateip "20.0.0.1,30.0.0.1"

    Adds Host with name prodhost1 and IP address 10.0.0.1 to two specified appliances, with a friendlyname, text description and two alternate IPs.

    To learn applianceid, use this command:  Get-AGMAppliance and use the clusterid as clusterid.  If you have multiple clusterids, comma separate them
    alternateip needs to be a comma separated list of IPs


    .DESCRIPTION
    A function to add Hosts

    #>
    
    if (($applianceid) -and ($clusterid))
    {
        Get-AGMErrorMessage -messagetoprint "Do not specify both applianceid and clusterid. Only clusterid is needed."
        return
    }

    if ($applianceid) { [string]$clusterid = $applianceid}


    if (!($clusterid))
    {
        $clusterid = Read-Host "Cluster ID"
    }
    $clustergrab = Get-AGMAppliance -filtervalue clusterid=$clusterid
    if ($clustergrab.count -eq 0)
    {
        Get-AGMErrorMessage -messagetoprint "Clusterid $clusterid could not be found.  Validate clusterid with Get-AGMAppliance"
        return
    }


    if (!($hostname))
    {
        [string]$hostname = Read-Host "Host name"
    }   
    if (!($ipaddress))
    {
        [string]$ipaddress = Read-Host "IP Address"
    }  
    if (!($hostype))
    {
        $hosttype = "generic"
    }
    # cluster needs to be like:  sources":[{"clusterid":"144488110379"},{"clusterid":"143112195179"}]
    $sources = @()
    foreach ($cluster in $clusterid.Split(","))
    {
        $sources += [ordered]@{ clusterid = $cluster }
    } 
    if ($organizationid)
    {
        $orglist = @()
        foreach ($org in $organizationid.Split(","))
        {
            $orglist += [ordered]@{ id = $org }
        } 
    }
    
    # alternate IP format needs to be like:  "alternateip":["10.20.0.1","10.30.0.1"],
    if ($alternateip)
    {
        $alternateipaddresses = @( $($alternateip.Split(",")) )
    }
    else 
    {
        $alternateipaddresses = @()
    }
    $udsagent = [ordered]@{}
    if ($secret)
    {
        $udsagent += [ordered]@{ shared_secret = $secret }
    }
    $body = [ordered]@{}
    $body += [ordered]@{ hosttype = $hosttype;
    hostname = $hostname;
    ipaddress = $ipaddress;
    alternateip = $alternateipaddresses;
    sources = $sources;
    }
    if ($orglist)
    { 
        $body += @{ orglist = $orglist }
    }
    if ($description)
    { 
        $body += @{ description = $description }
    }
    if ($friendlyname)
    { 
        $body += @{ friendlypath = $friendlyname }
    }
    if ($secret)
    {
        $body += @{ udsagent = $udsagent }
    }

    $json = $body | ConvertTo-Json -compress

    Post-AGMAPIData  -endpoint /host -body $json 
}


Function New-AGMMount ([string]$imageid,[string]$targethostid,[string]$jsonbody,[string]$label) 
{
    <#
    .SYNOPSIS
    Mounts an Image

    .EXAMPLE
    New-AGMMount -imageid 1234 -targethostid 5678
    
    Mounts image ID 1234 to target host with ID 5678

    .EXAMPLE
    New-AGMMount -imageid 53776703 -jsonbody '{"@type":"mountRest","label":"test mount","host":{"id":"43673548"},"poweronvm":false,"migratevm":false}'
    
    Mounts image ID 53776703 to target host with ID 43673548 with Label "test mount".
    The jsonbody field needs to be well formed JSON.   You can get this by running a mount job in the AGM GUI and then immediately displaying the audit log with:
    Get-AGMAudit -filtervalue "command~POST https" -limit 1 -sort id:desc

    .DESCRIPTION
    A function to mount an Image

    #>

    if (!($imageid))
    {
        [string]$imageid = Read-Host "ImageID to mount"
    }

    if ( (!($jsonbody)) -and (!($targethostid)) )
    {
        [string]$targethostid = Read-Host "Target host ID to mount $imageid to"
        if (!($label))
        {
            [string]$label = Read-Host "Label to apply to newly mounted image"
        }
    }
    if ($targethostid)
    {
        $body = @{
            label = $label;
            host = @{id=$targethostid}
        }
        $jsonbody = $body | ConvertTo-Json
    }

    Post-AGMAPIData  -endpoint /backup/$imageid/mount -body $jsonbody
}



Function New-AGMSLA ([string]$appid,[string]$slpid,[string]$sltid,[string]$jsonbody,[string]$scheduler) 
{
    <#
    .SYNOPSIS
    Creates an SLA

    .EXAMPLE
    New-AGMSLA -appid 1234 -sltid 5678 -slpid 9012 -scheduler disabled
    
    Creates a new SLA using APPID, SLT ID and SLP ID with scheduler disabled.   
    Details about the new SLA will be returned.
    The scheduler is disabled so options can be set.  
    You can enable the scheduler with  Set-AGMSLA
    If no options are needed, you don't need to specify scheduler state

    .DESCRIPTION
    A function to create an SLA

    #>

    if (($id) -and (!($appid)) )
    {
        $appid = $id
    }
    if (!($sltid))
    {
        $sltid = Read-Host "SLT ID"
    }
    if (!($slpid))
    {
        $slpid = Read-Host "SLP ID"
    }
   

    if (!($jsonbody)) 
    {

        $application = New-Object -TypeName psobject
        $application | Add-Member -MemberType NoteProperty -Name id -Value $appid

        $slp = New-Object -TypeName psobject
        $slp | Add-Member -MemberType NoteProperty -Name id -Value $slpid
        
        $slt = New-Object -TypeName psobject
        $slt | Add-Member -MemberType NoteProperty -Name id -Value $sltid
        
        $body = New-Object -TypeName psobject
        $body | Add-Member -MemberType NoteProperty -name application -Value $application

        if (!($scheduler))
        {
            $body | Add-Member -MemberType NoteProperty -Name scheduleoff -Value "false"
        }

        if ($scheduler.ToLower() -eq "enable")
        {
            $body | Add-Member -MemberType NoteProperty -Name scheduleoff -Value "false"
        }
        if ($scheduler.ToLower() -eq "disable")
        {
            $body | Add-Member -MemberType NoteProperty -Name scheduleoff -Value "true"
        }
        $body | Add-Member -MemberType NoteProperty -name slp -Value $slp
        $body | Add-Member -MemberType NoteProperty -name slt -Value $slt

        $jsonbody = $body | ConvertTo-Json
    }

    Post-AGMAPIData  -endpoint /sla -body $jsonbody
}

Function New-AGMUser ([string]$name,[string]$timezone,[string]$rolelist,[string]$orglist) 
{
    <#
    .SYNOPSIS
    Creates a User

    .EXAMPLE
    New-AGMUser -name "user@user.user" -rolelist "2,3" -orglist "4,5"

    Creates a new user

    .DESCRIPTION
    A function to create a User

    #>

    if (!($name))
    {
        Get-AGMErrorMessage -messagetoprint "Specify a username in email format with -name"
        return
    }

    if ($AGMToken)
    {
        if ($name -notlike "*@*") 
        { 
            Get-AGMErrorMessage -messagetoprint "Specify a username in email format with -name"
            return
        }
    }

    if (!($rolelist))
    {
        Get-AGMErrorMessage -messagetoprint "Specify a comma separated rolelist with -rolelist"
        return
    }
    if ($rolelist)
    {
        $rolebody = @()
        foreach ($role in $rolelist.Split(","))
        {   
            $rolebody += New-Object -TypeName psobject -Property @{id="$role"}
        }
    }
    if ($orglist)
    {
        $orgbody = @()
        foreach ($org in $orglist.Split(","))
        {   
            $orgbody += New-Object -TypeName psobject -Property @{id="$org"}
        }
    }
   $body = [ordered]@{
        name = $name;
        dataaccesslevel = "0";
        timezone = $timezone;
        rolelist = $rolebody
        orglist = $orgbody
    }
    $jsonbody = $body | ConvertTo-Json

    Post-AGMAPIData  -endpoint /user -body $jsonbody
}

<#
.SYNOPSIS
Discover VMWare VMs through AGM

.EXAMPLE
New-AGMVMDiscovery -vCenterId 6880886
#>
function New-AGMVMDiscovery {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [int]
        $vCenterId
    )

    Get-AGMAPIData -endpoint "/host/$vCenterId/discovervm"
}

<#
.SYNOPSIS
Create a new application for a VMWare VM.

.EXAMPLE
New-AGMVMApp -vCenterId 7550156 -Cluster 6019 -ClusterName cluster_foo -VmUuids ["91cd1ae2-9fbe-16bf-de71-f1577ab0a1b3"]
#>
function New-AGMVMApp {
    [CmdletBinding()]
    param (
        # The `id` of the vCenter host, you can find the `id` by `(Get-AGMHost -filtervalue "isvcenterhost=true") | Select-Object id,name`
        [Parameter(Mandatory = $true)]
        [int]
        $vCenterId,

        # The `id` of an appliance, it is NOT the `appliance_id`, you can get the appliance by `Get-AGMAppliance`
        [Parameter(Mandatory = $true)]
        [int]
        $Cluster,

        # The `clustername` of a cluster, you can get the cluster name by `Get-AGMClusterName -vCenterId <your-vcenter-id>`
        [Parameter(Mandatory = $true)]
        [string]
        $ClusterName,

        # The UUIDs of those VMs to be protected, UUIDs are included in the response of `New-AGMVMDiscovery`
        [Parameter(Mandatory = $true)]
        [string[]]
        $VmUuids
    )

    $body = [ordered]@{
        cluster=$Cluster;
        addvms=$true;
        vms=$VmUuids;
    }
    $json = $body | ConvertTo-Json

    Write-Verbose "New-AGMVMApp"
    Write-Verbose "/host/$vCenterId/host/$ClusterName/addvms" 
    Write-Verbose $json

    Post-AGMAPIData -endpoint "/host/$vCenterId/host/$ClusterName/addvms" -body $json
}