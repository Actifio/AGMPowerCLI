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

Function Set-AGMApplianceParameter ([string]$id,[String]$applianceid,[string]$clusterid,[string]$parameter,[string]$value)
{
    <#  
    .SYNOPSIS
    Set parameter on an Appliance

    .EXAMPLE
    Set-AGMApplianceParameter -id 7188 -parameter maxsnapslots -value 8
    Sets the value of maxsnapslots to 8 on the appliance with ID 7188
    Note that no value gets returned.   To validate you would need to then run:
    Get-AGMApplianceParameter -id 7188 -parameter maxsnapslots

    .NOTES
    Written by Anthony Vandewerdt
    
    #>

    if ( (!($AGMSESSIONID)) -or (!($AGMIP)) )
    {
        Get-AGMErrorMessage -messagetoprint "Not logged in or session expired. Please login using Connect-AGM"
        return
    }

    if ($clusterid) { $applianceid = $clusterid }
    if ($applianceid)
    {
        $appliancegrab = Get-AGMAppliance -filtervalue clusterid=$applianceid
    }
    if ($id)
    {
        $appliancegrab = Get-AGMAppliance -filtervalue id=$id
    }
    if (!($appliancegrab.clusterid))
    {
        Get-AGMErrorMessage -messagetoprint "Failed to find specified appliance.   Run Get-AGMAppliance and then specify the value listed as id with the -id parameter"
        return
    }
    else
    {
        $id = $appliancegrab.id
    }
    if (!($id))
    {
        $id = Read-Host "ID (for the Appliance)"
    }
    if (!($parameter))
    {
        [string]$parameter = Read-Host "Parameter name"
    }
    if (!($value))
    {
        [string]$value = Read-Host "Parameter value"
    }

    Post-AGMAPIData -endpoint /cluster/$id/parameter -extrarequests "param=$parameter&value=$value" -zerolength
}

Function Set-AGMApplianceSchedule ([string]$id,[String]$applianceid,[string]$clusterid,[string]$schedulename,[string]$day,[string]$frequency,[string]$op,[string]$repeatinterval,[string]$time)
{
    <#  
    .SYNOPSIS
    Set schedule on an Appliance using the ID of the Appliance

    .EXAMPLE
    Set-AGMApplianceSchedule -id 7188 -schedulename "autodiscovery" -frequency "daily"  -time "12:00"

    Set the autodiscovery schedule to run daily at 12:00 UTC
    Note that no data is returned, so to validate, you should then run:
    Get-AGMApplianceSchedule -id 7188 -schedulename "autodiscovery"

    .NOTES
    Written by Anthony Vandewerdt
    
    #>

    if ( (!($AGMSESSIONID)) -or (!($AGMIP)) )
    {
        Get-AGMErrorMessage -messagetoprint "Not logged in or session expired. Please login using Connect-AGM"
        return
    }

    if ($clusterid) { $applianceid = $clusterid }
    if ($applianceid)
    {
        $appliancegrab = Get-AGMAppliance -filtervalue clusterid=$applianceid
    }
    if ($id)
    {
        $appliancegrab = Get-AGMAppliance -filtervalue id=$id
    }
    if (!($appliancegrab.clusterid))
    {
        Get-AGMErrorMessage -messagetoprint "Failed to find specified appliance.   Run Get-AGMAppliance and then specify the value listed as id with the -id parameter"
        return
    }
    else
    {
        $id = $appliancegrab.id
    }
    if (!($id))
    {
        $id = Read-Host "ID (for the Appliance)"
    }

    if (!($schedulename))
    {
        [string]$schedulename = Read-Host "Schedule name"
    }
    if (!($repeatinterval)) { $repeatinterval = 1 }
    $body = [ordered]@{}
    $body += [ordered]@{ name = $schedulename }
    if ($day) { $body += [ordered]@{ day = $day } }
    if ($frequency) { $body += [ordered]@{ frequency = $frequency } }
    if ($op) { $body += [ordered]@{ op = $op } }
    if ($repeatinterval) { $body += [ordered]@{ repeat_interval = $repeatinterval } }
    if ($time) { $body += [ordered]@{ time = $time } }
    $json = $body | ConvertTo-Json

    Post-AGMAPIData -endpoint /cluster/$id/schedule -body $json 
}

Function Set-AGMConsistencyGroup ([string]$clusterid,[string]$applianceid,[string]$groupid,[string]$groupname,[string]$description) 
{
    <#
    .SYNOPSIS
    A command to set the group name or description of a consistency group

    .EXAMPLE
    Set-AGMConsistencyGroup -applianceid 143112195179 -groupid "12345" -groupname "newname" -description "better description than the last one"

    To learn applianceid, use this command:  Get-AGMAppliance and use the clusterid as applianceid.  
    To learn groupid, use this command:  Get-AGMConsistencyGroup

    .DESCRIPTION
    A function to modify Consistency Groups

    #>
    
    if ($applianceid) { [string]$clusterid = $applianceid}

    if (!($clusterid))
    {
        $clusterid = Read-Host "Appliance ID"
    }
    if (!($groupid))
    {
        [string]$groupid = Read-Host "Group ID"
    }   
 
    # cluster needs to be like:  sources":[{"clusterid":"144488110379"},{"clusterid":"143112195179"}]
    $sources = @()
    foreach ($cluster in $clusterid.Split(","))
    {
        $sources += [ordered]@{ id = $cluster }
    } 

    # {"groupname":"teddybear","description":"WANT A BETTER","cluster":{"id":"70194"},"host":{},"id":"353953"}
    # {"groupname":"teddybear","description":"WANT A BETTER2","cluster":{"id":"70194"},"host":{"id":"70631"},"id":"353953"}

    $body = [ordered]@{}
    if ($description)
    { 
        $body += @{ description = $description }
    }
    if ($groupname)
    { 
        $body += @{ groupname = $groupname }
    }
    $body += [ordered]@{ cluster = $sources;
    id = $groupid 
    }
    $json = $body | ConvertTo-Json

    PUT-AGMAPIData  -endpoint /consistencygroup/$groupid -body $json 
}

Function Set-AGMConsistencyGroupMember ([string]$groupid,[switch]$add,[switch]$remove,[string]$applicationid) 
{
    <#
    .SYNOPSIS
    A command to set the members of a consistency group

    .EXAMPLE
    Set-AGMConsistencyGroupMember -groupid "12345" -add -applicationid "1234"
    To add application ID 1233 to groupid 12345

    .EXAMPLE
    Set-AGMConsistencyGroupMember -groupid "12345" -add -applicationid "1234,5678"
    To add application ID 1233 and 5678 to groupid 12345

     .EXAMPLE
    Set-AGMConsistencyGroupMember -groupid "12345" -remove -applicationid "1234"
    To remove application ID 1233 from groupid 12345

    To learn groupid, use this command:  Get-AGMConsistencyGroup
    To learn application ID, use this command: Get-AGMApplication

    .DESCRIPTION
    A function to modify Consistency Group members

    #>
    
    if (!($groupid))
    {
        [string]$groupid = Read-Host "Group ID"
    }    
    if ( (!($add)) -and (!($remove)) )
    {
        Get-AGMErrorMessage -messagetoprint "You need to specify either -add or -remove"
        return
    }
    if (($add) -and ($remove))
    {
        Get-AGMErrorMessage -messagetoprint "Do not specify add and remove at the same time"
        return
    }

    # [{"action":"add","members":[210645]}]
    # [{"action":"remove","members":[210647]}]
    # [{"action":"add","members":[210647,210645]}]

    $body1 = [ordered]@{}
    if ($add)
    {
        $json = '[{"action":"add","members":[' +$applicationid +']}]'
    }
    if ($remove)
    {
        $json = '[{"action":"remove","members":[' +$applicationid +']}]'
    }

    Post-AGMAPIData -endpoint /consistencygroup/$groupid/member -body $json 
}


Function Set-AGMCredential ([string]$name,[string]$zone,[string]$id,[string]$credentialid,[string]$clusterid,[string]$applianceid,$filename,[string]$projectid) 
{
    <#
    .SYNOPSIS
    Updates a cloud credential

    .EXAMPLE
    Set-AGMCredential -credentialid 1234 -name cred1 -zone australia-southeast1-c -clusterid 144292692833 -filename keyfile.json
    
    To update just the JSON file to the same appliances for credential ID 1234

    .EXAMPLE
    Set-AGMCredential -credentialid 1234 -name cred1 -zone australia-southeast1-c  -filename keyfile.json
    
    To update the JSON file and also the name and default zone for credential ID 1234

    .DESCRIPTION
    A function to update cloud credentials.   You need to supply the 

    #>

    if ($id) { $credentialid = $id }
    if (!($credentialid))
    {
        [string]$credentialid = Read-Host "Credential ID"
    }
    
    if ($applianceid) { [string]$clusterid = $applianceid}

    if (!($filename))
    {
        $filename = Read-Host "JSON key file"
    }
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
        if (!($name))
        {
            $name = $credentialgrab.name
        }
        if (!($zone))
        {
            $zone = $credentialgrab.region
        }
        if(!($clusterid))
        {
            $clusterid = $credentialgrab.sources.clusterid -join ","
        }
    }

    # convert credential ID into some nice JSON
    $sources = ""
    foreach ($cluster in $clusterid.Split(","))
    {
        $sources = $sources +',{"clusterid":"' +$cluster +'"}'
    }
    # this removes the leading comma
    $sources = $sources.substring(1)

    # we constuct our JSON first to run test
    $json = '{"name":"' +$name +'","cloudtype":"GCP","region":"' +$zone +'","endpoint":"","credential":"'
    $json = $json + $jsonkey
    $json = $json +'","orglist":[],"projectid":"' +$projectid +'",'
    $json = $json +'"sources":[' +$sources +']}'

    # if the test fails we error out
    $testcredential = Post-AGMAPIData  -endpoint /cloudcredential/testconnection -body $json
    if ($testcredential.errors)
    {
        $testcredential
        return
    }
    
    $json = '{"id":"' +$credentialid +'","name":"' +$name +'","cloudtype":"GCP","region":"' +$zone +'","endpoint":"","credential":"'
    $json = $json + $jsonkey
    $json = $json +'","orglist":[],'
    $json = $json +'"sources":[' +$sources +']}'

    Put-AGMAPIData  -endpoint /cloudcredential/$credentialid -body $json
}


function Set-AGMImage([string]$imagename,[string]$backupname,[string]$imageid,[string]$label,[string]$expiration)
{
    <#
    .SYNOPSIS
    Changes a nominated image

    .EXAMPLE
    Set-AGMImage -imagename Image_2133445 -label "testimage"
    Labels Image_2133445 with the label "testimage"

    .EXAMPLE
    Set-AGMImage -imagename Image_2133445 -expiration "2021-09-01"
    Sets the expiration date for Image_2133445 to 2021-09-01

    .DESCRIPTION
    A function to change images.

    #>

    if ((!($label)) -and (!($expiration)))
    {
        Get-AGMErrorMessage -messagetoprint "Please specify either a new label with -label, or a new expiration date with -expiration"
        return
    }

    if (($label) -and ($expiration))
    {
        Get-AGMErrorMessage -messagetoprint "Please specify either a new label with -label, or a new expiration date with -expiration.   Please don't specify both."
        return
    }

    if ($backupname) { $imagename = $backupname }
    if ((!($imagename)) -and (!($imageid)))
    {
        $imagename = Read-Host "ImageName"
    }
    if ($imageid)
    {
        $id = $imageid
    }

    if ($imagename)
    {
        $imagegrab = Get-AGMImage -filtervalue backupname=$imagename
        if ($imagegrab.id)
        {
            $id = $imagegrab.id
        }
        else 
        {
            Get-AGMErrorMessage -messagetoprint "Failed to find $imagename"
            return
        }
    }

    if ($label)  
    { 
        $body = @{label=$label} 
        $json = $body | ConvertTo-Json
    }
    if ($expiration)  
    {
        $unixexpiration = Convert-ToUnixDate $expiration
        $json = '{"@type":"backupRest","expiration":' +$unixexpiration + '}'
    }
    Put-AGMAPIData  -endpoint /backup/$id -body $json
}



Function Set-AGMHostPort ([string]$clusterid,[string]$applianceid,[string]$hostid,[string]$iscsiname) 
{
    <#
    .SYNOPSIS
    Adds new Host ports

    .EXAMPLE
    New-AGMHost -applianceid 143112195179 -hostid "12345" iscsiname "iqn1"

    Adds iSCSI port name iqn1 to host ID 105008 on appliance ID 143112195179

    To learn applianceid, use this command:  Get-AGMAppliance and use the clusterid as applianceid.  If you have multiple applianceIDs, comma separate them
    To learn hostid, use this command:  Get-AGMHost

    .DESCRIPTION
    A function to add Host ports

    #>
    
    if ($applianceid) { [string]$clusterid = $applianceid}

    if (!($clusterid))
    {
        $clusterid = Read-Host "Appliance ID"
    }
    if (!($hostid))
    {
        [string]$hostid = Read-Host "Host ID"
    }   
    if (!($iscsiname))
    {
        [string]$iscsiname = Read-Host "iSCSI Name"
    }  
    # cluster needs to be like:  sources":[{"clusterid":"144488110379"},{"clusterid":"143112195179"}]
    $sources = @()
    foreach ($cluster in $clusterid.Split(","))
    {
        $sources += [ordered]@{ clusterid = $cluster }
    } 
    $iscsiobject = @( $iscsiname )
    $body = [ordered]@{}
    $body += @{ sources = $sources;
        iscsi_name = $iscsiobject 
    }
    $json = $body | ConvertTo-Json

    Post-AGMAPIData  -endpoint /host/$hostid/port -body $json 
}

Function Set-AGMHostSecret ([string]$secret, [string]$hostid, [switch]$force) {
    <#
    .SYNOPSIS
    Updates a host with a new secret to establish trusted communication. 

    .EXAMPLE
    Set-AGMHostSecret -secret "do1rg334omavci24yqvczfp6x3v8ih5yvfnvrs8wtk3egdgupx4sqerw" -hostid "12345"

    To learn hostid, use this command:  Get-AGMHost
    
    A secret can be found after successful installation of the Google Backup and DR agent. A new secret can be created with the 
    following commands. 
    'udsagent secret --reset [--restart]' or 'udsagent.exe secret --reset [--restart]'

    .EXAMPLE
    If the host already has trusted communication, and the certificate is active, the caller will be prompted for overwriting current certificate.
    There is a force parameter that can be set to avoid this behavior. 

    Set-AGMHostSecret -secret "do1rg334omavci24yqvczfp6x3v8ih5yvfnvrs8wtk3egdgupx4sqerw" -hostid "12345" -force

    .DESCRIPTION
    A function to update an existing host with a secret for trusted communication. Requires the Google Backup and DR agent to be installed on the host
    #>
    if (!$secret) {
        [string]$secret = Read-Host "Secret"
    }
    if (!$hostid) {
        [string]$hostid = Read-Host "Host ID"
    }
    if (!$hostid) {
        Get-AGMErrorMessage -messagetoprint "Host ID is required. Run Get-AGMHost to learn host id for the available hosts."
        return
    }
    $body = Get-AGMHost -hostid $hostid
    if ($body.errormessage) {
        Get-AGMErrorMessage -messagetoprint $body.errormessage
        return
    }
    if ($body.pki_state -eq "TRUSTED" -and (-not $body.cert_revoked) -and (-not $force)) {
        Write-Host "This host appears to already have established trusted communications. Are you sure you want to re-initialize the trust relationship?"
        [string]$overWrite = Read-Host "(y/n)"
        if ($overWrite -ne "y") {
            Get-AGMErrorMessage -messagetoprint "Input was $overWrite. Host has not been updated."
            return
        }
    }
    $body.udsagent | Add-Member -Name "shared_secret" -Type NoteProperty -Value $secret
    $json = $body | ConvertTo-Json -Depth 100
    $response = Put-AGMAPIData -endpoint /host/$hostid -body $json
    if ($response.pki_errors) {
        # If PKI state is not applicable, return the error response
        $errorMessage = "Updating the secret failed. $($response.pki_errors)"
        # If PKI state is trusted but cert has been revoked, return error response and help message for resetting the secret.
        if ($response.cert_revoked) {
            $errorMessage += "Finally, if the certificate had previously been revoked, it will be necessary to reset the agent on the host 
            machine with the command 'udsagent secret --reset [--restart]' or 'udsagent.exe secret --reset [--restart]'. 
            Please note that restarting the agent is required, and will interrupt any running jobs."
        }
        Get-AGMErrorMessage -messagetoprint $errorMessage
        return
    }
    return $response
}



Function Set-AGMSLA ([string]$id,[string]$slaid,[string]$appid,[string]$logicalgroupid,[string]$dedupasync,[string]$expiration,[string]$logexpiration,[string]$scheduler) 
{
    <#
    .SYNOPSIS
    Enables or disables an SLA 
    Note that if both an SLA ID and an App ID are supplied, the App ID will be ignored.

    .EXAMPLE
    Set-AGMSLA -slaid 1234 -dedupasync disable 
    
    Disables dedupasync for SLA ID 1234.  

    .EXAMPLE
    Set-AGMSLA -slaid 1234 -expiration disable 
    
    Disables expiration for SLA ID 1234.  

    .EXAMPLE
    Set-AGMSLA -logicalgroupid 1235 -expiration disable 
    
    Disables expiration for Logical Group ID 1235 

    .EXAMPLE
    Set-AGMSLA -appid 5678 -expiration disable 
    
    Disables expiration for App ID 5678.   

    .EXAMPLE
    Set-AGMSLA -appid 5678 -logexpiration disable 
    
    Disables log expiration for App ID 5678.   

    .EXAMPLE
    Set-AGMSLA -slaid 1234 -scheduler enable 
    
    Enables the scheduler for SLA ID 1234.   

    .EXAMPLE
    Set-AGMSLA -slaid 1234 -scheduler disable 
    
    Disables the scheduler for SLA ID 1234.   


    .DESCRIPTION
    A function to modify an SLA

    #>

    if ( (!($AGMSESSIONID)) -or (!($AGMIP)) )
    {
        Get-AGMErrorMessage -messagetoprint "Not logged in or session expired. Please login using Connect-AGM"
        return
    }

    if ($id)
    {
        $slaid = $id
    }

    if (($appid) -and (!($slaid)))
    {
        $slaid = (Get-AGMSLA -filtervalue appid=$appid).id
        if (!($slaid))
        {
            Get-AGMErrorMessage -messagetoprint "Could not find an SLA ID for App ID $appid   Please use Get-AGMSLA to find the correct SLA ID or Get-AGMApplication to find the correct App ID"
            return
        }
    }

    if ($logicalgroupid)
    {
        $logicalgroupgrab = (Get-AGMLogicalGroup $logicalgroupid).sla
        if (!($logicalgroupgrab))
        {
            Get-AGMErrorMessage -messagetoprint "Could not find any SLA ID for Logical Group ID $logicalgroupid   Please use Get-AGMLogicalGroup to find the correct managed Group ID"
            return
        }
        $slpid = $logicalgroupgrab.slp.id
        $sltid = $logicalgroupgrab.slt.id
    }

    if ( (!($slaid)) -and (!($logicalgroupid)) )
    {
        Get-AGMErrorMessage -messagetoprint "No SLA ID or App ID or Logical Group ID was supplied.  Please either supply an appid like:  -appid 1234     or an SLA ID like  -slaid 5678   or logical groupID like  -logicalgroupid"
        return
    }

    $body = New-Object -TypeName psobject

    if ($dedupasync.ToLower() -eq "enable"){
        $body | Add-Member -MemberType NoteProperty -Name dedupasyncoff -Value "false"
    }
    if ($dedupasync.ToLower() -eq "disable"){
        $body | Add-Member -MemberType NoteProperty -Name dedupasyncoff -Value "true"
    }

    if ($expiration.ToLower() -eq "enable"){
        $body | Add-Member -MemberType NoteProperty -Name expirationoff -Value "false"
    }
    if ($expiration.ToLower() -eq "disable"){
        $body | Add-Member -MemberType NoteProperty -Name expirationoff -Value "true"
    }

    if ($logexpiration.ToLower() -eq "enable"){
        $body | Add-Member -MemberType NoteProperty -Name logexpirationoff -Value "false"
    }
    if ($logexpiration.ToLower() -eq "disable"){
        $body | Add-Member -MemberType NoteProperty -Name logexpirationoff -Value "true"
    }

    if ($scheduler.ToLower() -eq "enable"){
        $body | Add-Member -MemberType NoteProperty -Name scheduleoff -Value "false"
    }
    if ($scheduler.ToLower() -eq "disable"){
        $body | Add-Member -MemberType NoteProperty -Name scheduleoff -Value "true"
    }
    if ($logicalgroupid)
    {
        $slp = @{id=$slpid}
        $slt = @{id=$sltid}
        $body | Add-Member -MemberType NoteProperty -Name slp -Value $slp
        $body | Add-Member -MemberType NoteProperty -Name slt -Value $slt
    }

    $jsonbody = $body | ConvertTo-Json

    if (!($logicalgroupid))
    {
        Put-AGMAPIData  -endpoint /sla/$slaid -body $jsonbody
    } else {
        Put-AGMAPIData  -endpoint /logicalgroup/$logicalgroupid/sla -body $jsonbody
    }
}

Function Set-AGMUser ([string]$userid,[string]$timezone,[string]$rolelist,[string]$orglist) 
{
    <#
    .SYNOPSIS
    Changes a User

    .EXAMPLE
    Set-AGMUser -userid 123 -rolelist "2,3" -orglist "4,5"

    Sets a user to use the specified roles and orgs.
    IMPORTANT - The rolelist and orglist will REPLACE the existing roles and orgs, not ADD to them. USE WITH CARE

    .DESCRIPTION
    A function to change a User

    #>

   
    if (!($userid))
    {
        Get-AGMErrorMessage -messagetoprint "Specify a user id (that can be learned with Get-AGMUSer) with -userid"
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

    Put-AGMAPIData  -endpoint /user/$userid -body $jsonbody
}