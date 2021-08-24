Function Set-AGMCredential ([string]$name,[string]$zone,[string]$id,[string]$clusterid,[string]$applianceid,$filename,[string]$projectid) 
{
    <#
    .SYNOPSIS
    Updates a cloud credential

    .EXAMPLE
    Set-AGMCredential -credentialid 1234 -name cred1 -zone australia-southeast1-c -clusterid 144292692833 -filename keyfile.json
    

    .DESCRIPTION
    A function to update cloud credentials

    #>

    if ($id) { $credentialid = $id }
    if (!($credentialid))
    {
        [string]$credentialid = Read-Host "Credential ID"
    }
    
    if ($applianceid) { [string]$clusterid = $applianceid}
    if (!($clusterid))
    {
        [string]$clusterid = Read-Host "Cluster IDs to update (comma separated)"
    }
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
        Get-AGMErrorMessage -messagetoprint "The credential ID $credentialid could not be found."
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
    }

    $sources = ""
    foreach ($cluster in $clusterid.Split(","))
    {
        $sources = $sources +',{"clusterid":"' +$cluster +'"}'
    }
    $sources = $sources.substring(1)

    $json = '{"name":"' +$name +'","cloudtype":"GCP","region":"' +$zone +'","endpoint":"","credential":"'
    $json = $json + $jsonkey
    $json = $json +'","orglist":[],"projectid":"' +$projectid +'",'
    $json = $json +'"sources":[' +$sources +']}'

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


function Set-AGMImage([string]$imagename,[string]$imageid,[string]$label)
{
    <#
    .SYNOPSIS
    Labels a nominated image

    .EXAMPLE
    Set-AGMImage
    You will be prompted for image Name 

    .EXAMPLE
    Set-AGMImage -imagename Image_2133445 -label "testimage"
    Labels Image_2133445 with the label "testimage"

    .DESCRIPTION
    A function to label images  

    #>


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

    if (!($label))
    {
        $label = Read-Host "Label"
    }


    $body = @{label=$label}
    $json = $body | ConvertTo-Json

    Put-AGMAPIData  -endpoint /backup/$id -body $json
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