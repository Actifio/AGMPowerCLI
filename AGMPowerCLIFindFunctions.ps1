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

<#
.SYNOPSIS
Find the host name of a vCenter by its vCenter ID.

.EXAMPLE
Find-vCenterHostName -vCenterId 6880886
#>
function Find-vCenterHostName {
  [CmdletBinding()]
  param (
      # The `id` of the vCenter host, you can find the `id` by `(Get-AGMHost -filtervalue "isvcenterhost=true") | Select-Object id,name`
      [Parameter(Mandatory = $true)]
      [int]
      $vCenterId
  )

  (Get-AGMHost -filtervalue "isvcenterhost=true&id=$vCenterId").hostname
}

<#
.SYNOPSIS
Find the VMs with the specified tag name.

.EXAMPLE
Find-vCenterTaggedVMs -VmTag 'MyVMTag'
#>
function Find-vCenterTaggedVMs {
  [CmdletBinding()]
  param (
      # Tag name that is associated with the VMs
      [Parameter(Mandatory = $true)]
      [string]
      $VmTag
  )

  $vcenter_vms_to_protect = @()
  Invoke-ListTag | ForEach-Object {
      $tag = Invoke-GetTagId -TagId $_
      if ($tag.name -eq $VmTag) {
          $tagged_vms = Invoke-ListAttachedObjectsTagIdTagAssociation -TagId $tag.id | Where-Object { $_.type -eq "VirtualMachine" }
          
          $tagged_vms | ForEach-Object {
              $vm_details = Invoke-GetVm -Vm $_.id
              $vcenter_vms_to_protect += [PSCustomObject]@{
                  id   = $_.id
                  name = $vm_details.name
                  uuid = $vm_details.identity.instance_uuid
              }
          }
          break
      }
  }

  return $vcenter_vms_to_protect
}