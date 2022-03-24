# 23.03.2022 Eike Doose
# https://dejanstojanovic.net/powershell/2019/september/cloning-windows-virtual-machine-in-azure-without-having-to-stop-it

#Existing virtual network where new virtual machine will be created

$virtualNetworkName = 'SDMS-Cloud1-01-DE-vNET01'

#Resource group of the VM to be clonned from 
$resourceGroupName = 'SDMS-Cloud1-01-DE'

#Region where managed disk will be created
$location = 'germanywestcentral'

#Names of source and target (new) VMs
$sourceVirtualMachineName = 'SDMS-Cloud1-01-DE-21-KD_TEMPLATE'
$targetVirtualMachineName = 'SDMS-Cloud1-01-DE-40-KD50999'

#Name of snapshot which will be created from the Managed Disk
$snapshotName = $sourceVirtualMachineName + '_OsDisk-snapshot'

#Name of the new Managed Disk
$diskName = $targetVirtualMachineName + '_OsDisk'

#Size of new Managed Disk in GB
$diskSize = 128

#Storage type for the new Managed Disk (Standard_LRS / Premium_LRS / StandardSSD_LRS)
$storageType = 'Premium_LRS'

#Size of the Virtual Machine (https://docs.microsoft.com/en-us/azure/virtual-machines/windows/sizes)
$targetVirtualMachineSize = 'Standard_B2s'

#Set the subscription for the current session where the commands wil execute
Select-AzSubscription -SubscriptionId '64c89a5a-3c5f-4d6b-a7d5-22dd43ae2e71'

#Get the existing VM from which to clone from
$sourceVirtualMachine = Get-AzVM -ResourceGroupName $resourceGroupName -Name $sourceVirtualMachineName

#Create new VM Disk Snapshot
$snapshot = New-AzSnapshotConfig -SourceUri $sourceVirtualMachine.StorageProfile.OsDisk.ManagedDisk.Id -Location $location -CreateOption copy
$snapshot = New-AzSnapshot -Snapshot $snapshot -SnapshotName $snapshotName -ResourceGroupName $resourceGroupName 

#Create a new Managed Disk from the Snapshot
$disk = New-AzDiskConfig -AccountType $storageType -DiskSizeGB $diskSize -Location $location -CreateOption Copy -SourceResourceId $snapshot.Id
$disk = New-AzDisk -Disk $disk -ResourceGroupName $resourceGroupName -DiskName $diskName

#Initialize virtual machine configuration
$targetVirtualMachine = New-AzVMConfig -VMName $targetVirtualMachineName -VMSize $targetVirtualMachineSize

#Attach Managed Disk to target virtual machine. OS type depends OS present in the disk (Windows/Linux)
$targetVirtualMachine = Set-AzVMOSDisk -VM $targetVirtualMachine -ManagedDiskId $disk.Id -CreateOption Attach -Windows

#Create a public IP for the VM
#$publicIp = New-AzPublicIpAddress -Name ($targetVirtualMachineName.ToLower() + '_ip') -ResourceGroupName $resourceGroupName -Location $location -AllocationMethod Dynamic
$publicIp = New-AzPublicIpAddress -Name ($targetVirtualMachineName + '_PublicIP') -ResourceGroupName $resourceGroupName -Location $location -AllocationMethod Dynamic

#Get Virtual Network information
$vnet = Get-AzVirtualNetwork -Name $virtualNetworkName -ResourceGroupName $resourceGroupName

# Create Network Interface for the VM
#$nic = New-AzNetworkInterface -Name ($targetVirtualMachineName.ToLower() + '_nic') -ResourceGroupName $resourceGroupName -Location $location -SubnetId $vnet.Subnets[0].Id -PublicIpAddressId $publicIp.Id
$nictrusted = New-AzNetworkInterface -Name ($targetVirtualMachineName + '_trustedNIC') -ResourceGroupName $resourceGroupName -Location $location -SubnetId $vnet.Subnets[0].Id
$nicuntrusted = New-AzNetworkInterface -Name ($targetVirtualMachineName + '_untrustedNIC') -ResourceGroupName $resourceGroupName -Location $location -SubnetId $vnet.Subnets[0].Id -PublicIpAddressId $publicIp.Id
$targetVirtualMachine = Add-AzVMNetworkInterface -VM $targetVirtualMachine -Id $nictrusted.Id
$targetVirtualMachine = Add-AzVMNetworkInterface -VM $targetVirtualMachine -Id $nicuntrusted.Id

# Create Network Security Group for the VM
$NSGrule1 = New-AzNetworkSecurityRuleConfig -Name rdp-rule -Description "Allow RDP" -Access Allow -Protocol Tcp -Direction Inbound -Priority 100 -SourceAddressPrefix Internet -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange 3389
$NSGrule2 = New-AzNetworkSecurityRuleConfig -Name web-rule -Description "Allow HTTPS" -Access Allow -Protocol Tcp -Direction Inbound -Priority 101 -SourceAddressPrefix Internet -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange 443
$nsg = New-AzNetworkSecurityGroup -Name ($targetVirtualMachineName + '_NSG') -ResourceGroupName $resourceGroupName -Location $location -SecurityRules $NSGrule1,$NSGrule2
$targetVirtualMachine = Add-AzNetworkSecurityGroup -VM $targetVirtualMachine -Id $nictrusted.Id

#Create the virtual machine with Managed Disk attached
New-AzVM -VM $targetVirtualMachine -ResourceGroupName $resourceGroupName -Location $location

#Remove the snapshot
Remove-AzSnapshot -ResourceGroupName $resourceGroupName -SnapshotName $snapshotName -Force

    
    