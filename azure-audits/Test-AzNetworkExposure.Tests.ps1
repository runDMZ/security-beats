BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Path = $PSCommandPath -replace '\.Tests\.ps1$', '.ps1'

    function New-Rule {
        param($Name, $Ports, $Source = @('*'), $Access = 'Allow', $Direction = 'Inbound')
        [pscustomobject]@{ Name = $Name; Id = "rule/$Name"; Direction = $Direction; Access = $Access; Protocol = 'Tcp'
            Priority = 100; SourceAddressPrefix = @($Source); DestinationPortRange = @($Ports) }
    }
}

Describe 'Test-AzNetworkExposure' {
    BeforeAll {
        Initialize-AzConnectionMock
        Mock Get-AzNetworkSecurityGroup {
            [pscustomobject]@{ Name = 'nsg-web'; ResourceGroupName = 'rg-a'; NetworkInterfaces = @('nic'); Subnets = @()
                SecurityRules = @(
                    (New-Rule 'rdp-open' '3389' 'Internet')
                    (New-Rule 'https-open' '443')
                    (New-Rule 'range-open' '3000-4000' '0.0.0.0/0')
                    (New-Rule 'all-ports' '*')
                    (New-Rule 'ssh-office' '22' '203.0.113.10/32')
                    (New-Rule 'ssh-denied' '22' '*' 'Deny')
                    (New-Rule 'outbound' '22' '*' 'Allow' 'Outbound')
                ) }
            [pscustomobject]@{ Name = 'nsg-spare'; ResourceGroupName = 'rg-a'; NetworkInterfaces = @(); Subnets = @()
                SecurityRules = @((New-Rule 'ssh-open' '22')) }
        }
        Mock Get-AzPublicIpAddress {
            [pscustomobject]@{ Name = 'ip-vm'; ResourceGroupName = 'rg-a'; Id = 'ip1'; IpAddress = '20.0.0.1'
                IpConfiguration = [pscustomobject]@{ Id = '/subscriptions/sub-1/resourceGroups/rg-a/providers/Microsoft.Network/networkInterfaces/vm1-nic/ipConfigurations/ipconfig1' } }
            [pscustomobject]@{ Name = 'ip-lb'; ResourceGroupName = 'rg-a'; Id = 'ip2'; IpAddress = '20.0.0.2'
                IpConfiguration = [pscustomobject]@{ Id = '/subscriptions/sub-1/resourceGroups/rg-a/providers/Microsoft.Network/loadBalancers/lb/frontendIPConfigurations/fe' } }
        }
        $script:Result = & $script:Path
        $script:Rules = $Result | Where-Object Category -EQ 'OpenNsgRule'
    }

    It 'rates RDP open to the Internet High' {
        ($Rules | Where-Object Resource -EQ 'nsg-web / rdp-open').Severity | Should -Be 'High'
    }
    It 'rates HTTPS open to everyone Medium' {
        ($Rules | Where-Object Resource -EQ 'nsg-web / https-open').Severity | Should -Be 'Medium'
    }
    It 'detects a sensitive port inside a range' {
        ($Rules | Where-Object Resource -EQ 'nsg-web / range-open').Severity | Should -Be 'High'
    }
    It 'rates "all ports" High' {
        ($Rules | Where-Object Resource -EQ 'nsg-web / all-ports').Severity | Should -Be 'High'
    }
    It 'ignores restricted sources, Deny rules and outbound rules' {
        $Rules.Resource | Should -Not -Contain 'nsg-web / ssh-office'
        $Rules.Resource | Should -Not -Contain 'nsg-web / ssh-denied'
        $Rules.Resource | Should -Not -Contain 'nsg-web / outbound'
    }
    It 'says when the NSG is not attached' {
        ($Rules | Where-Object Resource -EQ 'nsg-spare / ssh-open').Details | Should -Match 'NSG not attached'
    }
    It 'reports a public IP directly on a VM network interface, not one on a load balancer' {
        $vmIps = @($Result | Where-Object Category -EQ 'VmPublicIp')
        $vmIps.Resource | Should -Be @('ip-vm')
        $vmIps[0].Details | Should -Match 'vm1-nic'
    }
}
