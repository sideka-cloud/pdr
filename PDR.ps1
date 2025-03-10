# Parameters
$threshold = 6
$eventID = 4625
$rdpPort = 3389
$timeSpan = (Get-Date).AddHours(-1)  # Last 1 hour

# Retrieve failed RDP login events from the last hour
$filteredEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$eventID; StartTime=$timeSpan} -ErrorAction Stop

# Debugging: Output total events
Write-Host "Total Events Found: $($filteredEvents.Count)"

# Check if any events were found
if ($filteredEvents.Count -eq 0) {
    Write-Host "No events found for Event ID $eventID in the last hour."
    return
}

# Extract and group IP addresses
$propertyIndex = 19  # Correct index for IP address

# Collect IPs from events
$ipAddresses = $filteredEvents | ForEach-Object {
    $ip = $_.Properties[$propertyIndex].Value
    if ($ip -match '\d{1,3}(\.\d{1,3}){3}') {
        [PSCustomObject]@{IP = $ip}
    }
}

# Debugging: Output collected IP addresses
Write-Host "Collected IP Addresses:"
$ipAddresses | Format-Table -Property IP

# Check if IP addresses are being collected
if ($ipAddresses.Count -eq 0) {
    Write-Host "No valid IP addresses found."
    return
}

# Group IPs and filter by threshold
$failedLogins = $ipAddresses | Group-Object -Property IP | Where-Object { $_.Count -ge $threshold }

# Debugging: Output the grouped IP addresses
Write-Host "Failed Login IPs:"
$failedLogins | Format-Table -Property Name, Count

# Check if there are any failed logins that meet the threshold
if ($failedLogins.Count -eq 0) {
    Write-Host "No IP addresses exceed the threshold."
    return
}

# Function to get the network subnet from an IP address
function Get-SubnetFromIP($ipAddress) {
    $ip = [System.Net.IPAddress]::Parse($ipAddress)
    $ipBytes = $ip.GetAddressBytes()
    $subnet = "{0}.{1}.{2}.0/24" -f $ipBytes[0], $ipBytes[1], $ipBytes[2]
    return $subnet
}

# Process each IP that exceeded the threshold
foreach ($login in $failedLogins) {
    $ipAddress = $login.Name
    $subnet = Get-SubnetFromIP $ipAddress
    $ruleName = "Block RDP Brute Force - $subnet"

    # Check if a rule already exists
    $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if ($existingRule) {
        # If the rule exists but is disabled, enable it
        if ($existingRule.Enabled -eq 'False') {
            Set-NetFirewallRule -DisplayName $ruleName -Enabled True
            Write-Host "Enabled existing rule for subnet: $subnet"
        } else {
            Write-Host "Rule already exists and is enabled for subnet: $subnet"
        }
    } else {
        # Create a new rule if it does not exist
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Block -RemoteAddress $subnet -Protocol TCP -LocalPort $rdpPort -Profile Any
        Write-Host "Created new rule for subnet: $subnet"
    }
}
