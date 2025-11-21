function Get-RemainingActivations {
  <#
    .SYNOPSIS
        Queries Microsoft's Volume Activation service to return the remaining activation count for a given Volume License.

    .DESCRIPTION
        Queries Microsoft's Volume Activation service BatchActivation endpoint to return the number of Remaining activations for a Volume License
        NOTE: The product key is not directly query-able, so this function requires the Extended Product ID (EPID) instead.

        The Extended Product ID can be obtained from an existing installation by running: slmgr.vbs /dlv

        Requires internet access to reach Microsoft's activation web service, https://activation.sls.microsoft.com/BatchActivation/BatchActivation.asmx

    .PARAMETER ExtendedPID
        The full Extended Product ID (EPID) from an existing activation.
        Example: 03612-03763-081-809727-00-1033-14393.0000-3252025

    .EXAMPLE
        Get-RemainingActivations "03612-03763-081-809727-00-1033-14393.0000-3252025"
        Returns: -1 (unlimited activations remaining) or another integer value.

    .EXAMPLE
        Get-RemainingActivations "03612-03763-081-809727-00-1033-14393.0000-3252025' 
        (Positional usage — no parameter name needed)

    .OUTPUTS
        Number of remaining activations or error message.
    
    .NOTES
        Special thanks to https://github.com/dadorner-msft/activationws for insights into the activation web service.

    #>
  [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ExtendedPID 
    )


    # Microsoft's private key for HMAC-SHA256 (publicly known for this purpose)
    $privateKey = [byte[]]@(254, 49, 152, 117, 251, 72, 132, 134, 156, 243, 241, 206, 153, 168, 144, 100, 171, 87, 31, 202, 71, 4, 80, 88, 48, 36, 226, 20, 98, 135, 121, 160, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

   # Build the activation request XML
    $xmlContent = @"
<ActivationRequest xmlns="http://www.microsoft.com/DRM/SL/BatchActivationRequest/1.0"><VersionNumber>2.0</VersionNumber><RequestType>2</RequestType><Requests> <Request><PID>$ExtendedPID</PID></Request></Requests></ActivationRequest>
"@

    # Convert XML to Unicode bytes
    $byteXml = [System.Text.Encoding]::Unicode.GetBytes($xmlContent)

    # Base64 encode the XML bytes
    $base64Xml = [Convert]::ToBase64String($byteXml)

    # Compute HMAC-SHA256 digest
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = $privateKey
    $digestBytes = $hmac.ComputeHash($byteXml)
    $digest = [Convert]::ToBase64String($digestBytes)

    # Build the SOAP envelope
    $soapEnvelope = @"
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><soap:Body><BatchActivate xmlns="http://www.microsoft.com/BatchActivationService"><request><Digest>$digest</Digest><RequestXml>$base64Xml</RequestXml></request></BatchActivate></soap:Body></soap:Envelope>
"@

    # Set up the web request
    $url = "https://activation.sls.microsoft.com/BatchActivation/BatchActivation.asmx"
    $headers = @{
        "SOAPAction"   = "http://www.microsoft.com/BatchActivationService/BatchActivate"
    }

    # Send the request
    try {
        $response = Invoke-WebRequest -Uri $url -Method Post -Body $soapEnvelope -ContentType 'text/xml; charset=utf-8' -Headers $headers -UseBasicParsing
        
        # If the response contains the activationcount, regex it out and return it.
        # e.g. &lt;ActivationRemaining&gt;24738&lt;/ActivationRemaining&gt;
        $responseXmlMatch = [regex]::Match( $response.Content, "&lt;ActivationRemaining&gt;(\-?[0-9]+)&lt;/ActivationRemaining&gt;",[System.Text.RegularExpressions.RegexOptions]::Singleline)
        if ($responseXmlMatch.Success) {
            return $responseXmlMatch.Groups[1].Value
        } else {
            # Fallback: Extract the entire ResponseXml
            throw "No ActivationRemaining found in response. Full response:  $response.Content"    
        }
    } catch {
        return "Error: $($_.Exception.Message)"
    }
}

# Example call
Get-RemainingActivations -ExtendedPID "03612-03763-081-809727-00-1033-14393.0000-3252025"

# As of 20251121, that example returns -1, which indicates unlimited activations remaining.
