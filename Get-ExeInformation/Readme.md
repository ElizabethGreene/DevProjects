# Get-ExeInformation.ps1

Get-ExeInformation.ps1 is a PowerShell script designed to extract and display detailed metadata about Windows executable files (`.exe`).

Primary use cases for this tool are to determine if an app is 32 or 64-bit, and if a 32-bit app has the "Large Address Aware" bit set.

## Features

- Extracts version and product information from `.exe` files
- Displays file size, creation date, and other metadata
- Supports batch processing of multiple files
- Outputs results in a readable format

## Usage

```powershell
.\Get-ExeInformation.ps1 -Path "C:\Path\To\File.exe"
```

### Parameters

- `-Path`  
    Specifies the path to the `.exe` file or folder containing `.exe` files.

## Example

```powershell
.\Get-ExeInformation.ps1 -Path "C:\Windows\System32\notepad.exe"
```

## Screenshot

![Screenshot showing Get-ExeInformation.ps1 output](images/screenshot.png)

## Requirements

- Windows PowerShell 5.1 or later

## License

This project is licensed under the MIT License.

## Contributing

Contributions are welcome! Please open issues or submit pull requests for improvements.
