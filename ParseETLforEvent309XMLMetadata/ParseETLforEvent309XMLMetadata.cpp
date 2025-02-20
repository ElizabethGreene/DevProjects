/*
ParseETLforEvent309XMLMetadata.cpp
Copyright 2024 Elizabeth Greene <elizabeth.a.greene@gmail.com>

This program parses an ETL file for Event ID 309 and extracts the XML payload
to human readable text.
*/

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <iostream>
#include <vector>
#include <commdlg.h> // Include for common dialogs

// The pragma directives instruct the linker to compile with the specified libraries
// obviating the need for a separate makefile or build script.
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "comdlg32.lib")

// Callback function to process each event
void WINAPI ProcessEvent(PEVENT_RECORD event)
{
    if (event->EventHeader.EventDescriptor.Id == 309)
    { // Filter for Event ID 309
        // Access the event payload (UserData)
        BYTE *payload = (BYTE *)event->UserData;
        ULONG payloadLength = event->UserDataLength;

        std::string output = "";
        
        std::cout << "Event ID 309 Payload (" << payloadLength << " bytes): ";
        for (ULONG i = 0; i < payloadLength; ++i)
        {
            // printf("%02X ", payload[i]);
            if (payload[i] != 0)
            {
                output += static_cast<char>(payload[i]);
            }
        }
        std::cout << output << std::endl
                  << std::endl;
    }
}

std::string selectEtlFile() {
    // Special thanks to https://learn.microsoft.com/en-us/windows/win32/dlgbox/using-common-dialog-boxes 
    // for the code to open a file dialog box.

    OPENFILENAMEA ofn;      // Use OPENFILENAMEA for ANSI
    char szFile[260] = {0}; // Buffer for file name, initialized to zero

    // Initialize OPENFILENAME
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;   // No owner window
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = "ETL Files\0*.ETL\0All\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = NULL;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    // Display the Open dialog box
    if (GetOpenFileNameA(&ofn) == TRUE) {
        return std::string(ofn.lpstrFile); // Convert LPSTR to std::string
    } else {
        return ""; // Return empty string if dialog fails or is canceled
    }
}

int main()
{

    std::cout << "Select ETL file to parse:" << std::endl;
    std::string filename = selectEtlFile();
    if (filename.empty())
    {
        std::cerr << "No file selected or error occurred." << std::endl;
        return 1;
    }

    std::cout << "Parsing " << filename << std::endl;

    // Set up EVENT_TRACE_LOGFILE structure
    EVENT_TRACE_LOGFILE traceLog = {0}; // Use ANSI version
    traceLog.LogFileName = const_cast<LPSTR>(filename.c_str());
    traceLog.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD;
    traceLog.EventRecordCallback = ProcessEvent;

    // Open the trace
    TRACEHANDLE traceHandle = OpenTrace(&traceLog);
    if (traceHandle == INVALID_PROCESSTRACE_HANDLE)
    {
        std::cerr << "Failed to open trace: " << GetLastError() << std::endl;
        return 1;
    }

    // Process the trace
    ULONG status = ProcessTrace(&traceHandle, 1, NULL, NULL);
    if (status != ERROR_SUCCESS)
    {
        std::cerr << "Failed to process trace: " << status << std::endl;
    }

    // Close the trace
    CloseTrace(traceHandle);

    return 0;
}