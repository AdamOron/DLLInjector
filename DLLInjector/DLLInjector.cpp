#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>

/* Macro for the library loading (LoadLibraryA, LoadLibraryW, e.t.c) */
#define LOAD_METHOD LoadLibraryA

/*
Throws given error message and exits the program.
@param const char *format, the format of the message. ..., the additional arguments matching the format.
*/
void ThrowError(const char *format, ...)
{
    /* Notify that injection failed */
    printf("Injection failed!\n");
    /* Print given format & arguments */
    va_list varargs;
    va_start(varargs, format);
    vprintf(format, varargs);
    va_end(varargs);
    /* Exit with non-zero code */
    exit(1);
}

/*
Finds the Process matching the given name & returns its ID.
@param const wchar_t *wProcName, a wide-character-string specifying the desired process' name.
@return DWORD specifying the ID of the desired process, or NULL if it couldn't be found.
*/
DWORD FindProcessIdW(const wchar_t *wProcName)
{
    /* Get Snapshot of all running processes */
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    /* Initialzie PROCESSENTRY32 - process descriptor struct. Used for retrieving information about a process */
    PROCESSENTRY32 proc;
    /* We must initialize the dwSize property to the size of the struct */
    proc.dwSize = sizeof(PROCESSENTRY32);

    /* Grab first process from Snapshot, store it in the process descriptor */
    if (!Process32First(hSnapshot, &proc))
        /* If the function returned NULL, the Snapshot is empty -we can't find desired process */
        return NULL;

    do
    {
        /* Compare current process' name to the desired name */
        if (wcscmp(wProcName, proc.szExeFile) == 0)
            /* If we found a match (wcsmp returns difference), return the current process' ID */
            return proc.th32ProcessID;
    }
    /* Grab the next process in the Snapshot, store it in the process descriptor. If this returns NULL, exit the loop */
    while (Process32Next(hSnapshot, &proc));

    /* If we haven't found a match and exited the function, the given process name doesn't eixst */
    return NULL;
}

/*
Finds the Process matching the given name & returns its ID. 
This function is merely a wrapper for FindProcessIdW, as it accepts a C-string rather than a wide-string.
@param const char *procName, a C-character-string specifying the desired process' name.
@return DWORD specifying the ID of the desired process, or NULL if it couldn't be found.
*/
DWORD FindProcessId(const char *procName)
{
    /* The size of the given process name */
    size_t procNameLen = strlen(procName);
    /* Initialize wide-string that'll store process name */
    wchar_t *wProcName = new wchar_t[procNameLen + 1];
    /* Amount of wide-characters written, output from mbstowcs_s */
    size_t wProcNameLen;
    /*
    Convert given C-string to wide-string. Store result wide-string in wProcName & length of result in wProcNameLen.
    The passed length of the wide-string must be larger than the length of the C-string.
    */
    mbstowcs_s(&wProcNameLen, wProcName, procNameLen + 1, procName, procNameLen);
    /* Check if amount of written wide-characters matches */
    if (wProcNameLen != procNameLen + 1)
        /* If amount doesn't match, throw error */
        ThrowError("Failed to find process ID: unable to convert C-string to wide-string.");

    /* Call FindProcessIdW with the generated wide-string */
    DWORD procId = FindProcessIdW(wProcName);

    /* Delete wProcName ater we're done with it */
    delete[] wProcName;
    /* Return the found process ID */
    return procId;
}

/*
Finds process matching given process name, opens a handle & returns it.
@param const char *procName, the name of the desired process.
@return Open HANDLE to desired process.
*/
HANDLE FindProcessHandle(const char *procName)
{
    /* Find ID of desired process */
    DWORD procId = FindProcessId(procName);
    /* If returned ID is NULL, we failed to find the process */
    if (!procId)
        ThrowError("Failed to open process handle: couldn't find process \"%s\".");

    /* Get open handle to desired process */
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procId);
    /* If OpenProcess returned NULL, we failed to open a handle */
    if (!hProc)
        ThrowError("Failed to open process handle: OpenProcess returned NULL.");

    /* Returned open HANDLE to desired process */
    return hProc;
}

/*
Writes given library path to given process memory.
@param HANDLE hProc, a open handle to the desired process. const char *libraryPath, the desired path to be written.
@return LPCSTR pointing to the written path.
*/
LPCSTR WriteLibraryPath(HANDLE hProc, const char *libraryPath)
{
    /* Calculate the size of the library path string (sizeof(char) is 1, but for good measure) */
    size_t libraryPathSize = strlen(libraryPath) * sizeof(char);
    /* Allocate memory for the path within the given process */
    LPVOID lpAllocated = (char *) VirtualAllocEx(hProc, NULL, libraryPathSize, MEM_COMMIT, PAGE_READWRITE);
    /* If address of allocated memory is NULL, the allocation failed */
    if (!lpAllocated)
        ThrowError("Failed to write library path into process: VirtualAllocEx returned NULL.");

    /* Amount of bytes written into memory */
    SIZE_T bytesWritten;
    /* Write the given path into the process memory */
    WriteProcessMemory(hProc, lpAllocated, (LPCVOID) libraryPath, libraryPathSize, &bytesWritten);
    /* Compare amount of written bytes to the size of the path */
    if (bytesWritten != libraryPathSize)
        /* If there's a mismatch, throw error */
        ThrowError("Failed to write library path into process: wrong amount of bytes written.");

    /* Return pointer to the written path */
    return (LPCSTR) lpAllocated;
}

/*
Creates thread within the process for the library. This thread will load the library, which will then execute its code.
@param HANDLE hProc, open handle to the process. LPCSTR lpLibraryPath, the library's path (already written to the process).
*/
HANDLE CreateLibraryThread(HANDLE hProc, LPCSTR lpLibraryPath)
{
    /* Create thread within the process for loading & executing the library */
    HANDLE hRemoteThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE) LOAD_METHOD, (LPVOID) lpLibraryPath, 0, NULL);
    /* Check if created remote thread is NULL, if so it failed */
    if (!hRemoteThread)
        /* If creating remote thread failed, throw error */
        ThrowError("Failed to load library: CreateRemoteThread returned NULL.");

    /* Return open handle to remote thread */
    return hRemoteThread;
}

/*
Inject given library into given process.
@param const char *procName, the process to which we will inject. const char *libraryPath, the path of the library we will inject.
*/
void InjectLibrary(const char *procName, const char *libraryPath)
{
    /* Get open handle to desired process */
    HANDLE hProc = FindProcessHandle(procName);
    /* Load library & execute it in new thread within the process */
    HANDLE hRemoteThread = CreateLibraryThread(hProc, WriteLibraryPath(hProc, libraryPath));
    /* Close the process to the handle */
    CloseHandle(hProc);

    printf("Injected successfully!\n");
}

void InjectWithInput()
{
    printf("Invalid arguments passed to EXE. EXE expects to receive 2 arguments: <ProcName>, <DllPath>.\nGetting input from user...\n\n");

    char procName[MAX_PATH];
    char libraryPath[MAX_PATH];

    printf("Please enter process name (no whitspace characters): ");
    scanf_s("%259s", procName, MAX_PATH);
    printf("Please enter library path (no whitspace characters): ");
    scanf_s("%259s", libraryPath, MAX_PATH);

    InjectLibrary(procName, libraryPath);
}

int main(int argc, char *argv[])
{
    if (argc == 3)
        InjectLibrary(argv[1], argv[2]);
    else
        InjectWithInput();

    system("pause");
}
