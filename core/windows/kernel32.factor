IN: win32-api

LIBRARY: kernel32
! FUNCTION: _hread
! FUNCTION: _hwrite
! FUNCTION: _lclose
! FUNCTION: _lcreat
! FUNCTION: _llseek
! FUNCTION: _lopen
! FUNCTION: _lread
! FUNCTION: _lwrite
! FUNCTION: ActivateActCtx
! FUNCTION: AddAtomA
! FUNCTION: AddAtomW
! FUNCTION: AddConsoleAliasA
! FUNCTION: AddConsoleAliasW
! FUNCTION: AddLocalAlternateComputerNameA
! FUNCTION: AddLocalAlternateComputerNameW
! FUNCTION: AddRefActCtx
! FUNCTION: AddVectoredExceptionHandler
! FUNCTION: AllocateUserPhysicalPages
! FUNCTION: AllocConsole
! FUNCTION: AreFileApisANSI
! FUNCTION: AssignProcessToJobObject
! FUNCTION: AttachConsole
! FUNCTION: BackupRead
! FUNCTION: BackupSeek
! FUNCTION: BackupWrite
! FUNCTION: BaseCheckAppcompatCache
! FUNCTION: BaseCleanupAppcompatCache
! FUNCTION: BaseCleanupAppcompatCacheSupport
! FUNCTION: BaseDumpAppcompatCache
! FUNCTION: BaseFlushAppcompatCache
! FUNCTION: BaseInitAppcompatCache
! FUNCTION: BaseInitAppcompatCacheSupport
! FUNCTION: BasepCheckWinSaferRestrictions
! FUNCTION: BaseProcessInitPostImport
! FUNCTION: BaseQueryModuleData
! FUNCTION: BaseUpdateAppcompatCache
! FUNCTION: Beep
! FUNCTION: BeginUpdateResourceA
! FUNCTION: BeginUpdateResourceW
! FUNCTION: BindIoCompletionCallback
! FUNCTION: BuildCommDCBA
! FUNCTION: BuildCommDCBAndTimeoutsA
! FUNCTION: BuildCommDCBAndTimeoutsW
! FUNCTION: BuildCommDCBW
! FUNCTION: CallNamedPipeA
! FUNCTION: CallNamedPipeW
! FUNCTION: CancelDeviceWakeupRequest
FUNCTION: BOOL CancelIo ( HANDLE h ) ;
! FUNCTION: CancelTimerQueueTimer
! FUNCTION: CancelWaitableTimer
! FUNCTION: ChangeTimerQueueTimer
! FUNCTION: CheckNameLegalDOS8Dot3A
! FUNCTION: CheckNameLegalDOS8Dot3W
! FUNCTION: CheckRemoteDebuggerPresent
! FUNCTION: ClearCommBreak
! FUNCTION: ClearCommError
! FUNCTION: CloseConsoleHandle
FUNCTION: BOOL CloseHandle ( HANDLE h ) ;
! FUNCTION: CloseProfileUserMapping
! FUNCTION: CmdBatNotification
! FUNCTION: CommConfigDialogA
! FUNCTION: CommConfigDialogW
! FUNCTION: CompareFileTime
! FUNCTION: CompareStringA
! FUNCTION: CompareStringW
! FUNCTION: ConnectNamedPipe
! FUNCTION: ConsoleMenuControl
! FUNCTION: ContinueDebugEvent
! FUNCTION: ConvertDefaultLocale
! FUNCTION: ConvertFiberToThread
! FUNCTION: ConvertThreadToFiber
! FUNCTION: CopyFileA
! FUNCTION: CopyFileExA
! FUNCTION: CopyFileExW
! FUNCTION: CopyFileW
! FUNCTION: CopyLZFile
! FUNCTION: CreateActCtxA
! FUNCTION: CreateActCtxW
! FUNCTION: CreateConsoleScreenBuffer
! FUNCTION: CreateDirectoryA
! FUNCTION: CreateDirectoryExA
! FUNCTION: CreateDirectoryExW
FUNCTION: BOOL CreateDirectoryW ( LPCTSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttribytes ) ;
: CreateDirectory CreateDirectoryW ;

! FUNCTION: CreateEventA
! FUNCTION: CreateEventW
! FUNCTION: CreateFiber
! FUNCTION: CreateFiberEx


FUNCTION: HANDLE CreateFileW ( LPCTSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttribures, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile ) ;
: CreateFile CreateFileW ; inline

FUNCTION: HANDLE  CreateFileMappingW ( HANDLE hFile,
                                       LPSECURITY_ATTRIBUTES lpAttributes,
                                       DWORD flProtect,
                                       DWORD dwMaximumSizeHigh,
                                       DWORD dwMaximumSizeLow,
                                       LPCTSTR lpName ) ;
: CreateFileMapping CreateFileMappingW ;

! FUNCTION: CreateHardLinkA
! FUNCTION: CreateHardLinkW
! FUNCTION: HANDLE CreateIoCompletionPort ( HANDLE hFileHandle, HANDLE hExistingCompletionPort, ULONG_PTR uCompletionKey, DWORD dwNumberofConcurrentThreads ) ;
FUNCTION: HANDLE CreateIoCompletionPort ( HANDLE hFileHandle, HANDLE hExistingCompletionPort, void* uCompletionKey, DWORD dwNumberofConcurrentThreads ) ;
! FUNCTION: CreateJobObjectA
! FUNCTION: CreateJobObjectW
! FUNCTION: CreateJobSet
! FUNCTION: CreateMailslotA
! FUNCTION: CreateMailslotW
! FUNCTION: CreateMemoryResourceNotification
! FUNCTION: CreateMutexA
! FUNCTION: CreateMutexW
! FUNCTION: CreateNamedPipeA
! FUNCTION: CreateNamedPipeW
! FUNCTION: CreateNlsSecurityDescriptor
FUNCTION: BOOL CreatePipe ( PHANDLE hReadPipe, PHANDLE hWritePipe, LPSECURITY_ATTRIBUTES lpPipeAttributes, DWORD nSize ) ;
FUNCTION: BOOL CreateProcessW ( LPCTSTR lpApplicationname,
                                LPTSTR lpCommandLine,
                                LPSECURITY_ATTRIBUTES lpProcessAttributes,
                                LPSECURITY_ATTRIBUTES lpThreadAttributes,
                                BOOL bInheritHandles,
                                DWORD dwCreationFlags,
                                LPVOID lpEnvironment,
                                LPCTSTR lpCurrentDirectory,
                                LPSTARTUPINFO lpStartupInfo,
                                LPPROCESS_INFORMATION lpProcessInformation ) ;
: CreateProcess CreateProcessW ;
! FUNCTION: CreateProcessInternalA
! FUNCTION: CreateProcessInternalW
! FUNCTION: CreateProcessInternalWSecure
FUNCTION: HANDLE CreateRemoteThread ( HANDLE hProcess,
                                      LPSECURITY_ATTRIBUTES lpThreadAttributes,
                                      SIZE_T dwStackSize,
                                      LPVOID lpStartAddress,
                                      LPVOID lpParameter,
                                      DWORD dwCreationFlags,
                                      LPDWORD lpThreadId ) ; 
! FUNCTION: CreateSemaphoreA
! FUNCTION: CreateSemaphoreW
! FUNCTION: CreateSocketHandle
! FUNCTION: CreateTapePartition
! FUNCTION: CreateThread
! FUNCTION: CreateTimerQueue
! FUNCTION: CreateTimerQueueTimer
! FUNCTION: CreateToolhelp32Snapshot
! FUNCTION: CreateVirtualBuffer
! FUNCTION: CreateWaitableTimerA
! FUNCTION: CreateWaitableTimerW
! FUNCTION: DeactivateActCtx
! FUNCTION: DebugActiveProcess
! FUNCTION: DebugActiveProcessStop
! FUNCTION: DebugBreak
! FUNCTION: DebugBreakProcess
! FUNCTION: DebugSetProcessKillOnExit
! FUNCTION: DecodePointer
! FUNCTION: DecodeSystemPointer
! FUNCTION: DefineDosDeviceA
! FUNCTION: DefineDosDeviceW
! FUNCTION: DelayLoadFailureHook
! FUNCTION: DeleteAtom
! FUNCTION: DeleteCriticalSection
! FUNCTION: DeleteFiber
! FUNCTION: DeleteFileA
FUNCTION: BOOL DeleteFileW ( LPCTSTR lpFileName ) ;
: DeleteFile DeleteFileW ;
! FUNCTION: DeleteTimerQueue
! FUNCTION: DeleteTimerQueueEx
! FUNCTION: DeleteTimerQueueTimer
! FUNCTION: DeleteVolumeMountPointA
! FUNCTION: DeleteVolumeMountPointW
! FUNCTION: DeviceIoControl
! FUNCTION: DisableThreadLibraryCalls
! FUNCTION: DisconnectNamedPipe
! FUNCTION: DnsHostnameToComputerNameA
! FUNCTION: DnsHostnameToComputerNameW
! FUNCTION: DosDateTimeToFileTime
! FUNCTION: DosPathToSessionPathA
! FUNCTION: DosPathToSessionPathW
! FUNCTION: DuplicateConsoleHandle
! FUNCTION: DuplicateHandle
! FUNCTION: EncodePointer
! FUNCTION: EncodeSystemPointer
! FUNCTION: EndUpdateResourceA
! FUNCTION: EndUpdateResourceW
! FUNCTION: EnterCriticalSection
! FUNCTION: EnumCalendarInfoA
! FUNCTION: EnumCalendarInfoExA
! FUNCTION: EnumCalendarInfoExW
! FUNCTION: EnumCalendarInfoW
! FUNCTION: EnumDateFormatsA
! FUNCTION: EnumDateFormatsExA
! FUNCTION: EnumDateFormatsExW
! FUNCTION: EnumDateFormatsW
! FUNCTION: EnumerateLocalComputerNamesA
! FUNCTION: EnumerateLocalComputerNamesW
! FUNCTION: EnumLanguageGroupLocalesA
! FUNCTION: EnumLanguageGroupLocalesW
! FUNCTION: EnumResourceLanguagesA
! FUNCTION: EnumResourceLanguagesW
! FUNCTION: EnumResourceNamesA
! FUNCTION: EnumResourceNamesW
! FUNCTION: EnumResourceTypesA
! FUNCTION: EnumResourceTypesW
! FUNCTION: EnumSystemCodePagesA
! FUNCTION: EnumSystemCodePagesW
! FUNCTION: EnumSystemGeoID
! FUNCTION: EnumSystemLanguageGroupsA
! FUNCTION: EnumSystemLanguageGroupsW
! FUNCTION: EnumSystemLocalesA
! FUNCTION: EnumSystemLocalesW
! FUNCTION: EnumTimeFormatsA
! FUNCTION: EnumTimeFormatsW
! FUNCTION: EnumUILanguagesA
! FUNCTION: EnumUILanguagesW
! FUNCTION: EraseTape
! FUNCTION: EscapeCommFunction
! FUNCTION: ExitProcess
! FUNCTION: ExitThread
! FUNCTION: ExitVDM
! FUNCTION: ExpandEnvironmentStringsA
! FUNCTION: ExpandEnvironmentStringsW
! FUNCTION: ExpungeConsoleCommandHistoryA
! FUNCTION: ExpungeConsoleCommandHistoryW
! FUNCTION: ExtendVirtualBuffer
! FUNCTION: FatalAppExitA
! FUNCTION: FatalAppExitW
! FUNCTION: FatalExit
! FUNCTION: FileTimeToDosDateTime
! FUNCTION: FileTimeToLocalFileTime
! FUNCTION: FileTimeToSystemTime
! FUNCTION: FillConsoleOutputAttribute
! FUNCTION: FillConsoleOutputCharacterA
! FUNCTION: FillConsoleOutputCharacterW
! FUNCTION: FindActCtxSectionGuid
! FUNCTION: FindActCtxSectionStringA
! FUNCTION: FindActCtxSectionStringW
! FUNCTION: FindAtomA
! FUNCTION: FindAtomW
FUNCTION: BOOL FindClose ( HANDLE hFindFile ) ;
! FUNCTION: FindCloseChangeNotification
! FUNCTION: FindFirstChangeNotificationA
! FUNCTION: FindFirstChangeNotificationW
! FUNCTION: FindFirstFileA
! FUNCTION: FindFirstFileExA
! FUNCTION: FindFirstFileExW
FUNCTION: HANDLE FindFirstFileW ( LPCTSTR lpFileName, LPWIN32_FIND_DATA lpFindFileData ) ;
: FindFirstFile FindFirstFileW ;
! FUNCTION: FindFirstVolumeA
! FUNCTION: FindFirstVolumeMountPointA
! FUNCTION: FindFirstVolumeMountPointW
! FUNCTION: FindFirstVolumeW
! FUNCTION: FindNextChangeNotification
! FUNCTION: FindNextFileA
FUNCTION: BOOL FindNextFileW ( HANDLE hFindFile, LPWIN32_FIND_DATA lpFindFileData ) ;
: FindNextFile FindNextFileW ;
! FUNCTION: FindNextVolumeA
! FUNCTION: FindNextVolumeMountPointA
! FUNCTION: FindNextVolumeMountPointW
! FUNCTION: FindNextVolumeW
! FUNCTION: FindResourceA
! FUNCTION: FindResourceExA
! FUNCTION: FindResourceExW
! FUNCTION: FindResourceW
! FUNCTION: FindVolumeClose
! FUNCTION: FindVolumeMountPointClose
! FUNCTION: FlushConsoleInputBuffer
! FUNCTION: FlushFileBuffers
! FUNCTION: FlushInstructionCache
! FUNCTION: FlushViewOfFile
! FUNCTION: FoldStringA
! FUNCTION: FoldStringW
! FUNCTION: FormatMessageA
! FUNCTION: FormatMessageW
! FUNCTION: FreeConsole
! FUNCTION: FreeEnvironmentStringsA
! FUNCTION: FreeEnvironmentStringsW
! FUNCTION: FreeLibrary
! FUNCTION: FreeLibraryAndExitThread
! FUNCTION: FreeResource
! FUNCTION: FreeUserPhysicalPages
! FUNCTION: FreeVirtualBuffer
! FUNCTION: GenerateConsoleCtrlEvent
! FUNCTION: GetACP
! FUNCTION: GetAtomNameA
! FUNCTION: GetAtomNameW
! FUNCTION: GetBinaryType
! FUNCTION: GetBinaryTypeA
! FUNCTION: GetBinaryTypeW
! FUNCTION: GetCalendarInfoA
! FUNCTION: GetCalendarInfoW
! FUNCTION: GetCommandLineA
! FUNCTION: GetCommandLineW
! FUNCTION: GetCommConfig
! FUNCTION: GetCommMask
! FUNCTION: GetCommModemStatus
! FUNCTION: GetCommProperties
! FUNCTION: GetCommState
! FUNCTION: GetCommTimeouts
! FUNCTION: GetComPlusPackageInstallStatus
! FUNCTION: GetCompressedFileSizeA
! FUNCTION: GetCompressedFileSizeW
FUNCTION: BOOL GetComputerNameW ( LPTSTR lpBuffer, LPDWORD lpnSize ) ;
! FUNCTION: GetComputerNameExW
! FUNCTION: GetComputerNameW
: GetComputerName GetComputerNameW ;
! FUNCTION: GetConsoleAliasA
! FUNCTION: GetConsoleAliasesA
! FUNCTION: GetConsoleAliasesLengthA
! FUNCTION: GetConsoleAliasesLengthW
! FUNCTION: GetConsoleAliasesW
! FUNCTION: GetConsoleAliasExesA
! FUNCTION: GetConsoleAliasExesLengthA
! FUNCTION: GetConsoleAliasExesLengthW
! FUNCTION: GetConsoleAliasExesW
! FUNCTION: GetConsoleAliasW
! FUNCTION: GetConsoleCharType
! FUNCTION: GetConsoleCommandHistoryA
! FUNCTION: GetConsoleCommandHistoryLengthA
! FUNCTION: GetConsoleCommandHistoryLengthW
! FUNCTION: GetConsoleCommandHistoryW
! FUNCTION: GetConsoleCP
! FUNCTION: GetConsoleCursorInfo
! FUNCTION: GetConsoleCursorMode
! FUNCTION: GetConsoleDisplayMode
! FUNCTION: GetConsoleFontInfo
! FUNCTION: GetConsoleFontSize
! FUNCTION: GetConsoleHardwareState
! FUNCTION: GetConsoleInputExeNameA
! FUNCTION: GetConsoleInputExeNameW
! FUNCTION: GetConsoleInputWaitHandle
! FUNCTION: GetConsoleKeyboardLayoutNameA
! FUNCTION: GetConsoleKeyboardLayoutNameW
! FUNCTION: GetConsoleMode
! FUNCTION: GetConsoleNlsMode
! FUNCTION: GetConsoleOutputCP
! FUNCTION: GetConsoleProcessList
! FUNCTION: GetConsoleScreenBufferInfo
! FUNCTION: GetConsoleSelectionInfo
FUNCTION: DWORD GetConsoleTitleW ( LPWSTR lpConsoleTitle, DWORD nSize ) ;
: GetConsoleTitle GetConsoleTitleW ; inline
! FUNCTION: GetConsoleWindow
! FUNCTION: GetCPFileNameFromRegistry
! FUNCTION: GetCPInfo
! FUNCTION: GetCPInfoExA
! FUNCTION: GetCPInfoExW
! FUNCTION: GetCurrencyFormatA
! FUNCTION: GetCurrencyFormatW
! FUNCTION: GetCurrentActCtx
! FUNCTION: GetCurrentConsoleFont
! FUNCTION: GetCurrentDirectoryA
! FUNCTION: GetCurrentDirectoryW
FUNCTION: HANDLE GetCurrentProcess ( ) ;
! FUNCTION: GetCurrentProcessId
FUNCTION: HANDLE GetCurrentThread ( ) ;
! FUNCTION: GetCurrentThreadId
! FUNCTION: GetDateFormatA
! FUNCTION: GetDateFormatW
! FUNCTION: GetDefaultCommConfigA
! FUNCTION: GetDefaultCommConfigW
! FUNCTION: GetDefaultSortkeySize
! FUNCTION: GetDevicePowerState
! FUNCTION: GetDiskFreeSpaceA
! FUNCTION: GetDiskFreeSpaceExA
! FUNCTION: GetDiskFreeSpaceExW
! FUNCTION: GetDiskFreeSpaceW
! FUNCTION: GetDllDirectoryA
! FUNCTION: GetDllDirectoryW
! FUNCTION: GetDriveTypeA
! FUNCTION: GetDriveTypeW
! FUNCTION: GetEnvironmentStrings
! FUNCTION: GetEnvironmentStringsA
! FUNCTION: GetEnvironmentStringsW
! FUNCTION: GetEnvironmentVariableA
! FUNCTION: GetEnvironmentVariableW
! FUNCTION: GetExitCodeProcess
! FUNCTION: GetExitCodeThread
! FUNCTION: GetExpandedNameA
! FUNCTION: GetExpandedNameW
! FUNCTION: GetFileAttributesA
FUNCTION: DWORD GetFileAttributesW ( LPCTSTR lpFileName ) ;
! FUNCTION: GetFileAttributesExA

: GetFileExInfoStandard 0 ; inline


FUNCTION: BOOL GetFileAttributesExW ( LPCTSTR lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId, LPVOID lpFileInformation ) ;

: GetFileAttributesEx GetFileAttributesExW ;

FUNCTION: BOOL GetFileInformationByHandle ( HANDLE hFile, LPBY_HANDLE_FILE_INFORMATION lpFileInformation ) ;
FUNCTION: DWORD GetFileSize ( HANDLE hFile, LPDWORD lpFileSizeHigh ) ;
! FUNCTION: GetFileSizeEx
FUNCTION: BOOL GetFileTime ( HANDLE hFile, LPFILETIME lpCreationTime, LPFILETIME lpLastAccessTime, LPFILETIME lpLastWriteTime ) ;
FUNCTION: DWORD GetFileType ( HANDLE hFile ) ;
! FUNCTION: GetFirmwareEnvironmentVariableA
! FUNCTION: GetFirmwareEnvironmentVariableW
! FUNCTION: GetFullPathNameA
FUNCTION: DWORD GetFullPathNameW ( LPCTSTR lpFileName, DWORD nBufferLength, LPTSTR lpBuffer, LPTSTR* lpFilePart ) ;
: GetFullPathName GetFullPathNameW ;

!  clear "license.txt" 32768 "char[32768]" <c-object> f over >r GetFullPathName r> swap 2 * head >string .

! FUNCTION: GetGeoInfoA
! FUNCTION: GetGeoInfoW
! FUNCTION: GetHandleContext
! FUNCTION: GetHandleInformation
! FUNCTION: GetLargestConsoleWindowSize
FUNCTION: DWORD GetLastError ( ) ;
! FUNCTION: GetLinguistLangSize
! FUNCTION: GetLocaleInfoA
! FUNCTION: GetLocaleInfoW
! FUNCTION: GetLocalTime
! FUNCTION: GetLogicalDrives
! FUNCTION: GetLogicalDriveStringsA
! FUNCTION: GetLogicalDriveStringsW
! FUNCTION: GetLongPathNameA
! FUNCTION: GetLongPathNameW
! FUNCTION: GetMailslotInfo
! FUNCTION: GetModuleFileNameA
! FUNCTION: GetModuleFileNameW
FUNCTION: HMODULE GetModuleHandleW ( LPCWSTR lpModuleName ) ;
: GetModuleHandle GetModuleHandleW ; inline
! FUNCTION: GetModuleHandleExA
! FUNCTION: GetModuleHandleExW
! FUNCTION: GetNamedPipeHandleStateA
! FUNCTION: GetNamedPipeHandleStateW
! FUNCTION: GetNamedPipeInfo
! FUNCTION: GetNativeSystemInfo
! FUNCTION: GetNextVDMCommand
! FUNCTION: GetNlsSectionName
! FUNCTION: GetNumaAvailableMemory
! FUNCTION: GetNumaAvailableMemoryNode
! FUNCTION: GetNumaHighestNodeNumber
! FUNCTION: GetNumaNodeProcessorMask
! FUNCTION: GetNumaProcessorMap
! FUNCTION: GetNumaProcessorNode
! FUNCTION: GetNumberFormatA
! FUNCTION: GetNumberFormatW
! FUNCTION: GetNumberOfConsoleFonts
! FUNCTION: GetNumberOfConsoleInputEvents
! FUNCTION: GetNumberOfConsoleMouseButtons
! FUNCTION: GetOEMCP
FUNCTION: BOOL GetOverlappedResult ( HANDLE hFile, LPOVERLAPPED lpOverlapped, LPDWORD lpNumberOfBytesTransferred, BOOL bWait ) ;
! FUNCTION: GetPriorityClass
! FUNCTION: GetPrivateProfileIntA
! FUNCTION: GetPrivateProfileIntW
! FUNCTION: GetPrivateProfileSectionA
! FUNCTION: GetPrivateProfileSectionNamesA
! FUNCTION: GetPrivateProfileSectionNamesW
! FUNCTION: GetPrivateProfileSectionW
! FUNCTION: GetPrivateProfileStringA
! FUNCTION: GetPrivateProfileStringW
! FUNCTION: GetPrivateProfileStructA
! FUNCTION: GetPrivateProfileStructW
FUNCTION: LPVOID GetProcAddress ( HMODULE hModule, char* lpProcName ) ;
! FUNCTION: GetProcessAffinityMask
! FUNCTION: GetProcessHandleCount
! FUNCTION: GetProcessHeap
! FUNCTION: GetProcessHeaps
! FUNCTION: GetProcessId
! FUNCTION: GetProcessIoCounters
! FUNCTION: GetProcessPriorityBoost
! FUNCTION: GetProcessShutdownParameters
! FUNCTION: GetProcessTimes
! FUNCTION: GetProcessVersion
! FUNCTION: GetProcessWorkingSetSize
! FUNCTION: GetProfileIntA
! FUNCTION: GetProfileIntW
! FUNCTION: GetProfileSectionA
! FUNCTION: GetProfileSectionW
! FUNCTION: GetProfileStringA
! FUNCTION: GetProfileStringW
FUNCTION: BOOL GetQueuedCompletionStatus ( HANDLE hCompletionPort, LPDWORD lpNumberOfBytes, void* lpCompletionKey, LPOVERLAPPED lpOverlapped, DWORD dwMilliseconds ) ;
! FUNCTION: GetShortPathNameA
! FUNCTION: GetShortPathNameW
! FUNCTION: GetStartupInfoA
! FUNCTION: GetStartupInfoW
FUNCTION: HANDLE GetStdHandle ( DWORD nStdHandle ) ;
! FUNCTION: GetStringTypeA
! FUNCTION: GetStringTypeExA
! FUNCTION: GetStringTypeExW
! FUNCTION: GetStringTypeW
! FUNCTION: GetSystemDefaultLangID
! FUNCTION: GetSystemDefaultLCID
! FUNCTION: GetSystemDefaultUILanguage
! FUNCTION: GetSystemDirectoryA
! FUNCTION: GetSystemDirectoryW
FUNCTION: void GetSystemInfo ( LPSYSTEM_INFO lpSystemInfo ) ;
! FUNCTION: GetSystemPowerStatus
! FUNCTION: GetSystemRegistryQuota
FUNCTION: void GetSystemTime ( LPSYSTEMTIME lpSystemTime ) ;
! FUNCTION: GetSystemTimeAdjustment
FUNCTION: void GetSystemTimeAsFileTime ( LPFILETIME lpSystemTimeAsFileTime ) ;
! FUNCTION: GetSystemTimes
! FUNCTION: GetSystemWindowsDirectoryA
! FUNCTION: GetSystemWindowsDirectoryW
! FUNCTION: GetSystemWow64DirectoryA
! FUNCTION: GetSystemWow64DirectoryW
! FUNCTION: GetTapeParameters
! FUNCTION: GetTapePosition
! FUNCTION: GetTapeStatus
! FUNCTION: GetTempFileNameA
! FUNCTION: GetTempFileNameW
! FUNCTION: GetTempPathA
! FUNCTION: GetTempPathW
! FUNCTION: GetThreadContext
! FUNCTION: GetThreadIOPendingFlag
! FUNCTION: GetThreadLocale
! FUNCTION: GetThreadPriority
! FUNCTION: GetThreadPriorityBoost
! FUNCTION: GetThreadSelectorEntry
! FUNCTION: GetThreadTimes
! FUNCTION: GetTickCount
! FUNCTION: GetTimeFormatA
! FUNCTION: GetTimeFormatW
FUNCTION: DWORD GetTimeZoneInformation ( LPTIME_ZONE_INFORMATION lpTimeZoneInformation ) ;
! FUNCTION: GetUserDefaultLangID
! FUNCTION: GetUserDefaultLCID
! FUNCTION: GetUserDefaultUILanguage
! FUNCTION: GetUserGeoID
! FUNCTION: GetVDMCurrentDirectories
FUNCTION: DWORD GetVersion ( ) ;
FUNCTION: BOOL GetVersionExW ( LPOSVERSIONINFO lpVersionInfo ) ;
: GetVersionEx GetVersionExW ;
! FUNCTION: GetVolumeInformationA
! FUNCTION: GetVolumeInformationW
! FUNCTION: GetVolumeNameForVolumeMountPointA
! FUNCTION: GetVolumeNameForVolumeMountPointW
! FUNCTION: GetVolumePathNameA
! FUNCTION: GetVolumePathNamesForVolumeNameA
! FUNCTION: GetVolumePathNamesForVolumeNameW
! FUNCTION: GetVolumePathNameW
! FUNCTION: GetWindowsDirectoryA
! FUNCTION: GetWindowsDirectoryW
! FUNCTION: GetWriteWatch
! FUNCTION: GlobalAddAtomA
! FUNCTION: GlobalAddAtomW
FUNCTION: HGLOBAL GlobalAlloc ( UINT uFlags, SIZE_T dwBytes ) ;
! FUNCTION: GlobalCompact
! FUNCTION: GlobalDeleteAtom
! FUNCTION: GlobalFindAtomA
! FUNCTION: GlobalFindAtomW
! FUNCTION: GlobalFix
! FUNCTION: GlobalFlags
! FUNCTION: GlobalFree
! FUNCTION: GlobalGetAtomNameA
! FUNCTION: GlobalGetAtomNameW
! FUNCTION: GlobalHandle
FUNCTION: LPVOID GlobalLock ( HGLOBAL hMem ) ;
FUNCTION: void GlobalMemoryStatus ( LPMEMORYSTATUS lpBuffer ) ;
FUNCTION: BOOL GlobalMemoryStatusEx ( LPMEMORYSTATUSEX lpBuffer ) ;
! FUNCTION: GlobalReAlloc
! FUNCTION: GlobalSize
! FUNCTION: GlobalUnfix
FUNCTION: BOOL GlobalUnlock ( HGLOBAL hMem ) ;
! FUNCTION: GlobalUnWire
! FUNCTION: GlobalWire
! FUNCTION: Heap32First
! FUNCTION: Heap32ListFirst
! FUNCTION: Heap32ListNext
! FUNCTION: Heap32Next
! FUNCTION: HeapAlloc
! FUNCTION: HeapCompact
! FUNCTION: HeapCreate
! FUNCTION: HeapCreateTagsW
! FUNCTION: HeapDestroy
! FUNCTION: HeapExtend
! FUNCTION: HeapFree
! FUNCTION: HeapLock
! FUNCTION: HeapQueryInformation
! FUNCTION: HeapQueryTagW
! FUNCTION: HeapReAlloc
! FUNCTION: HeapSetInformation
! FUNCTION: HeapSize
! FUNCTION: HeapSummary
! FUNCTION: HeapUnlock
! FUNCTION: HeapUsage
! FUNCTION: HeapValidate
! FUNCTION: HeapWalk
! FUNCTION: InitAtomTable
! FUNCTION: InitializeCriticalSection
! FUNCTION: InitializeCriticalSectionAndSpinCount
! FUNCTION: InitializeSListHead
! FUNCTION: InterlockedCompareExchange
! FUNCTION: InterlockedDecrement
! FUNCTION: InterlockedExchange
! FUNCTION: InterlockedExchangeAdd
! FUNCTION: InterlockedFlushSList
! FUNCTION: InterlockedIncrement
! FUNCTION: InterlockedPopEntrySList
! FUNCTION: InterlockedPushEntrySList
! FUNCTION: InvalidateConsoleDIBits
! FUNCTION: IsBadCodePtr
! FUNCTION: IsBadHugeReadPtr
! FUNCTION: IsBadHugeWritePtr
! FUNCTION: IsBadReadPtr
! FUNCTION: IsBadStringPtrA
! FUNCTION: IsBadStringPtrW
! FUNCTION: IsBadWritePtr
! FUNCTION: IsDBCSLeadByte
! FUNCTION: IsDBCSLeadByteEx
! FUNCTION: IsDebuggerPresent
! FUNCTION: IsProcessInJob
FUNCTION: BOOL IsProcessorFeaturePresent ( DWORD ProcessorFeature ) ;
! FUNCTION: IsSystemResumeAutomatic
! FUNCTION: IsValidCodePage
! FUNCTION: IsValidLanguageGroup
! FUNCTION: IsValidLocale
! FUNCTION: IsValidUILanguage
! FUNCTION: IsWow64Process
! FUNCTION: LCMapStringA
! FUNCTION: LCMapStringW
! FUNCTION: LeaveCriticalSection
! FUNCTION: LoadLibraryA
! FUNCTION: LoadLibraryExA
! FUNCTION: LoadLibraryExW
! FUNCTION: LoadLibraryW
! FUNCTION: LoadModule
! FUNCTION: LoadResource
! FUNCTION: LocalAlloc
! FUNCTION: LocalCompact
! FUNCTION: LocalFileTimeToFileTime
! FUNCTION: LocalFlags
FUNCTION: HLOCAL LocalFree ( HLOCAL hMem ) ;
! FUNCTION: LocalHandle
! FUNCTION: LocalLock
! FUNCTION: LocalReAlloc
! FUNCTION: LocalShrink
! FUNCTION: LocalSize
! FUNCTION: LocalUnlock
! FUNCTION: LockFile
! FUNCTION: LockFileEx
! FUNCTION: LockResource
! FUNCTION: lstrcat
! FUNCTION: lstrcatA
! FUNCTION: lstrcatW
! FUNCTION: lstrcmp
! FUNCTION: lstrcmpA
! FUNCTION: lstrcmpi
! FUNCTION: lstrcmpiA
! FUNCTION: lstrcmpiW
! FUNCTION: lstrcmpW
! FUNCTION: lstrcpy
! FUNCTION: lstrcpyA
! FUNCTION: lstrcpyn
! FUNCTION: lstrcpynA
! FUNCTION: lstrcpynW
! FUNCTION: lstrcpyW
! FUNCTION: lstrlen
! FUNCTION: lstrlenA
! FUNCTION: lstrlenW
! FUNCTION: LZClose
! FUNCTION: LZCloseFile
! FUNCTION: LZCopy
! FUNCTION: LZCreateFileW
! FUNCTION: LZDone
! FUNCTION: LZInit
! FUNCTION: LZOpenFileA
! FUNCTION: LZOpenFileW
! FUNCTION: LZRead
! FUNCTION: LZSeek
! FUNCTION: LZStart
! FUNCTION: MapUserPhysicalPages
! FUNCTION: MapUserPhysicalPagesScatter
FUNCTION: LPVOID MapViewOfFile ( HANDLE hFileMappingObject,
                                 DWORD dwDesiredAccess,
                                 DWORD dwFileOffsetHigh,
                                 DWORD dwFileOffsetLow,
                                 SIZE_T dwNumberOfBytesToMap ) ;

FUNCTION: LPVOID MapViewOfFileEx ( HANDLE hFileMappingObject,
                                 DWORD dwDesiredAccess,
                                 DWORD dwFileOffsetHigh,
                                 DWORD dwFileOffsetLow,
                                 SIZE_T dwNumberOfBytesToMap,
                                 LPVOID lpBaseAddress ) ;

! FUNCTION: Module32First
! FUNCTION: Module32FirstW
! FUNCTION: Module32Next
! FUNCTION: Module32NextW
! FUNCTION: MoveFileA
! FUNCTION: MoveFileExA
! FUNCTION: MoveFileExW
FUNCTION: BOOL MoveFileW ( LPCTSTR lpExistingFileName, LPCTSTR lpNewFileName ) ;
: MoveFile MoveFileW ;
! FUNCTION: MoveFileWithProgressA
! FUNCTION: MoveFileWithProgressW
! FUNCTION: MulDiv
! FUNCTION: MultiByteToWideChar
! FUNCTION: NlsConvertIntegerToString
! FUNCTION: NlsGetCacheUpdateCount
! FUNCTION: NlsResetProcessLocale
! FUNCTION: NumaVirtualQueryNode
! FUNCTION: OpenConsoleW
! FUNCTION: OpenDataFile
! FUNCTION: OpenEventA
! FUNCTION: OpenEventW
! WARNING: OpenFile is limited to paths of 128 chars in length.  Do not use!
! FUNCTION: HFILE OpenFile ( LPCTSTR lpFileName, LPOFSTRUCT lpReOpenBuff, UINT uStyle ) ;
FUNCTION: HANDLE OpenFileMappingW ( DWORD dwDesiredAccess,
                                    BOOL bInheritHandle,
                                    LPCTSTR lpName ) ;
: OpenFileMapping OpenFileMappingW ;
! FUNCTION: OpenJobObjectA
! FUNCTION: OpenJobObjectW
! FUNCTION: OpenMutexA
! FUNCTION: OpenMutexW
FUNCTION: HANDLE OpenProcess ( DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId ) ;
! FUNCTION: OpenProfileUserMapping
! FUNCTION: OpenSemaphoreA
! FUNCTION: OpenSemaphoreW
! FUNCTION: OpenThread
! FUNCTION: OpenWaitableTimerA
! FUNCTION: OpenWaitableTimerW
! FUNCTION: OutputDebugStringA
! FUNCTION: OutputDebugStringW
! FUNCTION: PeekConsoleInputA
! FUNCTION: PeekConsoleInputW
! FUNCTION: PeekNamedPipe
! FUNCTION: PostQueuedCompletionStatus
! FUNCTION: PrepareTape
! FUNCTION: PrivCopyFileExW
! FUNCTION: PrivMoveFileIdentityW
! FUNCTION: Process32First
! FUNCTION: Process32FirstW
! FUNCTION: Process32Next
! FUNCTION: Process32NextW
! FUNCTION: ProcessIdToSessionId
! FUNCTION: PulseEvent
! FUNCTION: PurgeComm
! FUNCTION: QueryActCtxW
! FUNCTION: QueryDepthSList
! FUNCTION: QueryDosDeviceA
! FUNCTION: QueryDosDeviceW
! FUNCTION: QueryInformationJobObject
! FUNCTION: QueryMemoryResourceNotification
! FUNCTION: QueryPerformanceCounter
! FUNCTION: QueryPerformanceFrequency
! FUNCTION: QueryWin31IniFilesMappedToRegistry
! FUNCTION: QueueUserAPC
! FUNCTION: QueueUserWorkItem
! FUNCTION: RaiseException
! FUNCTION: ReadConsoleA
! FUNCTION: ReadConsoleInputA
! FUNCTION: ReadConsoleInputExA
! FUNCTION: ReadConsoleInputExW
! FUNCTION: ReadConsoleInputW
! FUNCTION: ReadConsoleOutputA
! FUNCTION: ReadConsoleOutputAttribute
! FUNCTION: ReadConsoleOutputCharacterA
! FUNCTION: ReadConsoleOutputCharacterW
! FUNCTION: ReadConsoleOutputW
! FUNCTION: ReadConsoleW
! FUNCTION: ReadDirectoryChangesW
FUNCTION: BOOL ReadFile ( HANDLE hFile, int lpBuffer, DWORD nNumberOfBytesToRead, void* lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped ) ;
! FUNCTION: BOOL ReadFile ( HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped ) ;
! FUNCTION: ReadFileEx
! FUNCTION: ReadFileScatter
FUNCTION: BOOL ReadProcessMemory ( HANDLE hProcess, void* lpBaseAddress, void* lpBuffer, long nSize, long* lpNumberOfBytesRead )  ;
! FUNCTION: RegisterConsoleIME
! FUNCTION: RegisterConsoleOS2
! FUNCTION: RegisterConsoleVDM
! FUNCTION: RegisterWaitForInputIdle
! FUNCTION: RegisterWaitForSingleObject
! FUNCTION: RegisterWaitForSingleObjectEx
! FUNCTION: RegisterWowBaseHandlers
! FUNCTION: RegisterWowExec
! FUNCTION: ReleaseActCtx
! FUNCTION: ReleaseMutex
! FUNCTION: ReleaseSemaphore
! FUNCTION: RemoveDirectoryA
FUNCTION: BOOL RemoveDirectoryW ( LPCTSTR lpPathName ) ;
: RemoveDirectory RemoveDirectoryW ;
! FUNCTION: RemoveLocalAlternateComputerNameA
! FUNCTION: RemoveLocalAlternateComputerNameW
! FUNCTION: RemoveVectoredExceptionHandler
! FUNCTION: ReplaceFile
! FUNCTION: ReplaceFileA
! FUNCTION: ReplaceFileW
! FUNCTION: RequestDeviceWakeup
! FUNCTION: RequestWakeupLatency
! FUNCTION: ResetEvent
! FUNCTION: ResetWriteWatch
! FUNCTION: RestoreLastError
! FUNCTION: ResumeThread
! FUNCTION: RtlCaptureContext
! FUNCTION: RtlCaptureStackBackTrace
! FUNCTION: RtlFillMemory
! FUNCTION: RtlMoveMemory
! FUNCTION: RtlUnwind
! FUNCTION: RtlZeroMemory
! FUNCTION: ScrollConsoleScreenBufferA
! FUNCTION: ScrollConsoleScreenBufferW
! FUNCTION: SearchPathA
! FUNCTION: SearchPathW
! FUNCTION: SetCalendarInfoA
! FUNCTION: SetCalendarInfoW
! FUNCTION: SetClientTimeZoneInformation
! FUNCTION: SetCommBreak
! FUNCTION: SetCommConfig
! FUNCTION: SetCommMask
! FUNCTION: SetCommState
! FUNCTION: SetCommTimeouts
! FUNCTION: SetComPlusPackageInstallStatus
! FUNCTION: SetComputerNameA
! FUNCTION: SetComputerNameExA
! FUNCTION: SetComputerNameExW
! FUNCTION: SetComputerNameW
! FUNCTION: SetConsoleActiveScreenBuffer
! FUNCTION: SetConsoleCommandHistoryMode
! FUNCTION: SetConsoleCP
! FUNCTION: SetConsoleCtrlHandler
! FUNCTION: SetConsoleCursor
! FUNCTION: SetConsoleCursorInfo
! FUNCTION: SetConsoleCursorMode
! FUNCTION: SetConsoleCursorPosition
! FUNCTION: SetConsoleDisplayMode
! FUNCTION: SetConsoleFont
! FUNCTION: SetConsoleHardwareState
! FUNCTION: SetConsoleIcon
! FUNCTION: SetConsoleInputExeNameA
! FUNCTION: SetConsoleInputExeNameW
! FUNCTION: SetConsoleKeyShortcuts
! FUNCTION: SetConsoleLocalEUDC
! FUNCTION: SetConsoleMaximumWindowSize
! FUNCTION: SetConsoleMenuClose
! FUNCTION: SetConsoleMode
! FUNCTION: SetConsoleNlsMode
! FUNCTION: SetConsoleNumberOfCommandsA
! FUNCTION: SetConsoleNumberOfCommandsW
! FUNCTION: SetConsoleOS2OemFormat
! FUNCTION: SetConsoleOutputCP
! FUNCTION: SetConsolePalette
! FUNCTION: SetConsoleScreenBufferSize
FUNCTION: BOOL SetConsoleTextAttribute ( HANDLE hConsoleOutput, WORD wAttributes ) ;
FUNCTION: BOOL SetConsoleTitleW ( LPCWSTR lpConsoleTitle ) ;
: SetConsoleTitle SetConsoleTitleW ;
! FUNCTION: SetConsoleWindowInfo
! FUNCTION: SetCPGlobal
! FUNCTION: SetCriticalSectionSpinCount
! FUNCTION: SetCurrentDirectoryA
! FUNCTION: SetCurrentDirectoryW
! FUNCTION: SetDefaultCommConfigA
! FUNCTION: SetDefaultCommConfigW
! FUNCTION: SetDllDirectoryA
! FUNCTION: SetDllDirectoryW
FUNCTION: BOOL SetEndOfFile ( HANDLE hFile ) ;
! FUNCTION: SetEnvironmentVariableA
! FUNCTION: SetEnvironmentVariableW
! FUNCTION: SetErrorMode
! FUNCTION: SetEvent
! FUNCTION: SetFileApisToANSI
! FUNCTION: SetFileApisToOEM
! FUNCTION: SetFileAttributesA
! FUNCTION: SetFileAttributesW
FUNCTION: DWORD SetFilePointer ( HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod ) ;
FUNCTION: DWORD SetFilePointerEx ( HANDLE hFile, LARGE_INTEGER lDistanceToMove, PLARGE_INTEGER lpDistanceToMoveHigh, DWORD dwMoveMethod ) ;
! FUNCTION: SetFileShortNameA
! FUNCTION: SetFileShortNameW
FUNCTION: BOOL SetFileTime ( HANDLE hFile, FILETIME* lpCreationTime, FILETIME* lpLastAccessTime, FILETIME* lpLastWriteTime ) ;
! FUNCTION: SetFileValidData
! FUNCTION: SetFirmwareEnvironmentVariableA
! FUNCTION: SetFirmwareEnvironmentVariableW
! FUNCTION: SetHandleContext
! FUNCTION: SetHandleCount
! FUNCTION: SetHandleInformation
! FUNCTION: SetInformationJobObject
! FUNCTION: SetLastConsoleEventActive
! FUNCTION: SetLastError
! FUNCTION: SetLocaleInfoA
! FUNCTION: SetLocaleInfoW
! FUNCTION: SetLocalPrimaryComputerNameA
! FUNCTION: SetLocalPrimaryComputerNameW
! FUNCTION: SetLocalTime
! FUNCTION: SetMailslotInfo
! FUNCTION: SetMessageWaitingIndicator
! FUNCTION: SetNamedPipeHandleState
! FUNCTION: SetPriorityClass
! FUNCTION: SetProcessAffinityMask
! FUNCTION: SetProcessPriorityBoost
! FUNCTION: SetProcessShutdownParameters
! FUNCTION: SetProcessWorkingSetSize
! FUNCTION: SetStdHandle
! FUNCTION: SetSystemPowerState
! FUNCTION: SetSystemTime
! FUNCTION: SetSystemTimeAdjustment
! FUNCTION: SetTapeParameters
! FUNCTION: SetTapePosition
! FUNCTION: SetTermsrvAppInstallMode
! FUNCTION: SetThreadAffinityMask
! FUNCTION: SetThreadContext
! FUNCTION: SetThreadExecutionState
! FUNCTION: SetThreadIdealProcessor
! FUNCTION: SetThreadLocale
! FUNCTION: SetThreadPriority
! FUNCTION: SetThreadPriorityBoost
! FUNCTION: SetThreadUILanguage
! FUNCTION: SetTimerQueueTimer
! FUNCTION: SetTimeZoneInformation
! FUNCTION: SetUnhandledExceptionFilter
! FUNCTION: SetupComm
! FUNCTION: SetUserGeoID
! FUNCTION: SetVDMCurrentDirectories
! FUNCTION: SetVolumeLabelA
! FUNCTION: SetVolumeLabelW
! FUNCTION: SetVolumeMountPointA
! FUNCTION: SetVolumeMountPointW
! FUNCTION: SetWaitableTimer
! FUNCTION: ShowConsoleCursor
! FUNCTION: SignalObjectAndWait
! FUNCTION: SizeofResource
! FUNCTION: Sleep
FUNCTION: DWORD SleepEx ( DWORD dwMilliSeconds, BOOL bAlertable ) ;
! FUNCTION: SuspendThread
! FUNCTION: SwitchToFiber
! FUNCTION: SwitchToThread
FUNCTION: BOOL SystemTimeToFileTime ( SYSTEMTIME* lpSystemTime, LPFILETIME lpFileTime ) ;
! FUNCTION: SystemTimeToTzSpecificLocalTime
! FUNCTION: TerminateJobObject
! FUNCTION: TerminateProcess
! FUNCTION: TerminateThread
! FUNCTION: TermsrvAppInstallMode
! FUNCTION: Thread32First
! FUNCTION: Thread32Next
! FUNCTION: TlsAlloc
! FUNCTION: TlsFree
! FUNCTION: TlsGetValue
! FUNCTION: TlsSetValue
! FUNCTION: Toolhelp32ReadProcessMemory
! FUNCTION: TransactNamedPipe
! FUNCTION: TransmitCommChar
! FUNCTION: TrimVirtualBuffer
! FUNCTION: TryEnterCriticalSection
! FUNCTION: TzSpecificLocalTimeToSystemTime
! FUNCTION: UnhandledExceptionFilter
! FUNCTION: UnlockFile
! FUNCTION: UnlockFileEx
FUNCTION: BOOL UnmapViewOfFile ( LPCVOID lpBaseAddress ) ;
! FUNCTION: UnregisterConsoleIME
! FUNCTION: UnregisterWait
! FUNCTION: UnregisterWaitEx
! FUNCTION: UpdateResourceA
! FUNCTION: UpdateResourceW
! FUNCTION: UTRegister
! FUNCTION: UTUnRegister
! FUNCTION: ValidateLCType
! FUNCTION: ValidateLocale
! FUNCTION: VDMConsoleOperation
! FUNCTION: VDMOperationStarted
! FUNCTION: VerifyConsoleIoHandle
! FUNCTION: VerifyVersionInfoA
! FUNCTION: VerifyVersionInfoW
! FUNCTION: VerLanguageNameA
! FUNCTION: VerLanguageNameW
! FUNCTION: VerSetConditionMask
! FUNCTION: VirtualAlloc
FUNCTION: HANDLE VirtualAllocEx ( HANDLE hProcess, void* lpAddress, long dwSize, DWORD flAllocationType, DWORD flProtect ) ;
! FUNCTION: VirtualBufferExceptionHandler
! FUNCTION: VirtualFree
FUNCTION: BOOL VirtualFreeEx ( HANDLE hProcess, void* lpAddress, long dwSize, DWORD dwFreeType ) ;
! FUNCTION: VirtualLock
! FUNCTION: VirtualProtect
! FUNCTION: VirtualProtectEx
! FUNCTION: VirtualQuery
FUNCTION: BOOL VirtualQueryEx ( HANDLE hProcess, void* lpAddress, MEMORY_BASIC_INFORMATION* lpBuffer, SIZE_T dwLength ) ;
! FUNCTION: VirtualUnlock
! FUNCTION: WaitCommEvent
! FUNCTION: WaitForDebugEvent
! FUNCTION: WaitForMultipleObjects
! FUNCTION: WaitForMultipleObjectsEx
! FUNCTION: WaitForSingleObject
! FUNCTION: WaitForSingleObjectEx
! FUNCTION: WaitNamedPipeA
! FUNCTION: WaitNamedPipeW
! FUNCTION: WideCharToMultiByte
! FUNCTION: WinExec
! FUNCTION: WriteConsoleA
! FUNCTION: WriteConsoleInputA
! FUNCTION: WriteConsoleInputVDMA
! FUNCTION: WriteConsoleInputVDMW
! FUNCTION: WriteConsoleInputW
! FUNCTION: WriteConsoleOutputA
! FUNCTION: WriteConsoleOutputAttribute
! FUNCTION: WriteConsoleOutputCharacterA
! FUNCTION: WriteConsoleOutputCharacterW
! FUNCTION: WriteConsoleOutputW
! FUNCTION: WriteConsoleW
FUNCTION: BOOL WriteFile ( HANDLE hFile, int lpBuffer, DWORD nNumberOfBytesToWrite, void* lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped ) ;
! FUNCTION: WriteFileEx
! FUNCTION: WriteFileGather
! FUNCTION: WritePrivateProfileSectionA
! FUNCTION: WritePrivateProfileSectionW
! FUNCTION: WritePrivateProfileStringA
! FUNCTION: WritePrivateProfileStringW
! FUNCTION: WritePrivateProfileStructA
! FUNCTION: WritePrivateProfileStructW
FUNCTION: BOOL WriteProcessMemory ( HANDLE hProcess, void* lpBaseAddress, void* lpBuffer, long nSize, long* lpNumberOfBytesWritten )  ;
! FUNCTION: WriteProfileSectionA
! FUNCTION: WriteProfileSectionW
! FUNCTION: WriteProfileStringA
! FUNCTION: WriteProfileStringW
! FUNCTION: WriteTapemark
! FUNCTION: WTSGetActiveConsoleSessionId
! FUNCTION: ZombifyActCtx