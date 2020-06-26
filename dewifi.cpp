/**
  Copyright (C) 2016, 2017 Odzhan. All Rights Reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:

  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  3. The name of the author may not be used to endorse or promote products
  derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE. */
  
#define _WIN32_IE 0x0500
#define UNICODE

#include <windows.h>
#include <wincrypt.h>
#include <Shlwapi.h>
#include <Shlobj.h>
#include <tlhelp32.h>
#include <msxml2.h>

#include <string>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#pragma comment (lib, "advapi32.lib")
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "shlwapi.lib")
#pragma comment (lib, "Shell32.lib")
#pragma comment (lib, "ole32.lib")
#pragma comment (lib, "oleaut32.lib")
#pragma comment (lib, "msxml2.lib")

/**
 *
 *  Determines if process token is elevated
 *  Returns TRUE or FALSE
 *
 */
BOOL isElevated(VOID) {
    HANDLE          hToken;
    BOOL            bResult = FALSE;
    TOKEN_ELEVATION te;
    DWORD           dwSize;
      
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
      if (GetTokenInformation(hToken, TokenElevation, &te, 
          sizeof(TOKEN_ELEVATION), &dwSize)) {
        bResult = te.TokenIsElevated != 0;
      }
      CloseHandle(hToken);
    }
    return bResult;
}

/**
 *
 *  Enables or disables a named privilege in token
 *  Returns TRUE or FALSE
 *
 */
BOOL SetPrivilege(wchar_t szPrivilege[], BOOL bEnable) {
    HANDLE           hToken;
    BOOL             bResult;
    LUID             luid;
    TOKEN_PRIVILEGES tp;
    
    bResult = OpenProcessToken(GetCurrentProcess(), 
      TOKEN_ADJUST_PRIVILEGES, &hToken);
    
    if (bResult) {    
      bResult = LookupPrivilegeValue(NULL, szPrivilege, &luid);
      if (bResult) {
        tp.PrivilegeCount           = 1;
        tp.Privileges[0].Luid       = luid;
        tp.Privileges[0].Attributes = (bEnable) ? SE_PRIVILEGE_ENABLED : 0;

        AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
        bResult = GetLastError() == ERROR_SUCCESS;
      }
      CloseHandle(hToken);
    }
    return bResult;
}

/**F*****************************************************************/
void xstrerror (wchar_t *fmt, ...) 
/**
 * PURPOSE : Display windows error
 *
 * RETURN :  Nothing
 *
 * NOTES :   None
 *
 *F*/
{
    wchar_t *error=NULL;
    va_list arglist;
    wchar_t buffer[2048];
    DWORD   dwError=GetLastError();
    
    va_start (arglist, fmt);
    wvnsprintf (buffer, 2048, fmt, arglist);
    va_end (arglist);
    
    if (FormatMessage (
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        NULL, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
        (LPWSTR)&error, 0, NULL))
    {
      wprintf (L"[ %s : %s\n", buffer, error);
      LocalFree (error);
    } else {
      wprintf (L"[ %s : %i\n", buffer, dwError);
    }
}

/**
 *
 *  Obtain process id of process name
 *
 *  Returns process id or zero
 *
 */
DWORD GetProcessId(wchar_t szName[]) {
    DWORD          dwId = 0;
    HANDLE         hSnap;
    BOOL           bResult;
    PROCESSENTRY32 pe32;
    
    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (hSnap != INVALID_HANDLE_VALUE) {
      pe32.dwSize = sizeof(PROCESSENTRY32);
      
      bResult = Process32First(hSnap, &pe32);
      while (bResult) {
        if (lstrcmpi(pe32.szExeFile, szName) == 0) {
          dwId = pe32.th32ProcessID;
          break;
        }
        bResult = Process32Next(hSnap, &pe32);
      }
      CloseHandle(hSnap);
    }
    return dwId;
}

BOOL ImpersonateSystem(VOID) {
    BOOL   bImpersonating = FALSE;
    HANDLE hToken, hProcess;
    // get id of a LocalSystem process
    DWORD  dwId = GetProcessId(L"lsass.exe");
    
    if (dwId != 0) {
      // enable debug privilege
      if (SetPrivilege(SE_DEBUG_NAME, TRUE)) {
        // attempt to open process
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwId);
        if (hProcess != NULL) {
          // attempt to open process token
          if (OpenProcessToken(hProcess, 
              TOKEN_IMPERSONATE | TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
            // attempt to impersonate LocalSystem
            bImpersonating = ImpersonateLoggedOnUser(hToken);
            if (!bImpersonating) {
              xstrerror(L"ImpersonateLoggedOnUser");
            }
            CloseHandle(hToken);
          } else {
            xstrerror(L"OpenProcessToken");
          }
          CloseHandle(hProcess);
        } else {
          xstrerror(L"OpenProcess(\"lsass.exe\")");
        }
      } else {
        xstrerror(L"SetPrivilege(SE_DEBUG_NAME, TRUE)");
      }
    } else {
      xstrerror(L"GetProcessId(\"lsass.exe\")");
    }
    return bImpersonating;
}
    
/**
 *
 *  Impersonate token of LocalSystem process
 *  Decrypt key with CryptUnprotectData 
 *  Display both the ascii and hex value of key
 *  
 */
void DecryptKey(std::wstring key) {
    static bool bImpersonating = false;
    BYTE        byteKey[2048];
    DWORD       dwLength = 2048;
    DATA_BLOB   in, out;
    char        buffer[1024] = {0};
      
    // if not impersonating LocalSystem
    if (!bImpersonating) {
      bImpersonating = ImpersonateSystem();
    }

    if (bImpersonating) {
      if (CryptStringToBinary(key.c_str(), key.length(), 
          CRYPT_STRING_HEX, byteKey, &dwLength, 0, 0)) {
          
        in.pbData = byteKey;
        in.cbData = dwLength;
        
        if (CryptUnprotectData(&in, NULL, NULL, 
            NULL, NULL, 0, &out)) 
        {
          if (out.cbData != 0) {        
            memcpy(buffer, out.pbData, out.cbData);
            printf("  %-64s  ", buffer);
            
            for (int i = 0; i < out.cbData; i++) {
              wprintf(L"%02x", out.pbData[i]);
            }
            LocalFree(out.pbData);
          } else xstrerror(L"CryptUnprotectData");
        } else {
          xstrerror(L"CryptUnprotectData()");
        }
      } else xstrerror(L"CryptStringToBinary"); 
    }
}

/**
 *
 *  obtains and returns text of node
 *
 */
std::wstring get_text(
  IXMLDOMDocument2 *pDoc, 
  PWCHAR pt, 
  PWCHAR subNode) 
{
    std::wstring         text = L"";
    IXMLDOMNode          *pNode = NULL;
    HRESULT              hr;
    BSTR                 bstrText;
    IXMLDOMNode          *pChild = NULL;
    std::wstring         nodeString = pt;
    
    nodeString += subNode;
    
    hr = pDoc->selectSingleNode(BSTR(nodeString.c_str()), &pNode);
    
    if (SUCCEEDED(hr) && pNode != NULL) {    
      hr = pNode->get_firstChild(&pChild);
      if (SUCCEEDED(hr) && pChild != NULL) {      
        hr = pChild->get_text(&bstrText);
        if (SUCCEEDED(hr)) {
          text = bstrText;
        } 
      } 
    } 
    return text;
}

// required to parse WLAN profiles
#define WLAN_NS   L"xmlns:s=\"http://www.microsoft.com/networking/WLAN/profile/v1\""
#define WLANAP_NS L"xmlns:s=\"http://www.microsoft.com/networking/WLANAP/profile/v1\""

void profile_properties(IXMLDOMDocument2 *pDoc, DWORD idx)
{
    PWCHAR       xml[2]={WLAN_NS, WLANAP_NS};
    PWCHAR       profiles[2]={L"WLANProfile", L"WLANAPProfile"};
    HRESULT      hr;
    VARIANT      ns;
    PWCHAR       pt;
    std::wstring ssid, auth, enc, key;
    
    V_VT(&ns) = VT_BSTR;
    V_BSTR(&ns) = SysAllocString(xml[idx]);
    pt = profiles[idx];
    hr = pDoc->setProperty(BSTR(L"SelectionNamespaces"), ns);

    if (SUCCEEDED(hr)) {    
      ssid = get_text(pDoc, pt, L"/s:SSIDConfig/s:SSID/s:name");
      auth = get_text(pDoc, pt, L"/s:MSM/s:security/s:authEncryption/s:authentication");
      enc  = get_text(pDoc, pt, L"/s:MSM/s:security/s:authEncryption/s:encryption");
      key  = get_text(pDoc, pt, L"/s:MSM/s:security/s:sharedKey/s:keyMaterial");
      
      if (!ssid.empty()) {
        wprintf(L"\n  %-20s  %-10s  %-20s", ssid.c_str(), auth.c_str(), enc.c_str());
      
        if (!key.empty()) {
          DecryptKey(key);
        }
      }
    } else {
      wprintf(L"\n  IXMLDOMDocument2->setProperty() failed : %08x", hr);
    }
}
    
/**
 *  
 *  DumpWLANProfile(wchar_t adapterGuid[], wchar_t profileGuid[])
 *  
 *
 */
void DumpWLANProfile(
  wchar_t adapterGuid[], 
  wchar_t profileGuid[]) 
{
    wchar_t                   path[MAX_PATH];
    wchar_t                   programData[MAX_PATH];
    HRESULT                   hr;
    IXMLDOMDocument2          *pDoc;
    VARIANT_BOOL              bIsSuccessful;
    VARIANT                   vpath;
    
    SHGetFolderPath(NULL, CSIDL_COMMON_APPDATA, 
        NULL, SHGFP_TYPE_CURRENT, programData);
        
    _snwprintf(path, MAX_PATH, 
      L"%s\\Microsoft\\Wlansvc\\Profiles\\Interfaces\\%s\\%s.xml", 
      programData, adapterGuid, profileGuid);

    hr = CoInitialize(NULL);
    if (FAILED(hr)) {
      wprintf(L"\nCoInitialize() failed : %08x", hr);
      return;
    }  
    
    hr = CoCreateInstance(CLSID_DOMDocument30, 
        NULL, CLSCTX_INPROC_SERVER,
        IID_IXMLDOMDocument2, (void**)&pDoc);
        
    if (SUCCEEDED(hr)) {
      VariantInit(&vpath);
      V_VT(&vpath) = VT_BSTR;
      V_BSTR(&vpath) = SysAllocString(path);
      pDoc->put_async(VARIANT_FALSE);
      hr = pDoc->load(vpath, &bIsSuccessful);
      
      if (SUCCEEDED(hr) && bIsSuccessful == VARIANT_TRUE) {
        profile_properties(pDoc, 0);
        profile_properties(pDoc, 1);
      } else {
        DWORD err = GetLastError();
        wprintf(L"\n  IXMLDOMDocument2->load(%s) failed : %08x : %i", path, hr, err);
      }
      pDoc = NULL;
    } else {
      wprintf(L"\n  CoCreateInstance() failed : %08x", hr);
    }
    CoUninitialize();
}

/**
 *
 *  If available, obtain adapter description for GUID
 *
 */
std::wstring GetAdapterDescription(std::wstring guid) {
    static       DWORD dwCtrlIdx = 0;
    LSTATUS      lStatus;
    DWORD        cbSize;
    std::wstring description = L"<unavailable>";
    wchar_t      path[1024], pnpInstance[1024], deviceDesc[1024];
    PWCHAR       pDesc;
    
    if (dwCtrlIdx == 0) {
      cbSize = sizeof(DWORD);
      lStatus = SHGetValue(HKEY_LOCAL_MACHINE, L"SYSTEM\\Select", 
          L"Default", 0, &dwCtrlIdx, &cbSize);
      if (lStatus != ERROR_SUCCESS) {
        dwCtrlIdx = 1;
      }
    }
    
    _snwprintf(path, sizeof(path) / sizeof(wchar_t), 
        L"SYSTEM\\ControlSet%03i\\Control\\Network\\"
        L"{4D36E972-E325-11CE-BFC1-08002BE10318}\\%s\\Connection", 
        dwCtrlIdx, guid.c_str());

    cbSize = sizeof(pnpInstance) / sizeof(wchar_t);
    lStatus = SHGetValue(HKEY_LOCAL_MACHINE, path, L"PnpInstanceID", 
        0, pnpInstance, &cbSize);
    if (lStatus == ERROR_SUCCESS) {
      _snwprintf(path, 1024, L"SYSTEM\\ControlSet%03i\\Enum\\%s", 
          dwCtrlIdx, pnpInstance);
    
      cbSize = sizeof(deviceDesc) / sizeof(wchar_t);
      lStatus = SHGetValue(HKEY_LOCAL_MACHINE, path, L"DeviceDesc", 
          0, &deviceDesc, &cbSize);
      pDesc = wcsrchr(deviceDesc, L';');
      if (pDesc != 0) {
        description = ++pDesc;
      }
    }
    return description;
}

DWORD EnumInterfaces(VOID) {
  HKEY         hSubKey;
  DWORD        dwError, dwIndex, cbSize; 
  WCHAR        adapterGuid[256], profileList[4096*4];
  PWCHAR       pProfileGuid;
  std::wstring description;
  
  dwError = RegOpenKeyEx(HKEY_LOCAL_MACHINE, 
      L"SOFTWARE\\Microsoft\\Wlansvc\\Interfaces", 0, 
      KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, &hSubKey);
  
  if (dwError != ERROR_SUCCESS) {
    xstrerror(L"RegOpenKeyEx(\"SOFTWARE\\Microsoft\\Wlansvc\\Interfaces\"");
    return 0;
  }
  
  dwIndex = 0;
  
  for (;;) {
    cbSize = sizeof(adapterGuid) / sizeof(wchar_t);
    dwError = RegEnumKeyEx(hSubKey, dwIndex, adapterGuid, 
        &cbSize, NULL, NULL, NULL, NULL);
    
    if (dwError != ERROR_SUCCESS) break; 
  
    if (dwError == ERROR_SUCCESS) {
      description = GetAdapterDescription(adapterGuid);
      
      cbSize = sizeof(profileList) / sizeof(wchar_t);
      dwError = RegGetValue(hSubKey, adapterGuid, L"ProfileList", 
          RRF_RT_REG_MULTI_SZ, 0, profileList, &cbSize);
          
      if (dwError == ERROR_SUCCESS) {
        pProfileGuid = profileList;
      wprintf(L"\n\n  %s %s", description.c_str(), adapterGuid);
      
      wprintf(L"\n  %-20s  %-10s  %-20s  %-64s  %-20s", 
          std::wstring(20, L'-').c_str(), 
          std::wstring(10, L'-').c_str(),  
          std::wstring(20, L'-').c_str(), 
          std::wstring(20, L'-').c_str(),
          std::wstring(20, L'-').c_str());
      
      wprintf(L"\n  %-20s  %-10s  %-20s  %-64s  %-20s", 
          L"SSID", L"Auth", L"Encryption", L"Key(Ascii)", L"Key(Hex)");
          
      wprintf(L"\n  %-20s  %-10s  %-20s  %-64s  %-20s", 
          std::wstring(20, L'-').c_str(), 
          std::wstring(10, L'-').c_str(),  
          std::wstring(20, L'-').c_str(), 
          std::wstring(20, L'-').c_str(),
          std::wstring(20, L'-').c_str());
          
        for (;;) {
          DumpWLANProfile(adapterGuid, pProfileGuid);
          pProfileGuid += wcslen(pProfileGuid) + 1;
          if (pProfileGuid[0] == 0) break;
        }
      } 
    }
    dwIndex++;
  }
  RegCloseKey(hSubKey);
  return 0;
}

VOID setw(SHORT X) {
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
    
    if (X <= csbi.dwSize.X) return;
    csbi.dwSize.X  = X;
    SetConsoleScreenBufferSize(GetStdHandle(STD_OUTPUT_HANDLE), csbi.dwSize);  
}

int main(void) {
    setw(300);

    if (!isElevated()) {
      printf("\n  WARNING: Process token requires elevation . . .\n");
    }
    
    EnumInterfaces();
    printf("\n\n  Press any key to continue . . .");
    fgetc(stdin);
    return 0;
}
