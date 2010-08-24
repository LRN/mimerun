/*
    Mimerun - runs files by their mime type

    Copyright (C) 2010 LRN

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#define CINTERFACE
#define COBJMACROS

#include <mimerun/mimerunshook.h>
#include <mimerun/misc.h>
#include <mimerun/mimerunguid.h>
#include <mimerun/mimerun.h>

#include <INITGUID.H>
#include <windows.h>
#include <objbase.h>
#include <shlobj.h>
#include <shlguid.h>


#undef INTERFACE
#define INTERFACE IMimeRunSHook
DECLARE_INTERFACE_(INTERFACE, IShellExecuteHookW)
{
  STDMETHOD(QueryInterface)(THIS_ REFIID, PVOID *);
  STDMETHOD_(ULONG,AddRef)(THIS);
  STDMETHOD_(ULONG,Release)(THIS);
  STDMETHOD(ExecuteW)(THIS_ LPSHELLEXECUTEINFOW);
};
#undef INTERFACE
#define IMimeRunSHook_QueryInterface(p,a,b) ((IMimeRunSHook *)p)->lpVtbl->QueryInterface((IMimeRunSHook *)p,a,b)
#define IMimeRunSHook_AddRef(p)             ((IMimeRunSHook *)p)->lpVtbl->AddRef((IMimeRunSHook *)p)
#define IMimeRunSHook_Release(p)            ((IMimeRunSHook *)p)->lpVtbl->Release((IMimeRunSHook *)p)

#define IMimeRunSHook_GetCount(p)           (((_IMimeRunSHook *)p)->count)
#define IMimeRunSHook_SetCount(p,c)         (((_IMimeRunSHook *)p)->count = c)

typedef struct {
  IMimeRunSHookVtbl *lpVtbl;
  DWORD count;
} _IMimeRunSHook;

HRESULT STDMETHODCALLTYPE MimeRunSHook_QueryInterface (IMimeRunSHook *this, REFIID vTableGuid, void **ppv);
ULONG STDMETHODCALLTYPE MimeRunSHook_AddRef (IMimeRunSHook *this);
ULONG STDMETHODCALLTYPE MimeRunSHook_Release (IMimeRunSHook *this);
HRESULT STDMETHODCALLTYPE MimeRunSHook_ExecuteW (IMimeRunSHook *this, LPSHELLEXECUTEINFOW einfo);

HRESULT STDMETHODCALLTYPE ClassFactory_QueryInterface(IClassFactory *this, REFIID factoryGuid, void **ppv);
ULONG STDMETHODCALLTYPE ClassFactory_AddRef (IClassFactory *this);
ULONG STDMETHODCALLTYPE ClassFactory_Release (IClassFactory *this);
HRESULT STDMETHODCALLTYPE ClassFactory_CreateInstance(IClassFactory *this, IUnknown *agreg, REFIID vTableGuid, void **ppv);
HRESULT STDMETHODCALLTYPE ClassFactory_LockServer (IClassFactory *this, BOOL flock);

static DWORD LockCount = 0;
static DWORD OutstandingObjects = 0;

static IMimeRunSHookVtbl _IMimeRunSHookVtbl =
{
  MimeRunSHook_QueryInterface,
  MimeRunSHook_AddRef,
  MimeRunSHook_Release,
  MimeRunSHook_ExecuteW,
};

static IClassFactoryVtbl _IClassFactoryVtbl =
{
  ClassFactory_QueryInterface,
  ClassFactory_AddRef,
  ClassFactory_Release,
  ClassFactory_CreateInstance,
  ClassFactory_LockServer
};

static IClassFactory ClassFactory = {&_IClassFactoryVtbl};

ULONG STDMETHODCALLTYPE ClassFactory_AddRef (IClassFactory *this)
{
  return 1;
}

ULONG STDMETHODCALLTYPE ClassFactory_Release (IClassFactory *this)
{
  return 1;
}

HRESULT STDMETHODCALLTYPE ClassFactory_QueryInterface (IClassFactory *this, REFIID factoryGuid, void **ppv)
{
  if (!IsEqualIID(factoryGuid, &IID_IUnknown) && !IsEqualIID(factoryGuid, &IID_IClassFactory))
  {
    *ppv = 0;
    return E_NOINTERFACE;
  }
  *ppv = this;
  IClassFactory_AddRef(this);
  return NOERROR;
}

HRESULT STDMETHODCALLTYPE ClassFactory_LockServer (IClassFactory *this, BOOL flock)
{
  if (flock)
    InterlockedIncrement (&LockCount);
  else
    InterlockedDecrement (&LockCount);
  return NOERROR;
}

HRESULT STDMETHODCALLTYPE ClassFactory_CreateInstance(IClassFactory *this, IUnknown *agreg, REFIID vTableGuid, void **ppv)
{
  HRESULT hr;
  _IMimeRunSHook *thisobj;

  *ppv = 0;
  if (agreg != NULL)
    hr = CLASS_E_NOAGGREGATION;
  else
  {
    if (!(thisobj = GlobalAlloc (GMEM_FIXED, sizeof(_IMimeRunSHook))))
      hr = E_OUTOFMEMORY;
    else
    {
      thisobj->lpVtbl = &_IMimeRunSHookVtbl;
      IMimeRunSHook_AddRef(thisobj);

      hr = IMimeRunSHook_QueryInterface(thisobj, vTableGuid, ppv);

      IMimeRunSHook_Release(thisobj);

      if (hr == NOERROR)
        InterlockedIncrement (&OutstandingObjects);
    }
  }
  return hr;
}

HRESULT STDMETHODCALLTYPE MimeRunSHook_QueryInterface (IMimeRunSHook * this, REFIID vTableGuid, void **ppv)
{
  if (!IsEqualIID(vTableGuid, &IID_IMimeRunSHook) && !IsEqualIID(vTableGuid, &IID_IShellExecuteHookW))
  {
    *ppv = 0;
    return E_NOINTERFACE;
  }
  *ppv = this;
  IMimeRunSHook_AddRef (this);
  return NOERROR;
}

ULONG STDMETHODCALLTYPE MimeRunSHook_AddRef (IMimeRunSHook * this)
{
  IMimeRunSHook_SetCount(this, IMimeRunSHook_GetCount(this) + 1);
  return IMimeRunSHook_GetCount(this);
}

ULONG STDMETHODCALLTYPE MimeRunSHook_Release (IMimeRunSHook * this)
{
  IMimeRunSHook_SetCount(this, IMimeRunSHook_GetCount(this) - 1);
  if (IMimeRunSHook_GetCount(this) == 0)
  {
    GlobalFree(this);
    InterlockedDecrement (&OutstandingObjects);
    return 0;
  }
  return IMimeRunSHook_GetCount(this);
}

HRESULT __stdcall DllGetClassObject (REFCLSID rclsid, REFIID riid, LPVOID * ppvObj)
{
  HRESULT hr; 
  *ppvObj = NULL; 

  if (IsEqualIID(rclsid, &CLSID_IMimeRunSHook))
    hr = IClassFactory_QueryInterface(&ClassFactory, riid, ppvObj);
  else
  {
    *ppvObj = 0;
    hr = CLASS_E_CLASSNOTAVAILABLE;
  }
  return hr;
} 

HRESULT __stdcall DllCanUnloadNow (void)
{
  return (OutstandingObjects | LockCount) ? S_FALSE : S_OK;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
  if (fdwReason == DLL_PROCESS_ATTACH)
  {
    LockCount = 0;
    OutstandingObjects = 0;
  }
  else if (fdwReason == DLL_PROCESS_DETACH)
  {
  }
  else if (fdwReason == DLL_THREAD_ATTACH)
  {
    HRESULT hr;
    if ((hr = CoInitializeEx (NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE)) != S_OK)
    {
      if (hr != S_FALSE)
        return FALSE;
    }
  }
  else if (fdwReason == DLL_THREAD_DETACH)
  {
    CoUninitialize ();
  }
  return TRUE;
}

HRESULT STDMETHODCALLTYPE MimeRunSHook_ExecuteW (IMimeRunSHook *this, LPSHELLEXECUTEINFOW einfo)
{
  wchar_t filename[MAX_PATH] = {0};
  DWORD dw;
  int res;
  wchar_t *lpfile = NULL, *lpdirectory = NULL;
  BOOL freefile = TRUE, freedir = TRUE;
  HRESULT hr = S_FALSE;
  wchar_t *logfile = NULL;
  HKEY mimerunkey = NULL;
  ULONG store_fmask = 0;

  if (einfo == NULL)
    return S_FALSE;

  store_fmask = einfo->fMask;

  get_sz_key (HKEY_CURRENT_USER, L"Software\\mimerun", L"debug", &logfile, KEY_WOW64_32KEY);
  if (logfile == NULL)
    get_sz_key (HKEY_LOCAL_MACHINE, L"Software\\mimerun", L"debug", &logfile, KEY_WOW64_32KEY);

  /* A special hack. If it's true, set SEE_MASK_NO_CONSOLE in einfo->fMask, otherwise - clear it,
   * unless the caller doesn't actually have a console.
   */
  if (this == (IMimeRunSHook *) 1)
    einfo->fMask |= SEE_MASK_NO_CONSOLE;
  else
  {
    if (GetConsoleWindow () != NULL)
      einfo->fMask &= ~SEE_MASK_NO_CONSOLE;
  }
  
  if (logfile)
  {
    logtofilew (logfile, L">MimeRunSHook_ExecuteW. This (%08X). einfo (einfo)", this, einfo);
    if (einfo != NULL)
    {
      logtofilew (logfile, L" = (\n");
      logtofilew (logfile, L"  cbSize (%d)\n", einfo->cbSize);
      logtofilew (logfile, L"  fMask (%08X)\n", einfo->fMask);
      logtofilew (logfile, L"  hwnd (%08X)\n", einfo->hwnd);
      logtofilew (logfile, L"  lpVerb (%s)\n", einfo->lpVerb != NULL ? einfo->lpVerb : L"NULL");
      logtofilew (logfile, L"  lpFile (%s)\n", einfo->lpFile != NULL ? einfo->lpFile : L"NULL");
      logtofilew (logfile, L"  lpParameters (%s)\n", einfo->lpParameters != NULL ? einfo->lpParameters : L"NULL");
      logtofilew (logfile, L"  lpDirectory (%s)\n", einfo->lpDirectory != NULL ? einfo->lpDirectory : L"NULL");
      logtofilew (logfile, L"  nShow (%d)\n", einfo->nShow);
      logtofilew (logfile, L"  hInstApp (%d)\n", einfo->hInstApp);
      logtofilew (logfile, L"  lpIDList (%08X)\n", einfo->lpIDList);
      logtofilew (logfile, L"  lpClass (%08X: %s)\n", einfo->lpClass,
          ~einfo->fMask & SEE_MASK_CLASSNAME ? L"IGNORED" : einfo->lpClass != NULL ? einfo->lpClass : L"NULL");
      logtofilew (logfile, L"  hkeyClass (%08X)\n", einfo->hkeyClass);
      logtofilew (logfile, L"  dwHotKey (%08X)\n", einfo->dwHotKey);
      logtofilew (logfile, L"\n");
    }
    else
      logtofilew (logfile, L"\n");
  }

  /* Different versions of Windows (or programs compiled for different versions of Windows) will
   * give SHELLEXECUTEINFOW of different sizes. We'll need it to be as long as the one we had at
   * compilation time
   */
  if (einfo->cbSize < sizeof (SHELLEXECUTEINFOW))
  {
    logtofilew (logfile, L"cbSize < %d\n", sizeof (SHELLEXECUTEINFOW));
    goto end;
  }

  /* Explorer is likely call ShellExecute with 'open' verb, while cmd.exe calls it with NULL verb.
   * For safety reasons we won't react on other verbs and will let the shell do its default thing.
   */
  if (einfo->lpVerb != NULL && wcsicmp (einfo->lpVerb, L"open") != 0)
  {
    logtofilew (logfile, L"lpVerb != NULL && lpVerb != \"open\"\n");
    goto end;
  }

  /* We only work on files */
  if (einfo->lpFile == NULL)
  {
    logtofilew (logfile, L"lpFile == NULL\n");
    goto end;
  }

  /* Expand environment variables in lpFile and lpDirectory (if it's not NULL) per caller's request */
  if (einfo->fMask & SEE_MASK_DOENVSUBST)
  {
    DWORD res;
    logtofilew (logfile, L"Substituting environment variables\n");
    res = ExpandEnvironmentStringsW (einfo->lpFile, NULL, 0);
    if (res > 0)
    {
      logtofilew (logfile, L"Allocating %d bytes for new lpFile\n", res * sizeof (wchar_t));
      lpfile = (wchar_t *) malloc (sizeof (wchar_t) * res);
      if (lpfile != NULL)
      {
        res = ExpandEnvironmentStringsW (einfo->lpFile, lpfile, res);
        if (res == 0)
        {
          logtofilew (logfile, L"Failed to expand lpFile from %s\n", einfo->lpFile);
          free (lpfile);  
          lpfile = (wchar_t *) einfo->lpFile;
          freefile = FALSE;
        }
        else
        {
          logtofilew (logfile, L"Expanded lpFile into %s\n", lpfile);
        }
      }
      else
      {
        logtofilew (logfile, L"Failed to allocate %d bytes\n", res * sizeof (wchar_t));
        freefile = FALSE;
      }
    }
    if (einfo->lpDirectory != NULL)
    {
      logtofilew (logfile, L"Expending lpDirectory\n");
      res = ExpandEnvironmentStringsW (einfo->lpDirectory, NULL, 0);
      if (res > 0)
      {
        logtofilew (logfile, L"Allocating %d bytes for new lpDirectory\n", res * sizeof (wchar_t));
        lpdirectory = (wchar_t *) malloc (sizeof (wchar_t) * res);
        if (lpdirectory != NULL)
        {
          res = ExpandEnvironmentStringsW (einfo->lpDirectory, lpdirectory, res);
          if (res == 0)
          {
            logtofilew (logfile, L"Failed to expand lpDirectory from %s\n", einfo->lpDirectory);
            free (lpdirectory);  
            lpdirectory = (wchar_t *) einfo->lpDirectory;
            freedir = FALSE;
          }
          else
          {
            logtofilew (logfile, L"Expanded lpDirectory to %s\n", lpdirectory);
          }
        }
        else
        {
          logtofilew (logfile, L"Failed to allocate %d bytes\n", res * sizeof (wchar_t));
          freedir = FALSE;
        }
      }
    }
    else
    {
      logtofilew (logfile, L"Not expanding lpDirectory\n");
      lpdirectory = NULL;
      freedir = FALSE;
    }
  }
  else
  {
    logtofilew (logfile, L"Not substituting environment variables\n");
    lpfile = (wchar_t *) einfo->lpFile;
    lpdirectory = (wchar_t *) einfo->lpDirectory;
    freedir = FALSE;
    freefile = FALSE;
  }

  /* We work only with filesystem objects - either absolute or relative paths */
  if (lpfile[1] == L':' || lpfile[0] == L'\\' && lpfile[1] == L'\\')
  {
    logtofilew (logfile, L"lpfile %s looks like an absolute path\n", lpfile);
    filename[MAX_PATH - 1] = L'\0';
    wcsncpy (filename, lpfile, MAX_PATH);
    if (filename[MAX_PATH - 1] != L'\0')
      filename[MAX_PATH - 1] = L'\0';
    logtofilew (logfile, L"Will check %s\n", filename);
  }
  else
  {
    /* It is a relative path, combine it with current directory.
     * This will be triggered for verious URIs too, but they will not yield any
     * meaningful filename when combined with current directory, making the
     * GetFileAttribute() fail later on.
     */
    DWORD len;
    logtofilew (logfile, L"lpfile %s does not look like an absolute path\n", lpfile);
    len = GetCurrentDirectoryW (MAX_PATH, filename);
    if (len == 0)
    {
      logtofilew (logfile, L"GetCurrentDirectory() have failed with %d\n", GetLastError ());
      goto end;
    }

    /* NULL-separator, length of filename, and directory separator,
       coupled with directory length must not exceed MAX_PATH */
    if (len > MAX_PATH - 1 - wcslen (lpfile) - 1)
    {
      logtofilew (logfile, L"Directory + file name is too long: %d > %d - 1 - %d - 1 == %d\n", len, MAX_PATH, wcslen (lpfile), MAX_PATH - 1 - wcslen (lpfile) - 1);
      goto end;
    }
    wcscpy (filename + len, L"\\");
    wcscpy (filename + len + 1, lpfile);
    logtofilew (logfile, L"Will check %s\n", filename);
  }

  /* We work only with files, not with directories. This will also scrap out
   * any non-filesystem URIs.
   */
  dw = GetFileAttributesW (filename);
  if (dw == INVALID_FILE_ATTRIBUTES || dw & FILE_ATTRIBUTE_DIRECTORY)
  {
    logtofilew (logfile, L"GetFileAttirbutesW returned %08X\n", dw);
    goto end;
  }

  /* OK, let's roll! */
  res = runmime (logfile, einfo, lpfile, lpdirectory);
  if (res == 0)
    hr = S_OK;
  else if (res < 0)
    hr = S_FALSE;
  else if (res > 0)
    hr = res;
  
end:
  if (freefile)
    free (lpfile);
  if (freedir)
    free (lpdirectory);
  if (logfile)
  {
    logtofilew (logfile, L"<MimeRunSHook_ExecuteW %d\n", hr);
    free (logfile);
  }
  /* Restore the original einfo->fMask, which might have been changed by us */
  einfo->fMask = store_fmask;
  return hr;
}
