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

#include <stdio.h>
#include <mimerun/mimerunguid.h>
#include <mimerun/mimerunshook.h>
#include <mimerun/misc.h>

#define EXPLOKEY L"Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"
#define HOOKKEY L"Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks"

#define HOOKDLLW L"libmimerunshook-%d.dll"

HMODULE advapi32;
typedef LONG (WINAPI *RegDeleteKeyExWFunction)(HKEY hKey, LPCWSTR lpSubKey, REGSAM samDesired, DWORD Reserved);
RegDeleteKeyExWFunction regdelkeyexw;

void usage(char **argv, wchar_t *cdir)
{
  wprintf (
      L"Usage: %S <--register|--unregister> [current_user|local_machine [--delete-rules]]\n"
      L"  --register   - installs mimerun shellexecute hook\n"
      L"    (also enables shell hooks on Vista and later)\n"
      L"  --unregister - uninstalls mimerun shellexecute hook\n"
      L"  current_user (default) | local_machine - register per-user or machine-wide\n"
      L"  --delete-rules - when unregistering, also remove mimrun's own registry branch\n",
         argv[0], cdir, VERSION_MAJOR);
}

int guid_to_string (GUID g, wchar_t buf[39])
{
  int ret = snwprintf (buf, 39, L"{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
      g.Data1, g.Data2, g.Data3, g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
      g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);
  return ret == 38;
}


int regsvr (int is64, GUID g, wchar_t *type, wchar_t *dllpath, wchar_t *threading)
{
  DWORD dwres;
  wchar_t guid[39];
  DWORD flags = is64 ? 0 : KEY_WOW64_32KEY;
  int ret = 0;
  wchar_t *typepath = NULL;
  if (guid_to_string (g, guid))
  {
    HKEY typekey = NULL;
    typepath = dup_wprintf (NULL, L"%sCLSID\\%s\\%s", L"", guid, type);
    if (typepath != NULL)
    {
      dwres = RegCreateKeyExW (HKEY_CLASSES_ROOT, typepath, 0, NULL, REG_OPTION_NON_VOLATILE, flags | KEY_SET_VALUE, NULL, &typekey, NULL);
      if (dwres == ERROR_SUCCESS)
      {
        dwres = RegSetValueExW (typekey, NULL, 0, REG_SZ, (const BYTE *) dllpath, (wcslen (dllpath) + 1) * sizeof (wchar_t));
        if (dwres == ERROR_SUCCESS)
        {
          if (threading != NULL)
          {
            dwres = RegSetValueExW (typekey, L"ThreadingModel", 0, REG_SZ, (const BYTE *) threading, (wcslen (threading) + 1) * sizeof (wchar_t));
            if (dwres != ERROR_SUCCESS)
            {
              fwprintf (stderr, L"Failed to set HKCR\\%s\\ThreadingModel to %s because of %d\n", typepath, threading, GetLastError ());
              ret = -5;
            }
          }
        }
        else
        {
          fwprintf (stderr, L"Failed to set HKCR\\%s\\(Default) to %s because of %d\n", typepath, dllpath, GetLastError ());
          ret = -4;
        }
        RegCloseKey (typekey);
      }
      else
      {
        fwprintf (stderr, L"Failed to create/open HKCR\\%s because of %d\n", typepath, GetLastError ());
        ret = -3;
      }
      free (typepath);
    }
    else
    {
      fwprintf (stderr, L"Failed to format a string\n");
      ret = -2;
    }
  }
  else
  {
    fwprintf (stderr, L"Failed to convert a GUID to string\n");
    ret = -1;
  }
  return ret;
}

int enablehooks (HKEY hkey, int is64)
{
  int ret = 0;
  DWORD dwres = 0;
  DWORD flags = is64 ? 0 : KEY_WOW64_32KEY;
  HKEY explokey = NULL;
  wchar_t *explokeyname = NULL;
  explokeyname = dup_wprintf (NULL, L"Software\\%s" EXPLOKEY, L"");
  if (explokeyname != NULL)
  {
    dwres = RegCreateKeyExW (hkey, explokeyname, 0, NULL, REG_OPTION_NON_VOLATILE, flags | KEY_SET_VALUE, NULL, &explokey, NULL);
    if (dwres == ERROR_SUCCESS)
    {
      DWORD one = 1;
      RegSetValueExW (explokey, L"EnableShellExecuteHooks", 0, REG_DWORD, (const BYTE *) &one, sizeof (one));
      RegCloseKey (explokey);
      ret = 0;
    }
    else
    {
      fwprintf (stderr, L"Failed to set %s\\%s\\EnableShellExecuteHooks to 1\n", 
          hkey == HKEY_LOCAL_MACHINE ? L"HKLM" : L"HKCU", explokeyname);
      ret = -2;
    }
    free (explokeyname);
  }
  else
  {
    fwprintf (stderr, L"Failed to format a string\n");
    ret = -1;
  }
  return ret;
}

int sethook (HKEY hkey, int is64, GUID g)
{
  wchar_t guid[39];
  DWORD flags = is64 ? 0 : KEY_WOW64_32KEY;
  DWORD dwres = 0;
  HKEY hooks = NULL;
  wchar_t *hookkeyname = NULL;
  wchar_t val[11] = L"MimeRun x86";
  if (is64)
  {
    val[9] = L'6';
    val[10] = L'4';
  }
  int ret = 0;
  if (guid_to_string (g, guid))
  {
    hookkeyname = dup_wprintf (NULL, L"Software\\%s" HOOKKEY, L"");
    if (hookkeyname != NULL)
    {
      dwres = RegCreateKeyExW (hkey, hookkeyname, 0, NULL, REG_OPTION_NON_VOLATILE, flags | KEY_SET_VALUE, NULL, &hooks, NULL);
      if (dwres == ERROR_SUCCESS)
      {
        dwres = RegSetValueExW (hooks, guid, 0, REG_SZ, (const BYTE *) val, (wcslen (val) + 1) * sizeof (wchar_t));
        if (dwres != ERROR_SUCCESS)
        {
          fwprintf (stderr, L"Failed to set %s\\%s\\%s to %s because of %d\n", hkey == HKEY_LOCAL_MACHINE ? L"HKLM" : L"HKCU", hookkeyname, guid, val, GetLastError ());
          ret = -4;
        }
        RegCloseKey (hooks);
      }
      else
      {
        fwprintf (stderr, L"Failed to create/open %s\\%s because of %d\n", hkey == HKEY_LOCAL_MACHINE ? L"HKLM" : L"HKCU", hookkeyname, GetLastError ());
        ret = -3;
      }
      free (hookkeyname);
    }
    else
    {
      fwprintf (stderr, L"Failed to format a string\n");
      ret = -2;
    }
  }
  else
  {
    fwprintf (stderr, L"Failed to convert a GUID to string\n");
    ret = -1;
  }
  return ret;
}

int setunknown (wchar_t *cmdrunpath)
{
  int ret = 0;
  DWORD dwres;
  HKEY akey;
  wchar_t command[] = L"Unknown\\shell\\mimerun\\command";
  wchar_t shell[] = L"Unknown\\shell";
  dwres = RegCreateKeyExW (HKEY_CLASSES_ROOT, command, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &akey, NULL);
  if (dwres == ERROR_SUCCESS)
  {
    dwres = RegSetValueExW (akey, NULL, 0, REG_SZ, (const BYTE *) cmdrunpath, (wcslen (cmdrunpath) + 1) * sizeof (wchar_t));
    if (dwres != ERROR_SUCCESS)
    {
      fwprintf (stderr, L"Failed to set HKCR\\%s\\(Default) to %s because of %d\n", command, cmdrunpath, GetLastError ());
      ret = -2;
    }
    RegCloseKey (akey);
    dwres = RegOpenKeyExW (HKEY_CLASSES_ROOT, shell, 0, KEY_SET_VALUE | KEY_QUERY_VALUE, &akey);
    if (dwres == ERROR_SUCCESS)
    {
      wchar_t *currentdefault = NULL;
      if (get_sz_key (HKEY_CLASSES_ROOT, shell, NULL, &currentdefault, 0) == 0)
      {
        dwres = RegSetValueExW (akey, L"Mimerun_backup_default", 0, REG_SZ, (const BYTE *) currentdefault, (wcslen (currentdefault) + 1) * sizeof (wchar_t));
        if (dwres == ERROR_SUCCESS)
        {
          wchar_t mimerunshell[] = L"mimerun";
          dwres = RegSetValueExW (akey, NULL, 0, REG_SZ, (const BYTE *) mimerunshell, (wcslen (mimerunshell) + 1) * sizeof (wchar_t));
          if (dwres != ERROR_SUCCESS)
          {
            fwprintf (stderr, L"Failed to set HKCR\\%s\\(Default) to %s because of %d\n", shell, mimerunshell, GetLastError ());
            ret = -5;
          }
        }
        else
        {
          fwprintf (stderr, L"Failed to set HKCR\\%s\\Mimerun_backup_default to %s because of %d\n", shell, currentdefault, GetLastError ());
          ret = -4;
        }
      }
      else
      {
        fwprintf (stderr, L"Failed to get HKCR\\%s\\(Default)", shell);
        ret = -3;
      }
      RegCloseKey (akey);
    }
  }
  else
  {
    fwprintf (stderr, L"Failed to create/open HKCR\\%s because of %d\n", command, GetLastError ());
    ret = -1;
  }
  return ret;
}


int reghook (wchar_t *cdir, HKEY hkey, int is64)
{
  wchar_t dllpath[MAX_PATH] = {0};
  wchar_t cmdrunpath[MAX_PATH + 34] = {0};
  int ret = 0;
  DWORD dwres;
  HKEY mimerunkey = NULL, rulekey = NULL;
  wchar_t *mimerunkeyname = NULL;
  wcscat (dllpath, cdir);
  wcscat (dllpath, L"\\");
  swprintf (wcschr (dllpath, L'\0'), HOOKDLLW, VERSION_MAJOR);
  wcscat (cmdrunpath, cdir);
  wcscat (cmdrunpath, L"\\");
  swprintf (wcschr (cmdrunpath, L'\0'), L"cmdrun.exe SW_SHOWNORMAL system_fallback %s", L"\"%1\"");
  ret = ret | enablehooks (hkey, is64);
  ret = ret | regsvr (is64, CLSID_IMimeRunSHook, L"InProcServer32", dllpath, L"Apartment");
  ret = ret | sethook (hkey, is64, CLSID_IMimeRunSHook);
  if (!is64)
    ret = ret | setunknown (cmdrunpath);

  if (!is64)
  {
    dwres = RegCreateKeyExW (hkey, L"Software\\mimerun\\rules", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WOW64_32KEY | KEY_CREATE_SUB_KEY, NULL, &mimerunkey, NULL);
    if (dwres == ERROR_SUCCESS)
    {
      dwres = RegCreateKeyExW (mimerunkey, L"0000_Check_for_shebang_first", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WOW64_32KEY | KEY_SET_VALUE, NULL, &rulekey, NULL);
      if (dwres == ERROR_SUCCESS)
      {
        DWORD three = MIMERUN_SHEBANG_LOOKFORIT | MIMERUN_SHEBANG_TRYITFIRST;
        wchar_t matchall[] = L".*";
        RegSetValueExW (rulekey, NULL, 0, REG_SZ, (const BYTE *) matchall, sizeof (wchar_t) * (wcslen (matchall) + 1));
        RegSetValueExW (rulekey, L"shebang", 0, REG_DWORD, (const BYTE *) &three, sizeof (three));
        RegCloseKey (rulekey);
      }
      dwres = RegCreateKeyExW (mimerunkey, L"9999_Example_rule_-_runs_Notepad_on_any_plain_text_file", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WOW64_32KEY | KEY_SET_VALUE, NULL, &rulekey, NULL);
      if (dwres == ERROR_SUCCESS)
      {
        wchar_t matchtextfile[] = L"name=.*; mime-type=text/plain;.*";
        wchar_t opennotepad[] = L"%SystemRoot%\\system32\\NOTEPAD.EXE %0";
        RegSetValueExW (rulekey, NULL, 0, REG_SZ, (const BYTE *) matchtextfile, sizeof (wchar_t) * (wcslen (matchtextfile) + 1));
        RegSetValueExW (rulekey, L"handler", 0, REG_SZ, (const BYTE *) opennotepad, sizeof (wchar_t) * (wcslen (opennotepad) + 1));
        RegCloseKey (rulekey);
      }
      RegCloseKey (mimerunkey);
    }
  }

  if (iam64on64 () && !is64)
    return ret | reghook (cdir, hkey, !is64);
  else
    return ret;
}

int unsethook (HKEY hkey, int is64, GUID g)
{
  wchar_t guid[39];
  DWORD flags = is64 ? 0 : KEY_WOW64_32KEY;
  DWORD dwres = 0;
  HKEY hooks = NULL;

  int ret = 0;
  if (guid_to_string (g, guid))
  {
    dwres = RegOpenKeyExW (hkey, L"Software\\" HOOKKEY, 0, flags | KEY_SET_VALUE, &hooks);
    if (dwres == ERROR_SUCCESS)
    {
      dwres = RegDeleteValueW (hooks, guid);
      RegCloseKey (hooks);
    }
  }
  else
  {
    fwprintf (stderr, L"Failed to convert a GUID to string\n");
    ret = -1;
  }
  return ret;
}

int unregsvr (int is64, GUID g)
{
  DWORD dwres;
  HKEY clsid;
  wchar_t guid[39];
  DWORD flags = is64 ? 0 : KEY_WOW64_32KEY;
  int ret = 0;
  if (guid_to_string (g, guid))
  {
    dwres = RegOpenKeyExW (HKEY_CLASSES_ROOT, L"CLSID", 0, flags | KEY_CREATE_SUB_KEY, &clsid);
    if (dwres == ERROR_SUCCESS)
    {
      HKEY guidkey = NULL;
      wchar_t *tmp;
      tmp = dup_wprintf (NULL, L"%s\\InprocServer32", guid);
      if (tmp != NULL)
      {
        if (regdelkeyexw)
          dwres = regdelkeyexw (clsid, tmp, flags, 0);
        else
          dwres = RegDeleteKeyW (clsid, tmp);
        free (tmp);
      }
      if (regdelkeyexw)
        dwres = regdelkeyexw (clsid, guid, flags, 0);
      else
        dwres = RegDeleteKeyW (clsid, guid);
      RegCloseKey (clsid);
    }
  }
  else
  {
    fwprintf (stderr, L"Failed to convert a GUID to string\n");
    ret = -1;
  }
  return ret;
}

int unsetunknown ()
{
  int ret = 0;
  DWORD dwres;
  HKEY akey;
  wchar_t shell[] = L"Unknown\\shell";
  dwres = RegOpenKeyExW (HKEY_CLASSES_ROOT, shell, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, &akey);
  if (dwres == ERROR_SUCCESS)
  {
    wchar_t *previousdefault = NULL;
    wchar_t *currentdefault = NULL;
    wchar_t *tmp;
    if (get_sz_key (HKEY_CLASSES_ROOT, shell, NULL, &currentdefault, 0) == 0)
    {
      if (wcscmp (currentdefault, L"mimerun") == 0)
      {
        if (get_sz_key (HKEY_CLASSES_ROOT, shell, L"Mimerun_backup_default", &previousdefault, 0) == 0)
        {
          if (wcscmp (previousdefault, L"mimerun") != 0)
          {
            dwres = RegSetValueExW (akey, NULL, 0, REG_SZ, (const BYTE *) previousdefault, (wcslen (previousdefault) + 1) * sizeof (wchar_t));
            if (dwres == ERROR_SUCCESS)
            {
              RegDeleteValueW (akey, L"Mimerun_backup_default");
            }
            else
            {
              fwprintf (stderr, L"Failed to set HKCR\\%s\\(Default) to %s because of %d\n", shell, previousdefault, GetLastError ());
              ret = -2;
            }
          }
          free (previousdefault);
        }
      }
      free (currentdefault);
    }
    dwres = RegDeleteKeyW (akey, L"mimerun\\command");
    if (dwres != ERROR_SUCCESS)
    {
      fwprintf (stderr, L"Failed to delete HKCR\\%s\\mimerun\\command because of %d\n", shell, dwres);
      ret = -1;
    }
    dwres = RegDeleteKeyW (akey, L"mimerun");
    if (dwres != ERROR_SUCCESS)
    {
      fwprintf (stderr, L"Failed to delete HKCR\\%s\\mimerun because of %d\n", shell, dwres);
      ret = -1;
    }
    RegCloseKey (akey);
  }
  return ret;
}


int unreghook (wchar_t *cdir, HKEY hkey, int is64, int delrules)
{
  int ret = 0;
  DWORD dwres;
  HKEY explokey = NULL;
  ret = ret | unregsvr (is64, CLSID_IMimeRunSHook);
  ret = ret | unsethook (hkey, is64, CLSID_IMimeRunSHook);
  if (!is64)
    ret = ret | unsetunknown ();

  if (!is64 && delrules)
  {
    /* This is broken - need a recursive key deletion function */
    explokey = NULL;
    dwres = RegOpenKeyExW (hkey, L"Software", 0, KEY_WOW64_32KEY, &explokey);
    if (dwres == ERROR_SUCCESS)
    {
      if (regdelkeyexw)
        regdelkeyexw (explokey, L"mimerun", KEY_WOW64_32KEY, 0);
      else
        dwres = RegDeleteKeyW (explokey, L"mimerun");
      RegCloseKey (explokey);
    }
  }

  if (iam64on64 () && !is64)
    return ret | unreghook (cdir, hkey, !is64, delrules);
  else
    return ret;
}


int main (int argc, char **argv)
{
  wchar_t cdir[MAX_PATH];
  DWORD dirlen = 0;
  int ret = 0;
  if ((dirlen = GetCurrentDirectoryW (MAX_PATH, cdir)) == 0)
    ret = 1;
  else if (argc == 1)
  {
    usage (argv, cdir);
  }
  else if (argc >= 2)
  {
    int user = 0;
    int delrules = 0;
    if (argc >= 3)
      if (strcmp (argv[2], "current_user") == 0)
        user = 1;
      else if (strcmp (argv[2], "local_machine") == 0)
        user = 0;
      else
      {
        usage (argv, cdir);
        ret = 2;
      }
    if (ret == 0 && argc >= 4)
      if (strcmp (argv[3], "--delete-rules") == 0)
        delrules = 1;
      else
      {
        usage (argv, cdir);
        ret = 3;
      }
    if (ret == 0)
    {
      if (strcmp (argv[1], "--register") == 0)
        ret = reghook (cdir, user ? HKEY_CURRENT_USER : HKEY_LOCAL_MACHINE, 0);
      else if (strcmp (argv[1], "--unregister") == 0)
      {
        advapi32 = LoadLibraryW (L"Advapi32.dll");
        if (advapi32 != NULL)
          regdelkeyexw = (RegDeleteKeyExWFunction) GetProcAddress (advapi32, "RegDeleteKeyExW");
        ret = unreghook (cdir, user ? HKEY_CURRENT_USER : HKEY_LOCAL_MACHINE, 0, delrules);
        if (advapi32 != NULL)
          FreeLibrary (advapi32);
      }
      else
      {
        usage (argv, cdir);
        ret = 4;
      }
    }
  }
  return ret;
}