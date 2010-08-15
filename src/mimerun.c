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

#include <mimerun/mimerun.h>

#include <magic.h>
#include <regex.h>

#include <mimerun/misc.h>

#ifndef SEE_MASK_WAITFORINPUTIDLE
#define SEE_MASK_WAITFORINPUTIDLE  0x02000000
#endif

/* Helper function. Retreives the environment variable <name> and stores its
 * value in memory. Returns the pointer to variable's value (or NULL if
 * the variable does not exist). Writes the variable's length into <len>
 */
wchar_t *store_var (const wchar_t *name, DWORD *len)
{
  DWORD varlen = 0;
  wchar_t *store;
  varlen = GetEnvironmentVariableW (name, NULL, 0);
  if (GetLastError () != ERROR_SUCCESS)
    return NULL;
  store = (wchar_t *) malloc (sizeof (wchar_t) * varlen);
  if (GetEnvironmentVariableW (name, store, varlen) != varlen - 1)
  {
    free (store);
    store = NULL;
  }
  else
    *len = varlen;
  return store;
}

/* Transforms <exp_str> into argc/argv pair.
 * First dimension of <new_argv> is allocated by make_argv, while elements of
 * <new_argv> point to the contents of <exp_str>, which is mangled by
 * make_argv (use wcsdup() and give make_argv a copy, if you need unmodified <exp_str>).
 * Free <new_argv> with free() when you're done with it.
 * Do not free <exp_str> while using <new_argv>.
 */
int make_argv (wchar_t *exp_str, int *num_args, wchar_t **new_argv)
{
  int i = 0;
  wchar_t *ptr = exp_str;
  wchar_t *prev_ptr = exp_str;
  if (num_args != NULL)
  {
    *num_args = 0;
  }
  while (prev_ptr[0] == L' ' && prev_ptr[0] != L'\0')
    prev_ptr += 1;
  for (ptr = prev_ptr; ptr[0] != L'\0'; ptr++)
  {
    if (ptr[0] == L'"')
    {
      for (ptr += 1; ptr[0] != L'"'; ptr++)
      {
        if (ptr[0] == L'\0')
          return -1; 
      }
    }
    else if (ptr[0] == L' ' && (ptr == exp_str || ptr[-1] != L' '))
    {
      if (num_args != NULL)
        *num_args += 1;
      if (new_argv != NULL)
      {
        new_argv[i] = prev_ptr;
        i += 1;
        ptr[0] = L'\0';
        prev_ptr = ptr + 1;
        while (prev_ptr[0] == L' ' && prev_ptr[0] != L'\0')
        {
          ptr += 1;
          prev_ptr += 1;
        }
      }
    }
  }
  if (num_args != NULL)
    *num_args += 1;
  if (new_argv != NULL)
    new_argv[i] = prev_ptr;
  return 0;
}

/* "Environment" variables that can be used in handler command lines */
#define APPLE_VARW L"MIMERUN_APPLE"
#define TYPE_VARW L"MIMERUN_TYPE"
#define ENC_VARW L"MIMERUN_ENCODING"
#define NAME_VARW L"MIMERUN_NAME"

typedef BOOL WINAPI (*Wow64DisableWow64FsRedirectionFunction)(PVOID *OldValue);
typedef BOOL WINAPI (*Wow64RevertWow64FsRedirectionFunction)(PVOID OldValue);

/* Runs a handler process specified by full command line <data> (with arguments).
 * Before running:
 * Replaces environment variables.
 * Replaces special MimeRun variables (see above) with the detected values taken from <mres>.
 * Replaces %* and %N with the appropriate bits of <lpfile> and <einfo>->lpParameters.
 * If <executable> is TRUE, waits until the handler process terminates, otherwise returns
 * (almost) immediately.
 */
int run_handler (wchar_t *logfile, wchar_t *data, MimeResults *mres, LPSHELLEXECUTEINFOW einfo, wchar_t *lpfile, wchar_t *lpdir, int executable, int fix_redir)
{
  BOOL ret = 0;
  PVOID redir;
  HMODULE kernel32 = NULL;
  Wow64DisableWow64FsRedirectionFunction disablewow64 = NULL;
  Wow64RevertWow64FsRedirectionFunction revertwow64 = NULL;
  DWORD err;
  int i;
  int depth = 0;
  size_t dupdatalen;
  wchar_t *exp_data = NULL;
  wchar_t *dupdata = NULL;
  wchar_t *dupparams = NULL;
  wchar_t **old_argv = NULL, **newargv = NULL;
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  DWORD applelen, typelen, enclen, namelen;
  wchar_t *store_apple = NULL, *store_type = NULL, *store_enc = NULL, *store_name = NULL;

  logtofilew (logfile, L">run_handler\n");

  if (einfo->lpParameters != NULL)
  {
    i = wcslen (einfo->lpParameters) + 1 + wcslen (lpfile);
    logtofilew (logfile, L"Fake commandline length is %d + 1 + %d == %d\n", wcslen (einfo->lpParameters), wcslen (lpfile), i);
    dupparams = (wchar_t *) malloc (sizeof (wchar_t *) * (i + 1));
    if (dupparams == NULL)
    {
      logtofilew (logfile, L"Failed to allocate %d bytes\n", sizeof (wchar_t *) * (i + 1));
      return 1;
    }
    dupparams[0] = L'\0';
    wcscat (dupparams, lpfile);
    wcscat (dupparams, L" ");
    wcscat (dupparams, einfo->lpParameters);
    logtofilew (logfile, L"Fake commandline is %s\n", dupparams);
    if (make_argv (dupparams, &i, NULL) == 0 && i >= 1)
    {
      old_argv = (wchar_t **) malloc (sizeof (wchar_t *) * (i + 1));
      make_argv (dupparams, NULL, old_argv);
      old_argv[i] = NULL;
      logtofilew (logfile, L"Old arguments:\n");
      for (i = 0; old_argv[i] != NULL; i++)
        logtofilew (logfile, L"%2d: %s\n", i, old_argv[i]);
      logtofilew (logfile, L"\n");
    }
    else
    {
      logtofilew (logfile, L"First call to make_argv() have failed or argc <= 0\n");
      free (dupparams);
      return 2;
    }
  }
  else
  {
    old_argv = (wchar_t **) malloc (sizeof (wchar_t *) * 2);
    old_argv[0] = lpfile;
    old_argv[1] = NULL;
    logtofilew (logfile, L"Old arguments:\n");
    for (i = 0; old_argv[i] != NULL; i++)
      logtofilew (logfile, L"%2d: %s\n", i, old_argv[i]);
    logtofilew (logfile, L"\n");
  }

  store_name = store_var (NAME_VARW, &namelen);
  store_type = store_var (TYPE_VARW, &typelen);
  store_enc = store_var (ENC_VARW, &enclen);
  store_apple = store_var (APPLE_VARW, &applelen);

  logtofilew (logfile, L"Backed up variables: {%s}, {%s}, {%s}, {%s}\n", store_name, store_type, store_enc, store_apple);

  SetEnvironmentVariableW (NAME_VARW, mres->wname == NULL ? L"" : mres->wname);
  SetEnvironmentVariableW (TYPE_VARW, mres->wtype == NULL ? L"" : mres->wtype);
  SetEnvironmentVariableW (ENC_VARW, mres->wenc == NULL ? L"" : mres->wenc);
  SetEnvironmentVariableW (APPLE_VARW, mres->wapple == NULL ? L"" : mres->wapple);
  
  exp_data = expand_vars (data, old_argv);

  logtofilew (logfile, L"Commandline with expanded variables: %s\n", exp_data);
  if (dupparams != NULL)
    free (dupparams);
  if (old_argv != NULL)
    free (old_argv);

  SetEnvironmentVariableW (NAME_VARW, store_name);
  SetEnvironmentVariableW (TYPE_VARW, store_type);
  SetEnvironmentVariableW (ENC_VARW, store_enc);
  SetEnvironmentVariableW (APPLE_VARW, store_apple);

  if (store_apple != NULL)
    free (store_apple);
  if (store_type != NULL)
    free (store_type);
  if (store_enc != NULL)
    free (store_enc);
  if (store_name != NULL)
    free (store_name);

  dupdata = (wchar_t *) wcsdup (exp_data);
  if (make_argv (dupdata, &i, NULL) == 0 && i >= 1)
  {
    newargv = (wchar_t **) malloc (sizeof (wchar_t *) * (i + 1));
    make_argv (dupdata, NULL, newargv);
    newargv[i] = NULL;
  }
  else
  {
    logtofilew (logfile, L"First call to make_argv() have failed or argc <= 0\n");
    free (dupdata);
    return 3;
  }

  memset (&si, 0, sizeof (si));
  si.cb = sizeof (si);
  if (einfo->nShow != SW_SHOWDEFAULT)
  {
    si.dwFlags |= STARTF_USESHOWWINDOW;
    si.wShowWindow = einfo->nShow;
    logtofilew (logfile, L"Using nShow == %d\n", si.wShowWindow);
  }


  if (einfo->fMask & SEE_MASK_NO_CONSOLE)
  {
    logtofilew (logfile, L"We will create new console and will not inherit in/out/err handles\n");
  }
  else
  {
    logtofilew (logfile, L"We will not create new console, child process will inherit in/out/err handles\n");
    si.dwFlags |= STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle (STD_INPUT_HANDLE);
    si.hStdOutput = GetStdHandle (STD_OUTPUT_HANDLE);
    si.hStdError = GetStdHandle (STD_ERROR_HANDLE);
  }

  if (fix_redir && iam32on64 ())
  {
    kernel32 = LoadLibraryW (L"kernel32.dll");
    if (kernel32 != NULL)
    {
      disablewow64 = (Wow64DisableWow64FsRedirectionFunction) GetProcAddress (kernel32, "Wow64DisableWow64FsRedirection");
      revertwow64 = (Wow64RevertWow64FsRedirectionFunction) GetProcAddress (kernel32, "Wow64RevertWow64FsRedirection");
      if (disablewow64 == NULL || revertwow64 == NULL)
        fix_redir = 0;
      else
        fix_redir = disablewow64 (&redir);
    }
    else
      fix_redir = 0;
  }
  else
    fix_redir = 0;

  ret = CreateProcessW (newargv[0], exp_data, NULL, NULL, TRUE, einfo->fMask & SEE_MASK_NO_CONSOLE ? CREATE_NEW_CONSOLE : 0, NULL, lpdir, &si, &pi);
  err = GetLastError();
  if (fix_redir != 0)
    revertwow64 (redir);
  if (kernel32 != NULL)
    FreeLibrary (kernel32);

  if (ret != 0)
  {
    logtofilew (logfile, L"CreateProcessW() succeeded\n");
    ret = 0;
    if (executable)
    {
      logtofilew (logfile, L"Waiting until executable process terminates...\n");
      WaitForSingleObject (pi.hProcess, INFINITE);
      logtofilew (logfile, L"Finished waiting until executable process terminates\n");
    }
    else
    {
      if (einfo->fMask & SEE_MASK_NOCLOSEPROCESS)
      {
        einfo->hProcess = pi.hProcess;
        logtofilew (logfile, L"Will return process handle %08X\n", pi.hProcess);
      }
      if (einfo->fMask & SEE_MASK_WAITFORINPUTIDLE)
      {
        logtofilew (logfile, L"Waiting until non-executable process' input idles...\n");
        WaitForInputIdle (pi.hProcess, 60*1000);
        logtofilew (logfile, L"Finished waiting until non-executable process' input idles\n");
      }
    }
    einfo->hInstApp = (HINSTANCE) 33;
  }
  else
  {
    logtofilew (logfile, L"CreateProcessW() have failed with %d\n", err);
    switch (err)
    {
    case ERROR_FILE_NOT_FOUND:
      einfo->hInstApp = (HINSTANCE) SE_ERR_FNF;
      break;
    case ERROR_PATH_NOT_FOUND:
      einfo->hInstApp = (HINSTANCE) SE_ERR_PNF;
      break;
    case ERROR_ACCESS_DENIED:
      einfo->hInstApp = (HINSTANCE) SE_ERR_ACCESSDENIED;
      break;
    case ERROR_NOT_ENOUGH_MEMORY:
      einfo->hInstApp = (HINSTANCE) SE_ERR_OOM;
      break;
    default:
      einfo->hInstApp = (HINSTANCE) 33;
    }
    ret = 1;
  }
  logtofilew (logfile, L"hInstApp is set to %d\n", einfo->hInstApp);
  free (exp_data);
  if (dupdata != NULL)
    free (dupdata);
  if (newargv != NULL)
    free (newargv);
  logtofilew (logfile, L"<run_handler %d\n", ret);
  return ret;
}

/* Returns 0 if the expression from <hKey>/<rulename>/(Default) matches <matchstring> */
int match_rule (wchar_t *logfile, HKEY hKey, wchar_t *rulename, wchar_t *matchstring)
{
  int ret = 0;
  wchar_t *ruleval = NULL;
  DWORD res, flags = 0;
  HKEY rulekey = NULL;
  regex_t reg;

  logtofilew (logfile, L">match_rule %s\n", rulename);
  ret = get_sz_key (hKey, rulename, NULL, &ruleval, KEY_WOW64_32KEY);
  if (ret < 0)
  {
    logtofilew (logfile, L"Failed to get rule value with %d (%d)\n", ret, GetLastError ());
    goto end;
  }
  ret = get_dword_key (hKey, rulename, L"flags", &flags, KEY_WOW64_32KEY);
  logtofilew (logfile, L"Got flags == %d\n", flags);
  flags = flags | REG_EXTENDED | REG_NOSUB;
  ret = regwcomp (&reg, ruleval, flags);
  if (ret != 0)
  {
    logtofilew (logfile, L"regwcomp() have failed to compile `%s' with %d\n", ruleval, ret);
    goto end;
  }
  ret = regwexec (&reg, matchstring, 0, NULL, 0);
  regfree (&reg);
end: 
  if (ruleval != NULL)
    free (ruleval);
  logtofilew (logfile, L"<match_rule %d\n", ret);
  return ret;
}

#define MATCHSTRING_FORMAT_ARGS(m, e, lpfile) \
    L"name=%s; mime-type=%s; mime-encoding=%s; apple=%s; commandline=%s%s%s;", \
    m->wname ? m->wname : L"", m->wtype ? m->wtype : L"", m->wenc ? m->wenc : L"", \
    m->wapple ? m->wapple : L"", lpfile, e->lpParameters ? L" " : L"", e->lpParameters ? e->lpParameters : L""

/* Enumerates the subkeys of <hKey>/Software/mimerun/rules and looks for a rule that matches the values
 * from <mres>, <lpfile> and <einfo>->lpParameters
 * Once a matching rule is found, its handler is executed and the function returns without looking checking
 * any other rules.
 */
int handle_key (wchar_t *logfile, HKEY hKey, MimeResults *mres, LPSHELLEXECUTEINFOW einfo, wchar_t *lpfile, wchar_t *lpdir)
{
  wchar_t *handle_val = NULL;
  HKEY rules;
  wchar_t *matchstring = NULL;
  wchar_t **allkeys = NULL;
  wchar_t *handler = NULL;
  DWORD allkeys_len, maxkey_len;
  LONG res = 0;
  int ret = -4;
  DWORD matchlen = 0;
  DWORD i;
  DWORD len = 0;
  BOOL sorted;

  logtofilew (logfile, L">handle_key\n");

  matchlen = _scwprintf (MATCHSTRING_FORMAT_ARGS(mres, einfo, lpfile));
  if (matchlen <= 0)
  {
    logtofilew (logfile, L"match string length %d <= 0\n", matchlen);
    ret = -1;
    goto end;
  }
  res = RegOpenKeyExW (hKey, L"Software\\mimerun\\rules", 0, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_32KEY, &rules);
  if (res != ERROR_SUCCESS)
  {
    logtofilew (logfile, L"Failed to open %08X\\Software\\mimerun\\rules\n", hKey);
    ret = -2;
    goto end;
  }
  res = RegQueryInfoKeyW (rules, NULL, NULL, NULL, &allkeys_len, &maxkey_len, NULL, NULL, NULL, NULL, NULL, NULL);
  if (res != ERROR_SUCCESS || (allkeys_len <= 0 || maxkey_len <= 0))
  {
    logtofilew (logfile, L"Failed to query keys from %08X\\Software\\mimerun\\rules\n", hKey);
    ret = -3;
    goto end;
  }
  allkeys = (wchar_t **) malloc (sizeof (wchar_t *) * (allkeys_len + 1));
  if (allkeys == NULL)
  {
    logtofilew (logfile, L"Failed to allocate %d bytes for rule keys\n", sizeof (wchar_t *) * (allkeys_len + 1));
    ret = -4;
    goto end;
  }
  memset (allkeys, 0, sizeof (wchar_t *) * (allkeys_len + 1));
  for (i = 0; i < allkeys_len; i++)
  {
    allkeys[i] = (wchar_t *) malloc (sizeof (wchar_t) * (maxkey_len + 1));
    if (allkeys[i] == NULL)
    {
      logtofilew (logfile, L"Failed to allocate %d bytes for one of the rule keys\n", sizeof (wchar_t) * (maxkey_len + 1));
      ret = -5;
      goto end;
    }
  }
  allkeys[allkeys_len] = NULL;
  for (i = 0; res == ERROR_SUCCESS; i++)
  {
    len = maxkey_len + 1;
    res = RegEnumKeyExW (rules, i, allkeys[i], &len, NULL, NULL, NULL, NULL);
  }
  logtofilew (logfile, L"Enumerated %d rules\n", i - 1);
  sorted = FALSE;
  while (!sorted)
  {
    sorted = TRUE;
    for (i = 1; i < allkeys_len; i++)
    {
      if (wcscmp (allkeys[i - 1], allkeys[i]) > 0)
      {
        sorted = FALSE;
        wchar_t *tmp;
        tmp = allkeys[i - 1];
        allkeys[i - 1] = allkeys[i];
        allkeys[i] = tmp;
      }
    }
  }
  matchstring = (wchar_t *) malloc (sizeof (wchar_t) * (matchlen + 1));
  swprintf (matchstring, MATCHSTRING_FORMAT_ARGS(mres, einfo, lpfile));
  logtofilew (logfile, L"Matchstring: %s\n", matchstring);
  for (i = 0; i < allkeys_len; i++)
  {
    if ((ret = match_rule (logfile, rules, allkeys[i], matchstring)) == 0)
    {
      handler = NULL;
      DWORD executable = 0;
      DWORD fix_redir = 0;
      DWORD shebang_flags = 0;
      char shebang_interp[MAX_PATH + 1];
      char *shebang_args = NULL;
      if (get_dword_key (rules, allkeys[i], L"executable", &executable, KEY_WOW64_32KEY) != 0)
        executable = 1;
      if (get_dword_key (rules, allkeys[i], L"fix_wow64_redirection", &fix_redir, KEY_WOW64_32KEY) != 0)
        fix_redir = 0;
      if (get_dword_key (rules, allkeys[i], L"shebang", &shebang_flags, KEY_WOW64_32KEY) != 0)
        shebang_flags = 0;
      logtofilew (logfile, L"Found a handler, execuable is %d, fix_wow64_redirection is %d, shebang is %d\n", executable, fix_redir, shebang_flags);

      if (shebang_flags & MIMERUN_SHEBANG_LOOKFORIT)
      {
        logtofilew (logfile, L"Trying to get shebang... ");
        if (get_shebang (lpfile, shebang_interp, &shebang_args) < 0)
        {
          shebang_flags = 0;
          logtofilew (logfile, L"FAILURE\n");
        }
        else
        {
          logtofilew (logfile, L"%S %S\n", shebang_interp, shebang_args ? shebang_args : "");
        }
      }
      if (shebang_flags & MIMERUN_SHEBANG_LOOKFORIT && shebang_flags & MIMERUN_SHEBANG_TRYITFIRST)
      {
        wchar_t *tmp = dup_wprintf (NULL, L"%S%s%S %s", shebang_interp, shebang_args == NULL ? L"" : L" ", shebang_args == NULL ? "" : shebang_args, lpfile);
        if (tmp != NULL)
        {
          ret = run_handler (logfile, tmp, mres, einfo, lpfile, lpdir, 1, fix_redir);
          free (tmp);
          free (shebang_args);
          if (shebang_flags & MIMERUN_SHEBANG_BAILONIT || ret == 0)
          {
            logtofilew (logfile, L"Bailing out after shebang\n", ret);
            goto end;
          }
          else
            einfo->hInstApp = (HINSTANCE) 33;
        }
      }
      if (get_sz_key (rules, allkeys[i], L"handler", &handler, KEY_WOW64_32KEY) == 0 && handler != NULL)
      {
        ret = run_handler (logfile, handler, mres, einfo, lpfile, lpdir, executable, fix_redir);
        free (handler);
        handler = NULL;
        if (ret == 0)
        {
          logtofilew (logfile, L"Handled, returning\n");
          goto end;
        }
      }
      else
      {
        logtofilew (logfile, L"Failed to get handler value\n");
      }
      if (shebang_flags & MIMERUN_SHEBANG_LOOKFORIT && ~shebang_flags & MIMERUN_SHEBANG_TRYITFIRST)
      {
        wchar_t *tmp = dup_wprintf (NULL, L"%S%s%S %s", shebang_interp, shebang_args == NULL ? L"" : L" ", shebang_args == NULL ? "" : shebang_args, lpfile);
        if (tmp != NULL)
        {
          ret = run_handler (logfile, tmp, mres, einfo, lpfile, lpdir, 1, fix_redir);
          free (tmp);
          free (shebang_args);
          if (shebang_flags & MIMERUN_SHEBANG_BAILONIT || ret == 0)
          {
            logtofilew (logfile, L"Bailing out after shebang\n");
            goto end;
          }
        }
      }
      ret = -4;
    }
  }
end:
  logtofilew (logfile, L"Cleaning up handle_key\n");
  if (matchstring != NULL)
    free (matchstring);
  if (allkeys != NULL)
  {
    for (i = 0; allkeys[i] != NULL; i++)
      free (allkeys[i]);
    free (allkeys);
  }
  if (rules != NULL)
    RegCloseKey (rules);

  logtofilew (logfile, L"<handle_key %d\n", ret);
  return ret;
}

/* calls handle_key() for HKCR and, if that yields no matches, for HKLM */
int handle (wchar_t *logfile, MimeResults *mres, LPSHELLEXECUTEINFOW einfo, wchar_t *lpfile, wchar_t *lpdir)
{
  logtofilew (logfile, L">handle\n");
  int ret = 0;
  if ((ret = handle_key (logfile, HKEY_CURRENT_USER, mres, einfo, lpfile, lpdir)) < 0)
    ret = handle_key (logfile, HKEY_LOCAL_MACHINE, mres, einfo, lpfile, lpdir);
  logtofilew (logfile, L"<handle %d\n", ret);
  return ret;
}

magic_t load(const char *magicfile, int flags)
{
  magic_t magic = magic_open(flags);
  if (magic == NULL) {
    return NULL;
  }
  if (magic_load(magic, magicfile) == -1) {
    magic_close(magic);
    return NULL;
  }
  return magic;
}

/* Casts libmagic on the file <lpfile> to determine its type and
 * tries to find and run a handler for that type of files.
 */
int runmime (wchar_t *logfile, LPSHELLEXECUTEINFOW einfo, wchar_t *lpfile, wchar_t *lpdirectory)
{
  magic_t magicmimetype = NULL, magicmimeencoding = NULL, magicapple = NULL, magicname = NULL;
  char *mimetype, *mimeencoding, *apple, *name;
  char *argv1 = NULL;
  MimeResults mres;
  int ret = 0;

  logtofilew (logfile, L">runmime\n");

  magicname = load (NULL, MAGIC_NONE);
  magicmimetype = load (NULL, MAGIC_MIME_TYPE);
  magicmimeencoding = load (NULL, MAGIC_MIME_ENCODING);
  magicapple = load (NULL, MAGIC_APPLE);

  logtofilew (logfile, L"magics: %08x, %08x, %08x, %08x\n", magicname, magicmimetype, magicmimeencoding, magicapple);
  wchartostr (lpfile, &argv1, CP_THREAD_ACP);
  logtofilew (logfile, L"file to check is %S\n", argv1);
  
  memset (&mres, 0, sizeof (mres));

  mres.type = (char *) magic_file (magicmimetype, argv1);
  mres.enc = (char *) magic_file (magicmimeencoding, argv1);
  mres.apple = (char *) magic_file (magicapple, argv1);
  mres.name = (char *) magic_file (magicname, argv1);

  logtofilew (logfile, L"magic results: {%S} {%S} {%S} {%S}\n", mres.name, mres.type, mres.enc, mres.apple);
  if (mres.name != NULL)
    mres.name = strdup (mres.name);
  if (mres.type != NULL)
    mres.type = strdup (mres.type);
  if (mres.enc != NULL)
    mres.enc = strdup (mres.enc);
  if (mres.apple != NULL)
    mres.apple = strdup (mres.apple);

  strtowchar (mres.name, &mres.wname, CP_THREAD_ACP);
  strtowchar (mres.type, &mres.wtype, CP_THREAD_ACP);
  strtowchar (mres.enc, &mres.wenc, CP_THREAD_ACP);
  strtowchar (mres.apple, &mres.wapple, CP_THREAD_ACP);

  magic_close (magicmimetype);
  magic_close (magicmimeencoding);
  magic_close (magicapple);
  magic_close (magicname);

  if (argv1 != NULL)
    free (argv1);

  if (mres.type == NULL && mres.apple == NULL && mres.name == NULL)
  {
    logtofilew (logfile, L"Zero results, returning.\n");
    ret = -1;
  }
  else
  {
    ret = handle (logfile, &mres, einfo, lpfile, lpdirectory);
  }

  if (mres.name != NULL)
    free (mres.name);
  if (mres.type != NULL)
    free (mres.type);
  if (mres.enc != NULL)
    free (mres.enc);
  if (mres.apple != NULL)
    free (mres.apple);

  if (mres.wname != NULL)
    free (mres.wname);
  if (mres.wtype != NULL)
    free (mres.wtype);
  if (mres.wenc != NULL)
    free (mres.wenc);
  if (mres.wapple != NULL)
    free (mres.wapple);
  
  logtofilew (logfile, L"<runmime %d\n", ret);
  return ret;
}
