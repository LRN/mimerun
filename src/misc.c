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

#include <mimerun/misc.h>
#include <windows.h>
#include <stdio.h>

/* Helper function. Calls wcscpy() and returns the length of src */
int cwcscpy (wchar_t *dst, wchar_t *src)
{
  wcscpy (dst, src);
  return wcslen (src);
}

/* Scans <data> for "%N" or "%*".
 * %* is replaced by "argv[1]" "argv[2]" ... depending on <argc> (note the double quotes)
 * %N is replaced by argv[N] (note the absence of double quotes)
 * Writes the length of the resulting string into <newlen>, if <newlen> is not NULL.
 * Fills <result> (allocated by the caller) with the resulting string, if <result> is not NULL
 */
int scan_vars (wchar_t *data, size_t datalen, size_t *newlen, wchar_t *result, int argc, wchar_t *argv[])
{
  int i = 0, j = 0;
  wchar_t *result_pointer = result;
  if (newlen != NULL)
    *newlen = datalen;
  for (i = 0; i < datalen; i++)
  {
    if (data[i] == L'%' && i < datalen - 1 && data[i + 1] == L'%')
    {
      if (result != NULL)
      {
        result_pointer[0] = L'%';
        result_pointer += 1;
      }
      if (newlen != NULL)
        *newlen -= 1;
      i += 1;
    }
    else if (data[i] == L'%' && i < datalen - 1 && ((data[i + 1] >= L'0' && data[i + 1] <= L'9') || data[i + 1] == L'*'))
    {
      if (data[i + 1] == L'*')
      {
        if (newlen != NULL)
        {
          *newlen += argc * 2;
          for (j = 1; j < argc; j++)
          {
            *newlen += wcslen (argv[j]);
            if (j > 1)
              *newlen += 1;
          }
        }
        if (result != NULL)
        {
          for (j = 1; j < argc; j++)
          {
            if (j > 1)
              result_pointer += cwcscpy (result_pointer, L" ");
            result_pointer += cwcscpy (result_pointer, L"\"");
            result_pointer += cwcscpy (result_pointer, argv[j]);
            result_pointer += cwcscpy (result_pointer, L"\"");
          }
        }
      }
      else
      {
        int arg_num = data[i + 1] - L'0';
        if (arg_num <= argc - 1)
        {
          if (newlen != NULL)
            *newlen += wcslen (argv[arg_num]);
          if (result != NULL)
          {
            result_pointer += cwcscpy (result_pointer, argv[arg_num]);
          }
        }
      }
      if (newlen != NULL)
        *newlen -= 2;
      i += 1;
    }
    else if (result != NULL)
    {
      result_pointer[0] = data[i];
      result_pointer += 1;
    }
  }
  return 0;
}

/* Returns a string that corresponds to <data> with all existing
 * environment variables replaced by their values and with
 * %* and %N replaced by the respective command line arguments, taken from <argv>.
 * The resulting string is allocated by expand_vars() and must be freed with free().
 */
wchar_t *expand_vars (wchar_t *data, wchar_t *argv[])
{
  DWORD res = 0;
  DWORD extra_len = 0;
  size_t newlen = 0;
  wchar_t *result;
  wchar_t *arg_result;
  int i = 0, j = 0;
  BOOL prevrep = FALSE;
  size_t len = 0;
  int argc;
  res = ExpandEnvironmentStringsW (data, NULL, 0);
  if (res == 0)
    return NULL;
  result = (wchar_t *) malloc (sizeof(wchar_t) * res);
  if (result == NULL)
    return NULL;
  res = ExpandEnvironmentStringsW (data, result, res);
  if (res == 0)
  {
    free (result);  
    return NULL;
  }

  argc = 0;
  for (arg_result = argv[0]; arg_result != NULL; arg_result = argv[argc])
    argc += 1;

  scan_vars (result, res, &newlen, NULL, argc, argv);
  arg_result = (wchar_t *) malloc (sizeof (wchar_t) * (newlen + 1));
  scan_vars (result, res, NULL, arg_result, argc, argv);
  free (result);
  return arg_result;
}
/* Helper function. Attempts to read shebang from <file>.
 * Fills <interpreter> with the interpreter part of shbang.
 * Writes a pointer to the argument string into *<arguments> (if <arugments> is not NULL).
 * *<arguments> is allocated by get_shebang and should be freed with free()
 */
int get_shebang (wchar_t *file, char interpreter[MAX_PATH + 1], char **arguments)
{
  FILE *f = NULL;
  char charbuf[2];
  int safetycounter = 0;
  int ret = 0;
  char tmp;
  if (file == NULL || interpreter == NULL)
    return -1;
  f = _wfopen (file, L"rb");
  if (f == NULL)
    return -2;
  fread (&charbuf, sizeof(char), 2, f);
  if (charbuf[0] != '#' || charbuf[1] != '!')
  {
    ret = -3;
  }
  else
  {
    int rcount = 1;
    interpreter[0] = ' ';
    for (safetycounter = 0; rcount == 1 && interpreter[0] == ' ' && interpreter[0] != 0x0D && interpreter[0] != 0x0A && safetycounter < 1024*32; safetycounter++)
      rcount = fread (interpreter, sizeof (char), 1, f);
    if (interpreter[0] == 0x0D || interpreter[0] == 0x0A || safetycounter >= 1024*32)
      ret = -4;
    else
    {
      for (safetycounter = 1; rcount == 1 && interpreter[safetycounter - 1] != ' ' && interpreter[safetycounter - 1] != 0x0D && interpreter[safetycounter - 1] != 0x0A && safetycounter < MAX_PATH + 1; safetycounter++)
        rcount = fread (&interpreter[safetycounter], sizeof (char), 1, f);
      if (safetycounter >= 1024*32)
        ret = -5;
      else
      {
        long argpos = ftell (f);
        tmp = interpreter[safetycounter - 1];
        if (safetycounter == MAX_PATH + 1)
          interpreter[MAX_PATH] = '\0';
        else
          interpreter[safetycounter - 1] = '\0';
        if (argpos == -1)
        {
          ret = -6;
        }
        else
        {
          if (arguments != NULL && tmp != 0x0D && tmp != 0x0A && tmp == ' ')
          {
            for (safetycounter = 0; rcount == 1 && tmp != 0x0D && tmp != 0x0A && safetycounter < 1024*32; safetycounter++)
              rcount = fread (&tmp, sizeof (char), 1, f);
            if (rcount != 1 || safetycounter >= 1024*32)
            {
              ret = -7;
            }
            else if (safetycounter > 1)
            {
              *arguments = (char *) malloc (sizeof (char) * safetycounter);
              if (*arguments == NULL)
              {
                ret = -8;
              }
              else
              {
                if (fseek (f, argpos, SEEK_SET) != 0)
                {
                  free (*arguments);
                  *arguments = NULL;
                  ret = -9;
                }
                else
                {
                  rcount = fread (*arguments, sizeof (char), safetycounter - 1, f);
                  if (rcount != safetycounter - 1)
                  {
                    free (*arguments);
                    *arguments = NULL;
                    ret = -10;
                  }
                  else
                  {
                    (*arguments)[safetycounter - 1] = '\0';
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  fclose (f);
  return ret;
}

wchar_t *dup_wprintf (int *rlen, wchar_t *format, ...)
{
  va_list argptr;
  wchar_t *result = NULL;
  int len = 0;

  if (format == NULL)
    return NULL;

  va_start(argptr, format);

  len = _vscwprintf (format, argptr);
  if (len >= 0)
  {
    result = (wchar_t *) malloc (sizeof (wchar_t *) * (len + 1));
    if (result != NULL)
    {
      int len2 = vswprintf (result, format, argptr);
      if (len2 != len || len2 <= 0)
      {
        free (result);
        result = NULL;
      }
      else if (rlen != NULL)
        *rlen = len;
    }
  }
  va_end(argptr);
  return result;
}

int iam64on64 ()
{
  SYSTEM_INFO sysinfo_32, sysinfo_64;
  sysinfo_32.wProcessorArchitecture = 0;
  sysinfo_64.wProcessorArchitecture = 0;
  GetNativeSystemInfo (&sysinfo_64);
  GetSystemInfo (&sysinfo_32);
  return sysinfo_64.wProcessorArchitecture == sysinfo_32.wProcessorArchitecture && sysinfo_64.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64;
}

int iam32on64 ()
{
  SYSTEM_INFO sysinfo_32, sysinfo_64;
  sysinfo_32.wProcessorArchitecture = 0;
  sysinfo_64.wProcessorArchitecture = 0;
  GetNativeSystemInfo (&sysinfo_64);
  GetSystemInfo (&sysinfo_32);
  return sysinfo_64.wProcessorArchitecture != sysinfo_32.wProcessorArchitecture && sysinfo_64.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64;
}

void logtofile (char *filename, char *format, ...)
{
  va_list argptr;
  FILE *f;
  if (filename == NULL)
    return;

  va_start(argptr, format);
 
  f = fopen (filename, "ab");
  if (f != NULL)
  {
    vfprintf(f, format, argptr);
    fclose (f);
  }
 
  va_end(argptr);
}

void logtofilew (wchar_t *filename, wchar_t *format, ...)
{
  va_list argptr;
  FILE *f;
  if (filename == NULL)
    return;

  va_start(argptr, format);
 
  f = _wfopen (filename, L"ab");
  if (f != NULL)
  {
    vfwprintf(f, format, argptr);
    fclose (f);
  }
 
  va_end(argptr);
}


/* Helper function. Opens <hKey>'s subkey <name> and retreives its DWORD value named <valname> 
 * and writes the result into variable pointed by <data>.
 * <valname> can be NULL to retreive the default value.
 * Will ask for <flags> | KEY_QUERY_VALUE access rights from <hKey>/<name>
 */
int get_dword_key (HKEY hKey, const wchar_t *name, const wchar_t *valname, DWORD *data, DWORD flags)
{
  LONG res = 0;
  int ret = 0;
  HKEY key = NULL;
  DWORD type1, type2;
  DWORD len1, len2;

  res = RegOpenKeyExW (hKey, name, 0, KEY_QUERY_VALUE | flags, &key);
  if (res != ERROR_SUCCESS)
  {
    ret = -1;
    goto end;
  }
  len1 = sizeof (DWORD);
  res = RegQueryValueExW (key, valname, NULL, &type1, (BYTE *) data, &len1);
  if (res != ERROR_SUCCESS)
  {
    ret = -2;
    goto end;
  }
  if (len1 <= 0 || type1 != REG_DWORD)
  {
    ret = -3;
    goto end;
  }
end:
  if (key != NULL)
    RegCloseKey (key);
  return ret;
}

/* Helper function. Opens <hKey>'s subkey <name> and retreives its SZ_REG value named <valname> 
 * and writes the result into variable pointed by <data>.
 * <valname> can be NULL to retreive the default value.
 * The resulting string is allocated by get_sz_key and should be freed by free().
 * Will ask for <flags> | KEY_QUERY_VALUE access rights from <hKey>/<name>
 */
int get_sz_key (HKEY hKey, const wchar_t *name, const wchar_t *valname, wchar_t **data, DWORD flags)
{
  LONG res = 0;
  int ret = 0;
  HKEY key = NULL;
  DWORD type1, type2;
  *data = NULL;
  DWORD len1, len2;

  res = RegOpenKeyExW (hKey, name, 0, KEY_QUERY_VALUE | flags, &key);
  if (res != ERROR_SUCCESS)
  {
    ret = -1;
    goto end;
  }
  res = RegQueryValueExW (key, valname, NULL, &type1, NULL, &len1);
  if (res != ERROR_SUCCESS)
  {
    ret = -2;
    goto end;
  }
  if (len1 <= 0 || type1 != REG_SZ && type1 != REG_EXPAND_SZ)
  {
    ret = -3;
    goto end;
  }
  len1 += sizeof (wchar_t);
  *data = (wchar_t *) malloc (len1);
  if (*data == NULL)
  {
    ret = -4;
    goto end;
  }
  len2 = len1;
  res = RegQueryValueExW (key, valname, NULL, &type2, (BYTE *) *data, &len2);
  if (res != ERROR_SUCCESS || type1 != type2 || len2 + sizeof (wchar_t) != len1)
  {
    ret = -5;
    goto end;
  }
  (*data)[len2 / sizeof (wchar_t)] = L'\0';
  RegCloseKey (key);
  return 0;
end:
  if (key != NULL)
    RegCloseKey (key);
  if (*data != NULL)
    free (*data);
  *data = NULL;
  return ret;
}

int
wchartostr (const wchar_t *wstr, char **retstr, UINT cp)
{
  char *str;
  int len, lenc;
  BOOL lossy = FALSE;

  if (wstr == NULL)
  {
    *retstr = NULL;
    return 0;
  }

  len = WideCharToMultiByte (cp, 0, wstr, -1, NULL, 0, NULL, &lossy);
  if (len <= 0)
  {
    return -1;
  }
  
  str = malloc (sizeof (char) * len);
  if (wstr == NULL)
  {
    return -2;
  }
  
  lenc = WideCharToMultiByte (cp, 0, wstr, -1, str, len, NULL, &lossy);
  if (lenc != len)
  {
    free (str);
    return -3;
  }
  *retstr = str;
  if (lossy)
    return 1;
  return 0;
}

int
strtowchar (const char *str, wchar_t **wretstr, UINT cp)
{
  wchar_t *wstr;
  int len, lenc;

  if (str == NULL)
  {
    *wretstr = NULL;
    return 0;
  }

  len = MultiByteToWideChar (cp, 0, str, -1, NULL, 0);
  if (len <= 0)
  {
    return -1;
  }
  
  wstr = malloc (sizeof (wchar_t) * len);
  if (wstr == NULL)
  {
    return -2;
  }
  
  lenc = MultiByteToWideChar (cp, 0, str, -1, wstr, len);
  if (lenc != len)
  {
    free (wstr);
    return -3;
  }
  *wretstr = wstr;
  return 0;
}
