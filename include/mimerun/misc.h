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

#ifndef __MISC_H__
#define __MISC_H__

#include <stdio.h>
#include <windows.h>

#if !defined(KEY_WOW64_32KEY) && !defined(_WIN64)
#define KEY_WOW64_32KEY 0
#endif

#define MIMERUN_SHEBANG_LOOKFORIT  0x01
#define MIMERUN_SHEBANG_TRYITFIRST 0x02
#define MIMERUN_SHEBANG_BAILONIT   0x04

int scan_vars (wchar_t *data, size_t datalen, size_t *newlen, wchar_t *result, int argc, wchar_t *argv[]);
wchar_t *expand_vars (wchar_t *data, wchar_t *argv[]);

int get_shebang (wchar_t *file, char interpreter[MAX_PATH + 1], char **arguments);

wchar_t *dup_wprintf (int *rlen, wchar_t *format, ...);

int iam64on64 ();
int iam32on64 ();
void logtofile (char *filename, char *format, ...);
void logtofilew (wchar_t *filename, wchar_t *format, ...);
void printhandles ();

int get_dword_key (HKEY hKey, const wchar_t *name, const wchar_t *valname, DWORD *data, DWORD flags);
int get_sz_key (HKEY hKey, const wchar_t *name, const wchar_t *valname, wchar_t **data, DWORD flags);

int wchartostr (const wchar_t *wstr, char **retstr, UINT cp);
int strtowchar (const char *str, wchar_t **wretstr, UINT cp);
#endif /*__MISC_H__*/
