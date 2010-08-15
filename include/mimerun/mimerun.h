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

#ifndef __MIMERUN_H__
#define __MIMERUN_H__

#include <stdio.h>
#include <windows.h>

typedef struct
{
  wchar_t *wname;
  char *name;
  wchar_t *wtype;
  char *type;
  wchar_t *wenc;
  char *enc;
  wchar_t *wapple;
  char *apple;  
} MimeResults;

int runmime (wchar_t *logfile, LPSHELLEXECUTEINFOW einfo, wchar_t *lpfile, wchar_t *lpdirectory);

#endif /* __MIMERUN_H__ */
