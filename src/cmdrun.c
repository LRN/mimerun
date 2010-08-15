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

#include <windows.h>
#include <mimerun/mimerunshook.h>
#include <stdio.h>
#include <mimerun/misc.h>
#include <errno.h>

/* This is the function we're going to load at runtime from libmimerunshook */
typedef HRESULT (STDMETHODCALLTYPE *MimeRunSHook_ExecuteW_Function) (LPVOID this, LPSHELLEXECUTEINFOW einfo);

/* This monstrosity simply passes commandline arguments to MimeRunSHook_ExecuteW(), as if
 * a ShellExecuteEx() call was made. This program is intended to be called by Windows shell,
 * which does not have neither console, nor standard streams. Usually this program is inserted
 * as a handler for unknown types of files.
 */
int CALLBACK WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
  wchar_t *cmdline = GetCommandLineW ();
  int argc;
  wchar_t **argv = CommandLineToArgvW (cmdline, &argc);
  if (argc > 3)
  {
    SHELLEXECUTEINFOW sei;
    HMODULE libmimerun;
    DWORD pathlen = 0;
    wchar_t cdir[MAX_PATH];
    wchar_t *tmp;
    HINSTANCE result;
    MimeRunSHook_ExecuteW_Function call_execute;
    if ((pathlen = GetModuleFileNameW (NULL, cdir, MAX_PATH)) > 0 && (tmp = wcsrchr (cdir, L'\\')) != NULL)
    {
      swprintf (tmp, L"\\libmimerunshook-%d.dll", VERSION_MAJOR);
      libmimerun = LoadLibraryW (cdir);
      if (libmimerun != NULL)
      {
        call_execute = (MimeRunSHook_ExecuteW_Function) GetProcAddress (libmimerun, "MimeRunSHook_ExecuteW");
        if (call_execute != NULL)
        {
          HRESULT hr;
          memset (&sei, 0, sizeof (sei));
          sei.cbSize = sizeof (sei);

          #define showconv(a) if (wcscmp (argv[1], L###a) == 0) sei.nShow = a

          showconv(SW_SHOWNORMAL);
          else showconv(SW_HIDE);
          else showconv(SW_MAXIMIZE);
          else showconv(SW_MINIMIZE);
          else showconv(SW_RESTORE);
          else showconv(SW_SHOW);
          else showconv(SW_SHOWDEFAULT);
          else showconv(SW_SHOWMAXIMIZED);
          else showconv(SW_SHOWMINIMIZED);
          else showconv(SW_SHOWMINNOACTIVE);
          else showconv(SW_SHOWNA);
          else showconv(SW_SHOWNOACTIVATE);
          else sei.nShow = SW_SHOWNORMAL;

          sei.lpFile = argv[3];
          sei.fMask = SEE_MASK_DOENVSUBST;

          /* This is a special hack: this == 1 means that the function is called directly */
          hr = call_execute ((LPVOID) 1, &sei);
          FreeLibrary (libmimerun);
          libmimerun = NULL;
          if (hr == S_OK)
          /* cmdrun is supposed to be run as a handler for unknown types of files. Which means that
           * the shell is out of ideas about handling this file. Which means that if call_execute() have
           * have failed (recognized the file, found a handler, but failed to run it), then we must show
           * an error.
           */
#ifdef _WIN64
            switch ((INT64) sei.hInstApp)
#else
            switch ((int) sei.hInstApp)
#endif
            {
            case 0:
              MessageBoxA (0, "The operating system is out of memory or resources.", "Failed to execute a file", MB_OK);
              break;
            case ERROR_FILE_NOT_FOUND:
              MessageBoxA (0, "The specified file was not found.", "Failed to execute a file", MB_OK);
              break;
            case ERROR_PATH_NOT_FOUND:
              MessageBoxA (0, "The specified path was not found.", "Failed to execute a file", MB_OK);
              break;
            case ERROR_BAD_FORMAT:
              MessageBoxA (0, "The .exe file is invalid (non-Win32 .exe or error in .exe image).", "Failed to execute a file", MB_OK);
              break;
            case SE_ERR_ACCESSDENIED:
              MessageBoxA (0, "The operating system denied access to the specified file.", "Failed to execute a file", MB_OK);
              break;
            case SE_ERR_ASSOCINCOMPLETE:
              MessageBoxA (0, "The file name association is incomplete or invalid.", "Failed to execute a file", MB_OK);
              break;
            case SE_ERR_DDEBUSY:
              MessageBoxA (0, "The DDE transaction could not be completed because other DDE transactions were being processed.", "Failed to execute a file", MB_OK);
              break;
            case SE_ERR_DDEFAIL:
              MessageBoxA (0, "The DDE transaction failed.", "Failed to execute a file", MB_OK);
              break;
            case SE_ERR_DDETIMEOUT:
              MessageBoxA (0, "The DDE transaction could not be completed because the request timed out.", "Failed to execute a file", MB_OK);
              break;
            case SE_ERR_DLLNOTFOUND:
              MessageBoxA (0, "The specified DLL was not found.", "Failed to execute a file", MB_OK);
              break;
            case SE_ERR_NOASSOC:
              MessageBoxA (0, "There is no application associated with the given file name extension. This error will also be returned if you attempt to print a file that is not printable.", "Failed to execute a file", MB_OK);
              break;
            case SE_ERR_OOM:
              MessageBoxA (0, "There was not enough memory to complete the operation.", "Failed to execute a file", MB_OK);
              break;
            case SE_ERR_SHARE:
              MessageBoxA (0, "A sharing violation occurred.", "Failed to execute a file", MB_OK);
              break;
            }
          else
          {
          /* call_execute() have failed to find a handler for this file. Depending on the arguments we should
           * either call the handler that was the Unknown handler before we registered (the default Windows
           * file association dialogue), or our own custom handler that displays rule editing dialog (not
           * implemented... yet?).
           */
            int fallback = 0;
            if (wcscmp (argv[2], L"system_fallback") == 0)
              fallback = 1;
            else if (wcscmp (argv[2], L"mimerun_fallback") == 0)
              fallback = 2;
            else
            {
              wchar_t *message = dup_wprintf (NULL, L"MimeRun and the Shell have faild to find a handler for the file %s. Press 'Yes' to run MimeRun rule editor to add new rule for this file. Press 'No' to run standard Shell File Association dialog. Press 'Cancel' to do nothing", argv[3]);
              if (message != NULL)
              {
                fallback = MessageBoxW (NULL, message, L"Failed to handle the file", MB_YESNOCANCEL);
                free (message);
                if (fallback == IDCANCEL)
                  fallback = 0;
                else if (fallback == IDYES)
                  fallback = 2;
                else if (fallback == IDNO)
                  fallback = 1;
                else
                  fallback = 0;
              }
            }
            if (fallback == 1)
            {
              wchar_t *openas = NULL;
              if (get_sz_key (HKEY_CLASSES_ROOT, L"Unknown\\shell\\opendlg\\command", NULL, &openas, 0) == 0)
              {
                wchar_t *expanded = NULL;
                wchar_t *fake_argv[3] = {L"", argv[3], NULL};
                expanded = expand_vars (openas, fake_argv);
                LocalFree (argv);
                argv = NULL;
                if (expanded != NULL)
                {
                  wchar_t **exargv;
                  int exargc;
                  free (openas);
                  openas = NULL;
                  if ((exargv = CommandLineToArgvW (expanded, &exargc)) != NULL && exargc > 0)
                  {
                    free (expanded);
                    expanded = NULL;
                    if (_wexecv (exargv[0], exargv) == -1)
                    {
                      switch (errno)
                      {
                      case E2BIG:
                        MessageBoxA (0, "The space required for the arguments and environment settings exceeds 32 K.", "Failed to execute system fallback", MB_OK);
                        break;
                      case EACCES:
                        MessageBoxA (0, "The specified file has a locking or sharing violation.", "Failed to execute system fallback", MB_OK);
                        break;
                      case EMFILE:
                        MessageBoxA (0, "Too many files open (the specified file must be opened to determine whether it is executable).", "Failed to execute system fallback", MB_OK);
                        break;
                      case ENOENT:
                        MessageBoxA (0, "File or path not found.", "Failed to execute system fallback", MB_OK);
                        break;
                      case ENOEXEC:
                        MessageBoxA (0, "The specified file is not executable or has an invalid executable-file format.", "Failed to execute system fallback", MB_OK);
                        break;
                      case ENOMEM:
                        MessageBoxA (0, "Not enough memory is available to execute the new process; or the available memory has been corrupted; or an invalid block exists, indicating that the calling process was not allocated properly.", "Failed to execute system fallback", MB_OK);
                        break;
                      default:
                        MessageBoxA (0, "Unknown error", "Failed to execute system fallback", MB_OK);
                        break;
                      }
                    }
                    LocalFree (exargv);
                  }
                  if (expanded != NULL)
                    free (expanded);
                }
                if (openas != NULL)
                  free (openas);
              }
            }
            else if (fallback == 2)
            {
              /* Not implemented yet - should run something like <currentdir>/mimerunruleedit.exe */
            }
          }
        }
        if (libmimerun != NULL)
          FreeLibrary (libmimerun);
      }
    }
  }
  if (argv != NULL)
    LocalFree (argv);
  return 0;
}

        