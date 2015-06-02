/* show_console.c: on Windows, show the console at the end of xchat */

#include <stdio.h>
#include <stdlib.h>
#include "windows.h"

int main (int argc, char ** argv)
{
    HWND hwnd = FindWindow (NULL, "xchat.exe");
    ShowWindow (hwnd, SW_SHOW);
    return 0;
}
