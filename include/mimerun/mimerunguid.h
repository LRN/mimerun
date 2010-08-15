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

#ifndef __MIMERUNGUID_H__
#define __MIMERUNGUID_H__

#include <objbase.h>

// {48B8EC64-6C00-4a39-988E-95E01BCDC7B9}
DEFINE_GUID(CLSID_IMimeRunSHook, 
0x48b8ec64, 0x6c00, 0x4a39, 0x98, 0x8e, 0x95, 0xe0, 0x1b, 0xcd, 0xc7, 0xb9);
// {CE78B141-6EF5-49fb-B60D-E52902D25D8B}
DEFINE_GUID(IID_IMimeRunSHook, 
0xce78b141, 0x6ef5, 0x49fb, 0xb6, 0xd, 0xe5, 0x29, 0x2, 0xd2, 0x5d, 0x8b);

#endif /* __MIMERUNGUID_H__ */
