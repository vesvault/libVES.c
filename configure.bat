@echo off

rem /*************************************************************************
rem          ___       ___
rem         /   \     /   \    VESvault
rem         \__ /     \ __/    Encrypt Everything without fear of losing the Key
rem            \\     //                   https://vesvault.com https://ves.host
rem             \\   //
rem     ___      \\_//
rem    /   \     /   \         libVES:                      VESvault API library
rem    \__ /     \ __/
rem       \\     //            VES Utility:   A command line interface to libVES
rem        \\   //
rem         \\_//              - Key Management and Exchange
rem         /   \              - Item Encryption and Sharing
rem         \___/              - Stream Encryption
rem
rem
rem (c) 2018 VESvault Corp
rem Jim Zubov <jz@vesvault.com>
rem
rem GNU General Public License v3
rem You may opt to use, copy, modify, merge, publish, distribute and/or sell
rem copies of the Software, and permit persons to whom the Software is
rem furnished to do so, under the terms of the COPYING file.
rem
rem This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
rem KIND, either express or implied.
rem
rem **************************************************************************/

copy /Y Makefile.win Makefile

echo *
echo * Quick config for Windows + Visual Studio
echo *
echo * Makefile created
echo *
echo * Set the proper paths to OpenSSL and libcURL in Makefile,
echo * then run nmake
echo *
