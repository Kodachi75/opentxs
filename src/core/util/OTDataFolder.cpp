/************************************************************
 *
 *                 OPEN TRANSACTIONS
 *
 *       Financial Cryptography and Digital Cash
 *       Library, Protocol, API, Server, CLI, GUI
 *
 *       -- Anonymous Numbered Accounts.
 *       -- Untraceable Digital Cash.
 *       -- Triple-Signed Receipts.
 *       -- Cheques, Vouchers, Transfers, Inboxes.
 *       -- Basket Currencies, Markets, Payment Plans.
 *       -- Signed, XML, Ricardian-style Contracts.
 *       -- Scripted smart contracts.
 *
 *  EMAIL:
 *  fellowtraveler@opentransactions.org
 *
 *  WEBSITE:
 *  http://www.opentransactions.org/
 *
 *  -----------------------------------------------------
 *
 *   LICENSE:
 *   This Source Code Form is subject to the terms of the
 *   Mozilla Public License, v. 2.0. If a copy of the MPL
 *   was not distributed with this file, You can obtain one
 *   at http://mozilla.org/MPL/2.0/.
 *
 *   DISCLAIMER:
 *   This program is distributed in the hope that it will
 *   be useful, but WITHOUT ANY WARRANTY; without even the
 *   implied warranty of MERCHANTABILITY or FITNESS FOR A
 *   PARTICULAR PURPOSE.  See the Mozilla Public License
 *   for more details.
 *
 ************************************************************/

#include <opentxs/core/stdafx.hpp>

#include <opentxs/core/util/OTDataFolder.hpp>
#include <opentxs/core/util/OTPaths.hpp>
#include <opentxs/core/Log.hpp>

#ifdef _WIN32
#include <direct.h>
#include <shlobj.h>
#endif

#ifndef _WIN32
#include <libgen.h>
#include <unistd.h>
#endif

#ifdef __APPLE__
#include "TargetConditionals.h"
#endif

#ifdef TARGET_OS_MAC
#include <mach-o/dyld.h>
#include <limits.h>
#endif

#define CONFIG_FILE_EXT ".cfg"
#define DATA_FOLDER_EXT "_data"
#define OT_CONFIG_ISRELATIVE "_is_relative"

namespace opentxs
{

OTDataFolder* OTDataFolder::pDataFolder;

bool OTDataFolder::Init(const String& strThreadContext)
{
    if (nullptr != pDataFolder)
        return true; // we already have a data dir setup.

    if (!strThreadContext.Exists()) {
        otErr << __FUNCTION__ << ": Null: "
              << "strThreadContext"
              << " passed in!\n";
        OT_FAIL;
    }
    if (3 > strThreadContext.GetLength()) {
        otErr << __FUNCTION__ << ": Too Short: "
              << "strThreadContext"
              << " !\n";
        OT_FAIL;
    }

    pDataFolder = new OTDataFolder; // make the new instance

    pDataFolder->m_bInitialized = false;

    // setup the config instance.
    std::unique_ptr<Settings> pSettings(new Settings(OTPaths::GlobalConfigFile()));
    pSettings->Reset();
    if (!pSettings->Load()) return false;

    // setup the RelativeKey
    String l_strRelativeKey("");
    l_strRelativeKey.Format("%s%s", strThreadContext.Get(),
                            OT_CONFIG_ISRELATIVE);

    bool l_IsRelative(false), l_Exist(false);
    String l_strFolderName(""), l_strDataConfigFilename("");

    // check the config for an existing configuration.
    if (!pSettings->Check_bool("data_path", l_strRelativeKey, l_IsRelative,
                               l_Exist)) {
        return false;
    } // is data folder relative

    if (l_Exist) {
        if (!pSettings->Check_str("data_path", strThreadContext,
                                  l_strFolderName, l_Exist)) {
            return false;
        } // what is the data folder

        if (l_Exist) {
            if (!pSettings->Check_str("data_config", strThreadContext,
                                      l_strDataConfigFilename, l_Exist)) {
                return false;
            } // what is config file name

            if (l_Exist) {
                if (l_IsRelative) // data folder path
                {
                    if (!OTPaths::AppendFolder(pDataFolder->m_strDataFolderPath,
                                               OTPaths::AppDataFolder(),
                                               l_strFolderName)) {
                        return false;
                    }
                }
                else {
                    pDataFolder->m_strDataFolderPath = l_strFolderName;
                }

                // data config file path.
                if (!OTPaths::AppendFile(pDataFolder->m_strDataConfigFilePath,
                                         OTPaths::AppDataFolder(),
                                         l_strDataConfigFilename)) {
                    return false;
                }

                pDataFolder->m_bInitialized = true;
                return true;
            }
        }
    }

    // if we get here we do not have a valid config, lets set one.

    // setup the default config file-name;
    l_strFolderName.Format("%s%s", strThreadContext.Get(), DATA_FOLDER_EXT);
    l_strDataConfigFilename.Format("%s%s", strThreadContext.Get(),
                                   CONFIG_FILE_EXT);

    if (!pSettings->Set_bool("data_path", l_strRelativeKey, true, l_Exist)) {
        return false;
    }
    if (!pSettings->Set_str("data_path", strThreadContext, l_strFolderName,
                            l_Exist)) {
        return false;
    }
    if (!pSettings->Set_str("data_config", strThreadContext,
                            l_strDataConfigFilename, l_Exist)) {
        return false;
    }

    if (!OTPaths::AppendFolder(pDataFolder->m_strDataFolderPath,
                               OTPaths::AppDataFolder(), l_strFolderName)) {
        return false;
    }
    if (!OTPaths::AppendFile(pDataFolder->m_strDataConfigFilePath,
                             OTPaths::AppDataFolder(),
                             l_strDataConfigFilename)) {
        return false;
    }

    // save config
    if (!pSettings->Save()) return false;
    pSettings->Reset();

    // have set the default dir, now returning true;

    pDataFolder->m_bInitialized = true;
    return true;
}

bool OTDataFolder::IsInitialized()
{
    if (nullptr == pDataFolder)
        return false; // we already have a data dir setup.

    return pDataFolder->m_bInitialized;
}

bool OTDataFolder::Cleanup()
{
    if (nullptr != pDataFolder) {
        delete pDataFolder;
        pDataFolder = nullptr;
        return true;
    }
    else {
        pDataFolder = nullptr;
        return false;
    }
}

String OTDataFolder::Get()
{
    if (!OTDataFolder::IsInitialized()) {
        OT_FAIL;
    }

    String strDataFolder = "";
    if (OTDataFolder::Get(strDataFolder)) {
        return strDataFolder;
    }
    else {
        strDataFolder = "";
        return strDataFolder;
    }
}

bool OTDataFolder::Get(String& strDataFolder)
{
    if (nullptr != pDataFolder) {
        if (true == pDataFolder->m_bInitialized) {
            if (pDataFolder->m_strDataFolderPath.Exists()) {
                strDataFolder = pDataFolder->m_strDataFolderPath;
                return true;
            }
        }
    }

    return false;
}

bool OTDataFolder::GetConfigFilePath(String& strConfigFilePath)
{
    if (nullptr != pDataFolder) {
        if (true == pDataFolder->m_bInitialized) {
            if (pDataFolder->m_strDataConfigFilePath.Exists()) {
                strConfigFilePath = pDataFolder->m_strDataConfigFilePath;
                return true;
            }
        }
    }

    return false;
}

} // namespace opentxs
