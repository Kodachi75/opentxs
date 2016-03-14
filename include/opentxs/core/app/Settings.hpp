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

#ifndef OPENTXS_CORE_OTSETTINGS_HPP
#define OPENTXS_CORE_OTSETTINGS_HPP

#include <memory>

#include <opentxs/core/String.hpp>

namespace opentxs
{

class Settings
{
private:
    Settings(const Settings&) = delete;
    Settings& operator=(const Settings&) = delete;

    class SettingsPvt;
    std::unique_ptr<SettingsPvt> pvt_;

    bool b_Loaded;

    String m_strConfigurationFileExactPath;

    // Core (Load and Save)
    EXPORT bool Load(const String& strConfigurationFileExactPath);
    EXPORT bool Save(const String& strConfigurationFileExactPath);

    // Log (log to Output in a well-formated way).
    EXPORT bool LogChange_str(const String& strSection, const String& strKey,
                              const String& strValue);

    EXPORT bool Init();
public:
    EXPORT Settings();

    EXPORT Settings(const String& strConfigFilePath);

    EXPORT ~Settings();

    EXPORT void SetConfigFilePath(const String& strConfigFilePath);
    EXPORT bool HasConfigFilePath();

    // Core (Public Load and Save)
    EXPORT bool Load();
    EXPORT bool Save();

    EXPORT const bool& IsLoaded() const;

    // Configuration Helpers
    //

    // Core (Reset Config, and Check if Config is empty)
    EXPORT bool Reset();
    EXPORT bool IsEmpty() const;

    // Check Only (get value of key from configuration, if the key exists, then
    // out_bKeyExist will be true.)
    EXPORT bool Check_str(const String& strSection, const String& strKey,
                          String& out_strResult, bool& out_bKeyExist) const;
    EXPORT bool Check_long(const String& strSection, const String& strKey,
                           int64_t& out_lResult, bool& out_bKeyExist) const;
    EXPORT bool Check_bool(const String& strSection, const String& strKey,
                           bool& out_bResult, bool& out_bKeyExist) const;

    // Set Only (set new or update value, out_bNewOrUpdate will be true if the
    // value changes.)
    EXPORT bool Set_str(const String& strSection, const String& strKey,
                        const String& strValue, bool& out_bNewOrUpdate,
                        const String& strComment = "");
    EXPORT bool Set_long(const String& strSection, const String& strKey,
                         const int64_t& lValue, bool& out_bNewOrUpdate,
                         const String& strComment = "");
    EXPORT bool Set_bool(const String& strSection, const String& strKey,
                         const bool& bValue, bool& out_bNewOrUpdate,
                         const String& strComment = "");

    // Check for a Section, if the section dosn't exist, it will be made and
    // out_bIsNewSection will be true.)
    EXPORT bool CheckSetSection(const String& strSection,
                                const String& strComment,
                                bool& out_bIsNewSection);

    // Check for Key, and returns if the key exists, otherwise will set the
    // default key. If the default key is set, then out_bIsNew will be true.)
    EXPORT bool CheckSet_str(const String& strSection, const String& strKey,
                             const String& strDefault, std::string& out_strResult,
                             bool& out_bIsNew, const String& strComment = "");
    EXPORT bool CheckSet_str(const String& strSection, const String& strKey,
                             const String& strDefault, String& out_strResult,
                             bool& out_bIsNew, const String& strComment = "");
    EXPORT bool CheckSet_long(const String& strSection, const String& strKey,
                              const int64_t& lDefault, int64_t& out_lResult,
                              bool& out_bIsNew, const String& strComment = "");
    EXPORT bool CheckSet_bool(const String& strSection, const String& strKey,
                              const bool& bDefault, bool& out_bResult,
                              bool& out_bIsNew, const String& strComment = "");

    // Set Option helper function for setting bool's
    EXPORT bool SetOption_bool(const String& strSection, const String& strKey,
                               bool& bVariableName);
};

} // namespace opentxs

#endif // OPENTXS_CORE_OTSETTINGS_HPP
