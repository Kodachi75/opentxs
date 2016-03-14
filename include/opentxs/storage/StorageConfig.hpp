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

#ifndef OPENTXS_STORAGE_STORAGECONFIG_HPP
#define OPENTXS_STORAGE_STORAGECONFIG_HPP

#include <functional>
#include <string>

namespace opentxs
{

typedef std::function<void(const std::string&, const std::string&)>  InsertCB;

class StorageConfig
{
public:
    bool auto_publish_nyms_ = true;
    bool auto_publish_servers_ = true;
    bool auto_publish_units_ = true;
    int64_t gc_interval_ = 60 * 60 * 1;
    std::string path_;
    InsertCB dht_callback_;

#ifdef OT_STORAGE_FS
    std::string fs_primary_bucket_ = "a";
    std::string fs_secondary_bucket_ = "b";
    std::string fs_root_file_ = "root";

#endif

#ifdef OT_STORAGE_SQLITE
    std::string sqlite3_primary_bucket_ = "a";
    std::string sqlite3_secondary_bucket_ = "b";
    std::string sqlite3_control_table_ = "control";
    std::string sqlite3_root_key_ = "a";
    std::string sqlite3_db_file_ = "opentxs.sqlite3";
#endif
};

}  // namespace opentxs
#endif // OPENTXS_STORAGE_STORAGECONFIG_HPP
