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
#ifdef OT_STORAGE_FS
#include <opentxs/storage/StorageFS.hpp>

#include <cstdio>
#include <ios>
#include <iostream>
#include <fstream>
#include <vector>

#include <boost/filesystem.hpp>

namespace opentxs
{

StorageFS::StorageFS(
    const StorageConfig& config,
    const Digest&hash,
    const Random& random)
        : ot_super(config, hash, random)
        , folder_(config.path_)
{
    Init_StorageFS();
}

void StorageFS::Init_StorageFS()
{
    boost::filesystem::create_directory(
        folder_ + "/" + config_.fs_primary_bucket_);
    boost::filesystem::create_directory(
        folder_+ "/" + config_.fs_secondary_bucket_);
}

void StorageFS::Purge(const std::string& path)
{
    if (path.empty()) { return; }

    boost::filesystem::remove_all(path);
}

std::string StorageFS::LoadRoot()
{
    if (!folder_.empty()) {
        std::string filename = folder_ + "/" + config_.fs_root_file_;

        if (!boost::filesystem::exists(filename)) { return ""; }

        std::ifstream file(
            filename,
            std::ios::in | std::ios::ate | std::ios::binary);

        if (file.good()) {
            std::ifstream::pos_type pos = file.tellg();

            if ((0 >= pos) || (0xFFFFFFFF <= pos)) { return ""; }

            uint32_t size(pos);

            file.seekg(0, std::ios::beg);

            std::vector<char> bytes(size);
            file.read(&bytes[0], size);

            return std::string(&bytes[0], size);
        }
    }

    return "";
}

bool StorageFS::Load(
    const std::string& key,
    std::string& value,
    const bool bucket)
{
    std::string folder =  folder_ + "/" + GetBucketName(bucket);
    std::string filename = folder + "/" + key;

    if (!boost::filesystem::exists(filename)) { return false; }

    if (!folder_.empty()) {
        std::ifstream file(
            filename,
            std::ios::in | std::ios::ate | std::ios::binary);

        if (file.good()) {
            std::ifstream::pos_type pos = file.tellg();

            if ((0 >= pos) || (0xFFFFFFFF <= pos)) { return false; }

            uint32_t size(pos);

            file.seekg(0, std::ios::beg);

            std::vector<char> bytes(size);
            file.read(&bytes[0], size);

            value.assign(&bytes[0], size);

            return true;
        }
    }

    return false;
}

bool StorageFS::StoreRoot(const std::string& hash)
{
    if (!folder_.empty()) {
        std::string filename = folder_ + "/" + config_.fs_root_file_;
        std::ofstream file(
            filename,
            std::ios::out | std::ios::trunc | std::ios::binary);

        if (file.good()) {
            file.write(hash.c_str(), hash.size());
            file.close();

            return true;
        }
    }

    return false;
}

bool StorageFS::Store(
    const std::string& key,
    const std::string& value,
    const bool bucket)
{
    std::string folder =  folder_ + "/" + GetBucketName(bucket);
    std::string filename = folder + "/" + key;

    if (!folder_.empty()) {
        std::ofstream file(
            filename,
            std::ios::out | std::ios::trunc | std::ios::binary);
        if (file.good()) {
            file.write(value.c_str(), value.size());
            file.close();

            return true;
        }
    }

    return false;
}

bool StorageFS::EmptyBucket(
    const bool bucket)
{
    assert(random_);

    std::string oldDirectory = folder_ + "/" + GetBucketName(bucket);
    std::string random = random_();
    std::string newName = folder_ + "/" + random;

    if (0 != std::rename(oldDirectory.c_str(), newName.c_str())) {
        return false;
    }

    std::thread backgroundDelete(&StorageFS::Purge, this, newName);
    backgroundDelete.detach();

    return boost::filesystem::create_directory(oldDirectory);
}

void StorageFS::Cleanup_StorageFS()
{
    // future cleanup actions go here
}

void StorageFS::Cleanup()
{
    Cleanup_StorageFS();
}

StorageFS::~StorageFS()
{
    Cleanup_StorageFS();
}

} // namespace opentxs
#endif
