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

#ifndef OPENTXS_STORAGE_STORAGE_HPP
#define OPENTXS_STORAGE_STORAGE_HPP

#include <atomic>
#include <cstdint>
#include <functional>
#include <iostream>
#include <limits>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <tuple>

#include <opentxs-proto/verify/VerifyCredentials.hpp>
#include <opentxs-proto/verify/VerifyContacts.hpp>
#include <opentxs-proto/verify/VerifyContracts.hpp>
#include <opentxs-proto/verify/VerifyStorage.hpp>

#include <opentxs/storage/StorageConfig.hpp>

namespace opentxs
{

typedef std::function<bool(const uint32_t, const std::string&, std::string&)>
    Digest;
typedef std::function<std::string()>
    Random;
typedef std::function<void(const proto::CredentialIndex&)> NymLambda;
typedef std::function<void(const proto::ServerContract&)> ServerLambda;
typedef std::function<void(const proto::UnitDefinition&)> UnitLambda;

template<class T>
std::string ProtoAsString(const T& serialized)
{
    auto size = serialized.ByteSize();
    char* protoArray = new char [size];

    serialized.SerializeToArray(protoArray, size);
    std::string serializedData(protoArray, size);
    delete[] protoArray;
    return serializedData;
}

// Content-aware storage module for opentxs
//
// Storage accepts serialized opentxs objects in protobuf form, writes them
// to persistant storage, and retrieves them on demand.
//
// All objects are stored in a key-value database. The keys are always the
// hash of the object being stored.
//
// This class maintains a set of index objects which map logical identifiers
// to object hashes. These index objects are stored in the same K-V namespace
// as the opentxs objects.
//
// The interface to a particular KV database is provided by child classes
// implementing this interface. Implementations need only provide methods for
// storing/retrieving arbitrary key-value pairs, and methods for setting and
// retrieving the hash of the root index object.
//
// The implementation of this interface must support the concept of "buckets"
// Objects are either stored and retrieved from either the primary bucket, or
// the alternate bucket. This allows for garbage collection of outdated keys
// to be implemented.
//
// TODO: investigate bugs resulting from running std namespace templates in
// this class. std::make_shared, std::unique_lock, and std::lock_guard do not
// always work as expected here.
class Storage
{
template<class T>
bool LoadProto(
    const std::string& hash,
    std::shared_ptr<T>& serialized,
    const bool checking = false)
{
    if (hash.empty()) {
        if (!checking) {
            std::cout << "Error:: Tried to load empty key" << std::endl;
        }

        return false;
    }

    bool attemptFirst;
    if (gc_running_.load() ) {
        attemptFirst = !current_bucket_;
    } else {
        attemptFirst = current_bucket_;
    }

    std::string data;

    std::lock_guard<std::mutex> bucketLock(bucket_lock_);
    bool foundInPrimary = false;
    if (Load(hash, data, attemptFirst)) {
        if (1 < data.size()) {
            serialized.reset(new T);
            serialized->ParseFromArray(data.c_str(), data.size());

            foundInPrimary = proto::Check<T>(*serialized, 0, 0xFFFFFFFF);
        }
    }

    bool foundInSecondary = false;
    if (!foundInPrimary) {
        // try again in the other bucket
        if (Load(hash, data, !attemptFirst)) {
            if (1 < data.size()) {
                serialized.reset(new T);
                serialized->ParseFromArray(data.c_str(), data.size());

                foundInSecondary = proto::Check<T>(*serialized, 0, 0xFFFFFFFF);
            }
        }
    }

    if (!foundInPrimary && !foundInSecondary && !checking) {
        std::cerr << "Failed loading object" << std::endl
                  << "Hash: " << hash << std::endl
                  << "Size: " << data.size() << std::endl;
    }

    return (foundInPrimary || foundInSecondary);
}

template<class T>
bool StoreProto(const T& data, std::string& key, std::string& plaintext)
{
    if (nullptr != digest_) {
        plaintext = opentxs::ProtoAsString<T>(data);
        digest_(Storage::HASH_TYPE, plaintext, key);

        return Store(
            key,
            plaintext,
            current_bucket_.load());
    }
    return false;
}

template<class T>
bool StoreProto(const T& data, std::string& key)
{
    std::string notUsed;

    return StoreProto<T>(data, key, notUsed);
}

template<class T>
bool StoreProto(const T& data)
{
    std::string notUsed;

    return StoreProto<T>(data, notUsed);
}

private:
    /** A set of metadata associated with a stored object
     *  * string: hash
     *  * string: alias
     */
    typedef std::pair<std::string, std::string> Metadata;

    /** Maps a logical id to the stored metadata for the object
     *  * string: id of the stored object
     *  * Metadata: metadata for the stored object
     */
    typedef std::map<std::string, Metadata> Index;

    static Storage* instance_pointer_;

    std::thread* gc_thread_ = nullptr;
    int64_t gc_interval_ = std::numeric_limits<int64_t>::max();

    Storage(const Storage&) = delete;
    Storage& operator=(const Storage&) = delete;

    void CollectGarbage();
    bool MigrateKey(const std::string& key);
    // Regenerate in-memory indices by recursively loading index objects
    // starting from the root hash
    void Read();
    void RunMapPublicNyms(NymLambda lambda); // copy the lambda since original
                                             // may destruct during execution
    void RunMapServers(ServerLambda lambda); // copy the lambda since original
                                             // may destruct during execution
    void RunMapUnits(UnitLambda lambda);     // copy the lambda since original
                                             // may destruct during execution
    // Methods for updating index objects
    bool UpdateCredentials(const std::string& id, const std::string& hash);
    bool UpdateNymCreds(
        const std::string& id,
        const std::string& hash,
        const std::string& alias);
    bool UpdateNym(const proto::StorageNym& nym, const std::string& alias);
    bool UpdateNymAlias(const std::string& id, const std::string& alias);
    bool UpdateNyms(std::unique_lock<std::mutex>& nymLock);
    bool UpdateSeed(
        const std::string& id,
        const std::string& hash,
        const std::string& alias);
    bool UpdateSeedAlias(const std::string& id, const std::string& alias);
    bool UpdateSeedDefault(const std::string& id);
    bool UpdateSeeds(std::unique_lock<std::mutex>& seedlock);
    bool UpdateServer(
        const std::string& id,
        const std::string& hash,
        const std::string& alias);
    bool UpdateServerAlias(const std::string& id, const std::string& alias);
    bool UpdateServers(std::unique_lock<std::mutex>& serverlock);
    bool UpdateUnit(
        const std::string& id,
        const std::string& hash,
        const std::string& alias);
    bool UpdateUnitAlias(const std::string& id, const std::string& alias);
    bool UpdateUnits(std::unique_lock<std::mutex>& unitlock);
    bool UpdateItems(const proto::StorageCredentials& creds);
    bool UpdateItems(const proto::StorageNymList& nyms);
    bool UpdateItems(const proto::StorageSeeds& seeds);
    bool UpdateItems(const proto::StorageServers& servers);
    bool UpdateItems(const proto::StorageUnits& units);
    bool UpdateRoot(const proto::StorageItems& items);
    bool UpdateRoot(proto::StorageRoot& root, const std::string& gcroot);
    bool UpdateRoot();

    void Cleanup_Storage();

protected:
    const uint32_t HASH_TYPE = 2; // BTC160
    StorageConfig config_;
    Digest digest_;
    Random random_;

    std::mutex init_lock_; // controls access to Read() method
    std::mutex bucket_lock_; // ensures buckets not changed during read
    std::mutex cred_lock_; // ensures atomic writes to credentials_
    std::mutex default_seed_lock_; // ensures atomic writes to default_seed_
    std::mutex gc_lock_; // prevents multiple garbage collection threads
    std::mutex nym_lock_; // ensures atomic writes to nyms_
    std::mutex seed_lock_; // ensures atomic writes to seeds_
    std::mutex server_lock_; // ensures atomic writes to servers_
    std::mutex unit_lock_; // ensures atomic writes to units_
    std::mutex write_lock_; // ensure atomic writes

    std::string root_hash_;
    std::string old_gc_root_; // used if a previous run of gc did not finish
    std::string items_;
    std::string default_seed_;

    std::atomic<bool> current_bucket_;
    std::atomic<bool> isLoaded_;
    std::atomic<bool> gc_running_;
    std::atomic<bool> gc_resume_;
    int64_t last_gc_ = 0;
    Index credentials_;
    Index nyms_;
    Index seeds_;
    Index servers_;
    Index units_;

    Storage(
        const StorageConfig& config,
        const Digest& hash,
        const Random& random);

    virtual void Init();

    // Pure virtual functions for implementation by child classes
    virtual std::string LoadRoot() = 0;
    virtual bool StoreRoot(const std::string& hash) = 0;
    virtual bool Load(
        const std::string& key,
        std::string& value,
        const bool bucket) = 0;
    virtual bool Store(
        const std::string& key,
        const std::string& value,
        const bool bucket) = 0;
    virtual bool EmptyBucket(const bool bucket) = 0;

public:
    /** A list of object IDs and their associated aliases
     *  * string: id of the stored object
     *  * string: alias of the stored object
     */
    typedef std::list<std::pair<std::string, std::string>> ObjectList;

    // Method for instantiating the singleton.
    static Storage& It(
        const Digest& hash,
        const Random& random,
        const StorageConfig& config);

    std::string DefaultSeed();
    bool Load(
        const std::string& id,
        std::shared_ptr<proto::Credential>& cred,
        const bool checking = false); // If true, suppress "not found" errors
    bool Load(
        const std::string& id,
        std::shared_ptr<proto::CredentialIndex>& nym,
        const bool checking = false); // If true, suppress "not found" errors
    bool Load(
        const std::string& id,
        std::shared_ptr<proto::CredentialIndex>& nym,
        std::string& alias,
        const bool checking = false); // If true, suppress "not found" errors
    bool Load(
        const std::string& id,
        std::shared_ptr<proto::Seed>& seed,
        const bool checking = false); // If true, suppress "not found" errors
    bool Load(
        const std::string& id,
        std::shared_ptr<proto::Seed>& seed,
        std::string& alias,
        const bool checking = false); // If true, suppress "not found" errors
    bool Load(
        const std::string& id,
        std::shared_ptr<proto::ServerContract>& contract,
        const bool checking = false); // If true, suppress "not found" errors
    bool Load(
        const std::string& id,
        std::shared_ptr<proto::ServerContract>& contract,
        std::string& alias,
        const bool checking = false); // If true, suppress "not found" errors
    bool Load(
        const std::string& id,
        std::shared_ptr<proto::UnitDefinition>& contract,
        const bool checking = false); // If true, suppress "not found" errors
    bool Load(
        const std::string& id,
        std::shared_ptr<proto::UnitDefinition>& contract,
        std::string& alias,
        const bool checking = false); // If true, suppress "not found" errors
    void MapPublicNyms(NymLambda& lambda);
    void MapServers(ServerLambda& lambda);
    void MapUnitDefinitions(UnitLambda& lambda);
    bool RemoveServer(const std::string& id);
    bool RemoveUnitDefinition(const std::string& id);
    void RunGC();
    std::string ServerAlias(const std::string& id);
    ObjectList ServerList();
    bool SetDefaultSeed(const std::string& id);
    bool SetNymAlias(const std::string& id, const std::string& alias);
    bool SetSeedAlias(const std::string& id, const std::string& alias);
    bool SetServerAlias(const std::string& id, const std::string& alias);
    bool SetUnitDefinitionAlias(const std::string& id, const std::string& alias);
    bool Store(const proto::Credential& data);
    bool Store(const proto::CredentialIndex& data, const std::string alias="");
    bool Store(const proto::Seed& data, const std::string alias="");
    bool Store(const proto::ServerContract& data, const std::string alias="");
    bool Store(const proto::UnitDefinition& data, const std::string alias="");
    std::string UnitDefinitionAlias(const std::string& id);
    ObjectList UnitDefinitionList();

    virtual void Cleanup();
    virtual ~Storage();
};

}  // namespace opentxs
#endif // OPENTXS_STORAGE_STORAGE_HPP
