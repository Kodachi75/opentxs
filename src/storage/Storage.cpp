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

#include <opentxs/storage/Storage.hpp>

#include <ctime>
#include <cstdlib>
#include <iostream>

#ifdef OT_STORAGE_FS
#include <opentxs/storage/StorageFS.hpp>
#elif defined OT_STORAGE_SQLITE
#include <opentxs/storage/StorageSqlite3.hpp>
#endif

namespace opentxs
{
Storage* Storage::instance_pointer_ = nullptr;

Storage::Storage(
    const StorageConfig& config,
    const Digest& hash,
    const Random& random)
        : gc_interval_(config.gc_interval_)
        , config_(config)
        , digest_(hash)
        , random_(random)
{
    std::time_t time = std::time(nullptr);
    last_gc_ = static_cast<int64_t>(time);

    Init();
}

void Storage::Init()
{
    current_bucket_.store(false);
    isLoaded_.store(false);
    gc_running_.store(false);
    gc_resume_.store(false);
}

Storage& Storage::It(
    const Digest& hash,
    const Random& random,
    const StorageConfig& config)
{

    if (nullptr == instance_pointer_) {
#ifdef OT_STORAGE_FS
        instance_pointer_ = new StorageFS(config, hash, random);
#elif defined OT_STORAGE_SQLITE
        instance_pointer_ = new StorageSqlite3(config, hash, random);
#endif
    }

    assert(nullptr != instance_pointer_);

    return *instance_pointer_;
}

void Storage::Read()
{
    std::lock_guard<std::mutex> readLock(init_lock_);

    if (!isLoaded_.load()) {
        isLoaded_.store(true);

        root_hash_ = LoadRoot();

        if (root_hash_.empty()) { return; }

        std::shared_ptr<proto::StorageRoot> root;

        if (!LoadProto<proto::StorageRoot>(root_hash_, root)) { return; }

        items_ = root->items();
        current_bucket_.store(root->altlocation());
        last_gc_ = root->lastgc();
        gc_resume_.store(root->gc());
        old_gc_root_ = root->gcroot();

        std::shared_ptr<proto::StorageItems> items;

        if (!LoadProto<proto::StorageItems>(items_, items)) { return; }

        if (!items->creds().empty()) {
            std::shared_ptr<proto::StorageCredentials> creds;

            if (!LoadProto<proto::StorageCredentials>(items->creds(), creds)) {
                std::cerr << __FUNCTION__ << ": failed to load credential "
                          << "index item. Database is corrupt." << std::endl;
                std::abort();
            }

            for (auto& it : creds->cred()) {
                credentials_.insert(std::pair<std::string, std::string>(
                    it.itemid(),
                    it.hash()));
            }
        }

        if (!items->nyms().empty()) {
            std::shared_ptr<proto::StorageNymList> nyms;

            if (!LoadProto<proto::StorageNymList>(items->nyms(), nyms)) {
                std::cerr << __FUNCTION__ << ": failed to load nym "
                << "index item. Database is corrupt." << std::endl;
                std::abort();
            }

            for (auto& it : nyms->nym()) {
                nyms_.insert(std::pair<std::string, std::string>(
                    it.itemid(),
                    it.hash()));
            }
        }

        if (!items->servers().empty()) {
            std::shared_ptr<proto::StorageServers> servers;

            if (!LoadProto<proto::StorageServers>(items->servers(), servers)) {
                std::cerr << __FUNCTION__ << ": failed to load server "
                << "index item. Database is corrupt." << std::endl;
                std::abort();
            }

            for (auto& it : servers->server()) {
                servers_.insert(std::pair<std::string, std::string>(
                    it.itemid(),
                    it.hash()));
            }
        }
    }
}

// Applies a lambda to all public nyms in the database in a detached thread.
void Storage::MapPublicNyms(NymLambda& lambda)
{
    std::thread bgMap(&Storage::RunMapPublicNyms, this, lambda);
    bgMap.detach();
}

// Applies a lambda to all server contracts in the database in a detached thread.
void Storage::MapServers(ServerLambda& lambda)
{
    std::thread bgMap(&Storage::RunMapServers, this, lambda);
    bgMap.detach();
}

void Storage::RunMapPublicNyms(NymLambda lambda)
{
    // std::unique_lock was failing to unlock the mutex even after Release()
    // was called. For now, lock and unlock mutexes directly instead of using
    // std::unique_lock and std::lock_guard

    gc_lock_.lock(); // block gc while iterating

    write_lock_.lock();
    std::string index = items_;
    write_lock_.unlock();

    std::shared_ptr<proto::StorageItems> items;

    if (!LoadProto<proto::StorageItems>(items_, items)) {
        gc_lock_.unlock();
        return;
    }

    if (items->nyms().empty()) {
        gc_lock_.unlock();
        return;
    }

    std::shared_ptr<proto::StorageNymList> nyms;

    if (!LoadProto<proto::StorageNymList>(items->nyms(), nyms)) {
        gc_lock_.unlock();
        return;
    }

    for (auto& it : nyms->nym()) {
        std::shared_ptr<proto::StorageNym> nymIndex;

        if (!LoadProto<proto::StorageNym>(it.hash(), nymIndex)) { continue; }

        std::shared_ptr<proto::CredentialIndex> nym;

        if (!LoadProto<proto::CredentialIndex>(nymIndex->credlist().hash(), nym))
            { continue; }

        lambda(*nym);
    }

    gc_lock_.unlock();
}

void Storage::RunMapServers(ServerLambda lambda)
{
    // std::unique_lock was failing to unlock the mutex even after Release()
    // was called. For now, lock and unlock mutexes directly instead of using
    // std::unique_lock and std::lock_guard

    gc_lock_.lock(); // block gc while iterating

    write_lock_.lock();
    std::string index = items_;
    write_lock_.unlock();

    std::shared_ptr<proto::StorageItems> items;

    if (!LoadProto<proto::StorageItems>(items_, items)) {
        gc_lock_.unlock();
        return;
    }

    if (items->servers().empty()) {
        gc_lock_.unlock();
        return;
    }

    std::shared_ptr<proto::StorageServers> servers;

    if (!LoadProto<proto::StorageServers>(items->servers(), servers)) {
        gc_lock_.unlock();
        return;
    }

    for (auto& it : servers->server()) {
        std::shared_ptr<proto::ServerContract> server;

        if (!LoadProto<proto::ServerContract>(it.hash(), server))
            { continue; }

        lambda(*server);
    }

    gc_lock_.unlock();
}

bool Storage::UpdateNymCreds(const std::string& id, const std::string& hash)
{
    // Reuse existing object, since it may contain more than just creds
    if (!id.empty() && !hash.empty()) {
        std::shared_ptr<proto::StorageNym> nym;

        if (!LoadProto<proto::StorageNym>(id, nym, true)) {
            nym = std::make_shared<proto::StorageNym>();
            nym->set_version(1);
            nym->set_nymid(id);
        } else {
            nym->clear_credlist();
        }

        proto::StorageItemHash* item = nym->mutable_credlist();
        item->set_version(1);
        item->set_itemid(id);
        item->set_hash(hash);

        if (!proto::Check<proto::StorageNym>(*nym, 0, 0xFFFFFFFF)) {
            abort();
        }

        if (StoreProto<proto::StorageNym>(*nym)) {
            return UpdateNyms(*nym);
        }
    }

    return false;
}

bool Storage::UpdateCredentials(const std::string& id, const std::string& hash)
{
    // Do not test for existing object - we always regenerate from scratch
    if (!id.empty() && !hash.empty()) {

        // Block reads while updating credential map
        cred_lock_.lock();
        credentials_[id] = hash;
        proto::StorageCredentials credIndex;
        credIndex.set_version(1);
        for (auto& cred : credentials_) {
            if (!cred.first.empty() && !cred.second.empty()) {
                proto::StorageItemHash* item = credIndex.add_cred();
                item->set_version(1);
                item->set_itemid(cred.first);
                item->set_hash(cred.second);
            }
        }
        cred_lock_.unlock();

        if (!proto::Check<proto::StorageCredentials>(credIndex, 0, 0xFFFFFFFF)) {
            abort();
        }

        if (StoreProto<proto::StorageCredentials>(credIndex)) {
            return UpdateItems(credIndex);
        }
    }

    return false;
}

bool Storage::UpdateNyms(const proto::StorageNym& nym)
{
    // Do not test for existing object - we always regenerate from scratch
    if (digest_) {
        std::string id = nym.nymid();
        std::string plaintext = ProtoAsString<proto::StorageNym>(nym);
        std::string hash;
        digest_(Storage::HASH_TYPE, plaintext, hash);

        // Block reads while updating nym map
        std::unique_lock<std::mutex> nymLock(nym_lock_);
        nyms_[id] = hash;
        proto::StorageNymList nymIndex;
        nymIndex.set_version(1);
        for (auto& nym : nyms_) {
            if (!nym.first.empty() && !nym.second.empty()) {
                proto::StorageItemHash* item = nymIndex.add_nym();
                item->set_version(1);
                item->set_itemid(nym.first);
                item->set_hash(nym.second);
            }
        }
        nymLock.unlock();

        if (!proto::Check<proto::StorageNymList>(nymIndex, 0, 0xFFFFFFFF)) {
            abort();
        }

        if (StoreProto<proto::StorageNymList>(nymIndex)) {
            return UpdateItems(nymIndex);
        }
    }

    return false;
}

bool Storage::UpdateServers(const std::string& id, const std::string& hash)
{
    // Do not test for existing object - we always regenerate from scratch
    if (!id.empty() && !hash.empty()) {

        // Block reads while updating credential map
        std::unique_lock<std::mutex> serverlock(server_lock_);
        servers_[id] = hash;
        proto::StorageServers serverIndex;
        serverIndex.set_version(1);
        for (auto& server : servers_) {
            if (!server.first.empty() && !server.second.empty()) {
                proto::StorageItemHash* item = serverIndex.add_server();
                item->set_version(1);
                item->set_itemid(server.first);
                item->set_hash(server.second);
            }
        }
        serverlock.unlock();

        if (!proto::Check<proto::StorageServers>(serverIndex, 0, 0xFFFFFFFF)) {
            abort();
        }

        if (StoreProto<proto::StorageServers>(serverIndex)) {
            return UpdateItems(serverIndex);
        }
    }

    return false;
}

bool Storage::UpdateItems(const proto::StorageCredentials& creds)
{
    // Reuse existing object, since it may contain more than just creds
    std::shared_ptr<proto::StorageItems> items;

    if (!LoadProto<proto::StorageItems>(items_, items, true)) {
        items = std::make_shared<proto::StorageItems>();
        items->set_version(1);
    } else {
        items->clear_creds();
    }

    if (digest_) {
        std::string plaintext = ProtoAsString<proto::StorageCredentials>(creds);
        std::string hash;
        digest_(Storage::HASH_TYPE, plaintext, hash);

        items->set_creds(hash);

        if (!proto::Check<proto::StorageItems>(*items, 0, 0xFFFFFFFF)) {
            abort();
        }

        if (StoreProto<proto::StorageItems>(*items)) {
            return UpdateRoot(*items);
        }
    }

    return false;
}

bool Storage::UpdateItems(const proto::StorageNymList& nyms)
{
    // Reuse existing object, since it may contain more than just nyms
    std::shared_ptr<proto::StorageItems> items;

    if (!LoadProto<proto::StorageItems>(items_, items, true)) {
        items = std::make_shared<proto::StorageItems>();
        items->set_version(1);
    } else {
        items->clear_nyms();
    }

    if (digest_) {
        std::string plaintext = ProtoAsString<proto::StorageNymList>(nyms);
        std::string hash;
        digest_(Storage::HASH_TYPE, plaintext, hash);

        items->set_nyms(hash);

        if (!proto::Check<proto::StorageItems>(*items, 0, 0xFFFFFFFF)) {
            abort();
        }

        if (StoreProto<proto::StorageItems>(*items)) {
            return UpdateRoot(*items);
        }
    }

    return false;
}

bool Storage::UpdateItems(const proto::StorageServers& servers)
{
    // Reuse existing object, since it may contain more than just servers
    std::shared_ptr<proto::StorageItems> items;

    if (!LoadProto<proto::StorageItems>(items_, items, true)) {
        items = std::make_shared<proto::StorageItems>();
        items->set_version(1);
    } else {
        items->clear_servers();
    }

    if (digest_) {
        std::string plaintext = ProtoAsString<proto::StorageServers>(servers);
        std::string hash;
        digest_(Storage::HASH_TYPE, plaintext, hash);

        items->set_servers(hash);

        if (!proto::Check<proto::StorageItems>(*items, 0, 0xFFFFFFFF)) {
            abort();
        }

        if (StoreProto<proto::StorageItems>(*items)) {
            return UpdateRoot(*items);
        }
    }

    return false;
}

bool Storage::UpdateRoot(const proto::StorageItems& items)
{
    // Reuse existing object to preserve current settings
    std::shared_ptr<proto::StorageRoot> root;

    if (!LoadProto<proto::StorageRoot>(root_hash_, root, true)) {
        root = std::make_shared<proto::StorageRoot>();
        root->set_version(1);
        root->set_altlocation(false);
        std::time_t time = std::time(nullptr);
        root->set_lastgc(static_cast<int64_t>(time));
    } else {
        root->clear_items();
    }

    if (digest_) {
        std::string plaintext = ProtoAsString<proto::StorageItems>(items);
        std::string hash;
        digest_(Storage::HASH_TYPE, plaintext, hash);

        items_ = hash;

        root->set_version(1);
        root->set_items(hash);

        if (!proto::Check<proto::StorageRoot>(*root, 0, 0xFFFFFFFF)) {
            abort();
        }

        if (StoreProto<proto::StorageRoot>(*root)) {
            plaintext = ProtoAsString<proto::StorageRoot>(*root);
            digest_(Storage::HASH_TYPE, plaintext, hash);

            root_hash_ = hash;

            return StoreRoot(hash);
        }
    }

    return false;
}

// this version is for starting garbage collection only
bool Storage::UpdateRoot(
    proto::StorageRoot& root,
    const std::string& gcroot)
{
    if (digest_) {
        root.set_altlocation(current_bucket_.load());

        std::time_t time = std::time(nullptr);
        last_gc_ = static_cast<int64_t>(time);
        root.set_lastgc(last_gc_);
        root.set_gc(true);
        root.set_gcroot(gcroot);

        if (!proto::Check<proto::StorageRoot>(root, 0, 0xFFFFFFFF)) {
            abort();
        }

        if (StoreProto<proto::StorageRoot>(root)) {
            std::string hash;
            std::string plaintext = ProtoAsString<proto::StorageRoot>(root);
            digest_(Storage::HASH_TYPE, plaintext, hash);

            root_hash_ = hash;

            return StoreRoot(hash);
        }
    }

    return false;
}

// this version is for ending garbage collection only
bool Storage::UpdateRoot()
{
    std::shared_ptr<proto::StorageRoot> root;

    bool loaded = LoadProto<proto::StorageRoot>(root_hash_, root);

    assert(loaded);

    if (loaded && digest_) {
        gc_running_.store(false);
        root->set_gc(false);

        if (!proto::Check<proto::StorageRoot>(*root, 0, 0xFFFFFFFF)) {
            abort();
        }

        if (StoreProto<proto::StorageRoot>(*root)) {
            std::string hash;
            std::string plaintext = ProtoAsString<proto::StorageRoot>(*root);
            digest_(Storage::HASH_TYPE, plaintext, hash);

            root_hash_ = hash;

            return StoreRoot(hash);
        }
    }

    return false;
}

bool Storage::Load(
    const std::string& id,
    std::shared_ptr<proto::Credential>& cred,
    const bool checking)
{
    if (!isLoaded_.load()) { Read(); }

    bool found = false;
    std::string hash;

    // block writes while searching credential map
    cred_lock_.lock();
    auto it = credentials_.find(id);
    if (it != credentials_.end()) {
        found = true;
        hash = it->second;
    }
    cred_lock_.unlock();

    if (found) {
        return LoadProto<proto::Credential>(hash, cred, checking);
    }

    if (!checking) {
        std::cout << __FUNCTION__ << ": Error: credential with id " << id
                << " does not exist in the map of stored credentials."
                << std::endl;
    }

    return false;
}

bool Storage::Load(
    const std::string& id,
    std::shared_ptr<proto::ServerContract>& contract,
    const bool checking)
{
    if (!isLoaded_.load()) { Read(); }

    bool found = false;
    std::string hash;

    // block writes while searching server map
    std::unique_lock<std::mutex> serverLock(server_lock_);
    auto it = servers_.find(id);
    if (it != servers_.end()) {
        found = true;
        hash = it->second;
    }
    serverLock.unlock();

    if (found) {
        return LoadProto<proto::ServerContract>(hash, contract, checking);
    }

    if (!checking) {
        std::cout << __FUNCTION__ << ": Error: server with id " << id
        << " does not exist in the map of stored contracts."
        << std::endl;
    }

    return false;
}

bool Storage::Load(
    const std::string& id,
    std::shared_ptr<proto::CredentialIndex>& credList,
    const bool checking)
{
    if (!isLoaded_.load()) { Read(); }

    bool found = false;
    std::string nymHash;

    // block writes while searching nym map
    std::unique_lock<std::mutex> nymLock(nym_lock_);
    auto it = nyms_.find(id);
    if (it != nyms_.end()) {
        found = true;
        nymHash = it->second;
    }
    nymLock.unlock();

    if (found) {
        std::shared_ptr<proto::StorageNym> nym;

        if (LoadProto<proto::StorageNym>(nymHash, nym, checking)) {
            std::string credListHash = nym->credlist().hash();

            if (LoadProto<proto::CredentialIndex>
                (credListHash, credList, checking)) {

                return true;
            } else {
                std::cout << __FUNCTION__ << ": Error: can not load public nym "
                << id << ". Database is corrupt." << std::endl;
                abort();
            }
        } else {
            std::cout << __FUNCTION__ << ": Error: can not load index object "
            << "for nym " << id << ". Database is corrupt." << std::endl;
            abort();
        }
    }

    if (!checking) {
        std::cout << __FUNCTION__ << ": Error: credential with id " << id
        << " does not exist in the map of stored credentials."
        << std::endl;
    }

    return false;
}

bool Storage::Store(const proto::Credential& data)
{
    if (!isLoaded_.load()) { Read(); }

    // Avoid overwriting private credentials with public credentials
    bool existingPrivate = false;
    std::shared_ptr<proto::Credential> existing;

    if (Load(data.id(), existing, true)) { // suppress "not found" error
        existingPrivate = (proto::KEYMODE_PRIVATE == existing->mode());
    }

    if (existingPrivate && (proto::KEYMODE_PRIVATE != data.mode())) {
        std::cout << "Skipping update of existing private credential with "
                  << "non-private version." << std::endl;

        return true;
    }

    if (digest_) {
        std::string plaintext = ProtoAsString<proto::Credential>(data);
        std::string key;
        digest_(Storage::HASH_TYPE, plaintext, key);

        std::lock_guard<std::mutex> writeLock(write_lock_);
        bool savedCredential = Store(
            key,
            plaintext,
            current_bucket_.load());

        if (savedCredential) {
            return UpdateCredentials(data.id(), key);
        }
    }
    return false;
}

bool Storage::Store(const proto::ServerContract& data)
{
    if (!isLoaded_.load()) { Read(); }

    if (digest_) {
        std::string plaintext = ProtoAsString<proto::ServerContract>(data);
        std::string key;
        digest_(Storage::HASH_TYPE, plaintext, key);

        std::lock_guard<std::mutex> writeLock(write_lock_);
        bool savedCredential = Store(
            key,
            plaintext,
            current_bucket_.load());

        if (savedCredential) {
            if (config_.auto_publish_servers_ && config_.dht_callback_) {
                config_.dht_callback_(data.id(), plaintext);
            }
            return UpdateServers(data.id(), key);
        }
    }
    return false;
}

bool Storage::Store(const proto::CredentialIndex& data)
{
    if (!isLoaded_.load()) { Read(); }

    if (digest_) {
        std::string plaintext = ProtoAsString<proto::CredentialIndex>(data);
        std::string key;
        digest_(Storage::HASH_TYPE, plaintext, key);

        std::lock_guard<std::mutex> writeLock(write_lock_);
        bool saved = Store(
            key,
            plaintext,
            current_bucket_.load());

        if (saved) {
            if (config_.auto_publish_nyms_ && config_.dht_callback_) {
                config_.dht_callback_(data.nymid(), plaintext);
            }
            return UpdateNymCreds(data.nymid(), key);
        }
    }

    return false;
}

void Storage::CollectGarbage()
{
    bool oldLocation = current_bucket_.load();
    current_bucket_.store(!(current_bucket_.load()));

    std::shared_ptr<proto::StorageRoot> root;
    std::string gcroot, gcitems;
    bool updated = false;

    if (!gc_resume_.load()) {
        // Do not allow changes to root index object until we've updated it.
        std::unique_lock<std::mutex> writeLock(write_lock_);
        gcroot = root_hash_;

        if (!LoadProto<proto::StorageRoot>(root_hash_, root, true)) {
            // If there is no root object, then there's nothing to gc
            gc_running_.store(false);
            return;
        }
        gcitems = root->items();
        updated = UpdateRoot(*root, gcroot);
        writeLock.unlock();
    } else {
        gcroot = old_gc_root_;

        if (!LoadProto<proto::StorageRoot>(old_gc_root_, root)) {
            // If this branch is reached, the data store is corrupted
            abort();
        }
        gcitems = root->items();
        updated = true;
        gc_resume_.store(false);
    }

    if (!updated) {
        gc_running_.store(false);
        return;
    }
    MigrateKey(gcitems);
    std::shared_ptr<proto::StorageItems> items;

    if (!LoadProto<proto::StorageItems>(gcitems, items)) {
        gc_running_.store(false);
        return;
    }

    if (!items->creds().empty()) {
        MigrateKey(items->creds());
        std::shared_ptr<proto::StorageCredentials> creds;

        if (!LoadProto<proto::StorageCredentials>(items->creds(), creds)) {
            gc_running_.store(false);
            return;
        }

        for (auto& it : creds->cred()) {
            MigrateKey(it.hash());
        }
    }

    if (!items->nyms().empty()) {
        MigrateKey(items->nyms());
        std::shared_ptr<proto::StorageNymList> nyms;

        if (!LoadProto<proto::StorageNymList>(items->nyms(), nyms)) {
            gc_running_.store(false);
            return;
        }

        for (auto& it : nyms->nym()) {
            MigrateKey(it.hash());
            std::shared_ptr<proto::StorageNym> nym;

            if (!LoadProto<proto::StorageNym>(it.hash(), nym)) {
                gc_running_.store(false);
                return;
            }

            MigrateKey(nym->credlist().hash());
        }
    }

    if (!items->servers().empty()) {
        MigrateKey(items->servers());
        std::shared_ptr<proto::StorageServers> servers;

        if (!LoadProto<proto::StorageServers>(items->servers(), servers)) {
            gc_running_.store(false);
            return;
        }

        for (auto& it : servers->server()) {
            MigrateKey(it.hash());
        }
    }

    std::unique_lock<std::mutex> writeLock(write_lock_);
    UpdateRoot();
    writeLock.unlock();

    std::unique_lock<std::mutex> bucketLock(bucket_lock_);
    EmptyBucket(oldLocation);
    bucketLock.unlock();

    gc_running_.store(false);
}

bool Storage::MigrateKey(const std::string& key)
{
    std::string value;

    // try to load the key from the inactive bucket
    if (Load(key, value, !(current_bucket_.load()))) {

        // save to the active bucket
        if (Store(key, value, current_bucket_.load())) {
            return true;
        } else {
            return false;
        }
    }

    return true; // the key must have already been in the active bucket
}

void Storage::RunGC()
{
    if (!isLoaded_.load()) { return; }

    std::lock_guard<std::mutex> gclock(gc_lock_);
    std::time_t time = std::time(nullptr);
    const bool intervalExceeded =
        ((time - last_gc_) > gc_interval_);

    if (!gc_running_.load() && ( gc_resume_.load() || intervalExceeded)) {
        assert (!gc_running_.load());
        gc_running_.store(true);
        gc_thread_ = new std::thread(&Storage::CollectGarbage, this);
    }
}

void Storage::Storage::Cleanup_Storage()
{
    if ((nullptr != gc_thread_) && gc_thread_->joinable()) {
        gc_thread_->join();
        delete gc_thread_;
    }
}

void Storage::Storage::Cleanup()
{
    Cleanup_Storage();
}

Storage::~Storage()
{
    Cleanup_Storage();
}


} // namespace opentxs
