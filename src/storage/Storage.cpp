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

        if (!LoadProto(root_hash_, root)) { return; }

        items_ = root->items();
        current_bucket_.store(root->altlocation());
        last_gc_ = root->lastgc();
        gc_resume_.store(root->gc());
        old_gc_root_ = root->gcroot();

        std::shared_ptr<proto::StorageItems> items;

        if (!LoadProto(items_, items)) { return; }

        if (!items->creds().empty()) {
            std::shared_ptr<proto::StorageCredentials> creds;

            if (!LoadProto(items->creds(), creds)) {
                std::cerr << __FUNCTION__ << ": failed to load credential "
                          << "index item. Database is corrupt." << std::endl;
                std::cerr << "Hash of bad object: (" << items->creds()
                          << ")" << std::endl;
                std::abort();
            }

            for (auto& it : creds->cred()) {
                credentials_.insert({it.itemid(), {it.hash(), it.alias()}});
            }
        }

        if (!items->nyms().empty()) {
            std::shared_ptr<proto::StorageNymList> nyms;

            if (!LoadProto(items->nyms(), nyms)) {
                std::cerr << __FUNCTION__ << ": failed to load nym "
                << "index item. Database is corrupt." << std::endl;
                std::cerr << "Hash of bad object: (" << items->nyms()
                << ")" << std::endl;
                std::abort();
            }

            for (auto& it : nyms->nym()) {
                nyms_.insert({it.itemid(), {it.hash(), it.alias()}});
            }
        }

        if (!items->seeds().empty()) {
            std::shared_ptr<proto::StorageSeeds> seeds;

            if (!LoadProto(items->seeds(), seeds)) {
                std::cerr << __FUNCTION__ << ": failed to load seed "
                          << "index item. Database is corrupt." << std::endl;
                std::cerr << "Hash of bad object: (" << items->seeds()
                          << ")" << std::endl;
                std::abort();
            }

            default_seed_ = seeds->defaultseed();

            for (auto& it : seeds->seed()) {
                seeds_.insert({it.itemid(), {it.hash(), it.alias()}});
            }
        }

        if (!items->servers().empty()) {
            std::shared_ptr<proto::StorageServers> servers;

            if (!LoadProto(items->servers(), servers)) {
                std::cerr << __FUNCTION__ << ": failed to load server "
                          << "index item. Database is corrupt." << std::endl;
                std::cerr << "Hash of bad object: (" << items->servers()
                          << ")" << std::endl;
                std::abort();
            }

            for (auto& it : servers->server()) {
                servers_.insert({it.itemid(), {it.hash(), it.alias()}});
            }
        }

        if (!items->units().empty()) {
            std::shared_ptr<proto::StorageUnits> units;

            if (!LoadProto(items->units(), units)) {
                std::cerr << __FUNCTION__ << ": failed to load unit "
                          << "index item. Database is corrupt." << std::endl;
                std::cerr << "Hash of bad object: (" << items->units()
                          << ")" << std::endl;
                std::abort();
            }

            for (auto& it : units->unit()) {
                units_.insert({it.itemid(), {it.hash(), it.alias()}});
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

// Applies a lambda to all unit definitions in the database in a detached thread.
void Storage::MapUnitDefinitions(UnitLambda& lambda)
{
    std::thread bgMap(&Storage::RunMapUnits, this, lambda);
    bgMap.detach();
}

bool Storage::RemoveServer(const std::string& id)
{
    if (!isLoaded_.load()) { Read(); }

    std::lock_guard<std::mutex> writeLock(write_lock_);

    // Block reads while modifying server map
    std::unique_lock<std::mutex> serverlock(server_lock_);
    auto deleted = servers_.erase(id);

    if (0 != deleted) {
        return UpdateServers(serverlock);
    }

    return false;
}

bool Storage::RemoveUnitDefinition(const std::string& id)
{
    if (!isLoaded_.load()) { Read(); }

    std::lock_guard<std::mutex> writeLock(write_lock_);

    // Block reads while modifying unit map
    std::unique_lock<std::mutex> unitlock(unit_lock_);
    auto deleted = units_.erase(id);

    if (0 != deleted) {
        return UpdateUnits(unitlock);
    }

    return false;
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

    if (!LoadProto(items_, items)) {
        gc_lock_.unlock();
        return;
    }

    if (items->nyms().empty()) {
        gc_lock_.unlock();
        return;
    }

    std::shared_ptr<proto::StorageNymList> nyms;

    if (!LoadProto(items->nyms(), nyms)) {
        gc_lock_.unlock();
        return;
    }

    for (auto& it : nyms->nym()) {
        std::shared_ptr<proto::StorageNym> nymIndex;

        if (!LoadProto(it.hash(), nymIndex)) { continue; }

        std::shared_ptr<proto::CredentialIndex> nym;

        if (!LoadProto(nymIndex->credlist().hash(), nym))
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

    if (!LoadProto(items_, items)) {
        gc_lock_.unlock();
        return;
    }

    if (items->servers().empty()) {
        gc_lock_.unlock();
        return;
    }

    std::shared_ptr<proto::StorageServers> servers;

    if (!LoadProto(items->servers(), servers)) {
        gc_lock_.unlock();
        return;
    }

    for (auto& it : servers->server()) {
        std::shared_ptr<proto::ServerContract> server;

        if (!LoadProto(it.hash(), server))
            { continue; }

        lambda(*server);
    }

    gc_lock_.unlock();
}

void Storage::RunMapUnits(UnitLambda lambda)
{
    // std::unique_lock was failing to unlock the mutex even after Release()
    // was called. For now, lock and unlock mutexes directly instead of using
    // std::unique_lock and std::lock_guard

    gc_lock_.lock(); // block gc while iterating

    write_lock_.lock();
    std::string index = items_;
    write_lock_.unlock();

    std::shared_ptr<proto::StorageItems> items;

    if (!LoadProto(items_, items)) {
        gc_lock_.unlock();
        return;
    }

    if (items->units().empty()) {
        gc_lock_.unlock();
        return;
    }

    std::shared_ptr<proto::StorageUnits> units;

    if (!LoadProto(items->units(), units)) {
        gc_lock_.unlock();
        return;
    }

    for (auto& it : units->unit()) {
        std::shared_ptr<proto::UnitDefinition> unit;

        if (!LoadProto(it.hash(), unit))
            { continue; }

        lambda(*unit);
    }

    gc_lock_.unlock();
}

bool Storage::UpdateNymCreds(
    const std::string& id,
    const std::string& hash,
    const std::string& alias)
{
    // Reuse existing object, since it may contain more than just creds
    if (!id.empty() && !hash.empty()) {
        std::shared_ptr<proto::StorageNym> nym;

        if (!LoadProto(id, nym, true)) {
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

        if (!proto::Check(*nym, 0, 0xFFFFFFFF)) {
            abort();
        }

        if (StoreProto(*nym)) {
            return UpdateNym(*nym, alias);
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
        credentials_[id].first = hash;
        proto::StorageCredentials credIndex;
        credIndex.set_version(1);
        for (auto& cred : credentials_) {
            if (!cred.first.empty() && !cred.second.first.empty()) {
                proto::StorageItemHash* item = credIndex.add_cred();
                item->set_version(1);
                item->set_itemid(cred.first);
                item->set_hash(cred.second.first);
                item->set_alias(cred.second.second);
            }
        }
        cred_lock_.unlock();

        if (!proto::Check(credIndex, 0, 0xFFFFFFFF)) {
            abort();
        }

        if (StoreProto(credIndex)) {
            return UpdateItems(credIndex);
        }
    }

    return false;
}

bool Storage::UpdateNym(const proto::StorageNym& nym, const std::string& alias)
{
    // Do not test for existing object - we always regenerate from scratch
    if (digest_) {
        std::string id = nym.nymid();
        std::string plaintext = ProtoAsString<proto::StorageNym>(nym);
        std::string hash;
        digest_(Storage::HASH_TYPE, plaintext, hash);

        // Block reads while updating nym map
        std::unique_lock<std::mutex> nymLock(nym_lock_);
        std::string newAlias = alias;

        // If no alias was passed in, attempt to preserving existing alias
        if (alias.empty() && !nyms_[id].second.empty()) {
            newAlias = nyms_[id].second;
        }

        nyms_[id].first = hash;
        nyms_[id].second = newAlias;

        return UpdateNyms(nymLock);
    }

    return false;
}

bool Storage::UpdateNymAlias(const std::string& id, const std::string& alias)
{
    if (!id.empty() && !alias.empty()) {

        // Block reads while updating nym map
        std::unique_lock<std::mutex> nymLock(nym_lock_);
        nyms_[id].second = alias;

        return UpdateNyms(nymLock);
    }

    return false;
}

bool Storage::UpdateNyms(std::unique_lock<std::mutex>& nymLock)
{
    proto::StorageNymList nymIndex;
    nymIndex.set_version(1);
    for (auto& nym : nyms_) {
        if (!nym.first.empty() && !nym.second.first.empty()) {
            proto::StorageItemHash* item = nymIndex.add_nym();
            item->set_version(1);
            item->set_itemid(nym.first);
            item->set_hash(nym.second.first);
            item->set_alias(nym.second.second);
        }
    }
    nymLock.unlock();

    if (!proto::Check(nymIndex, 0, 0xFFFFFFFF)) {
        abort();
    }

    if (StoreProto(nymIndex)) {
        return UpdateItems(nymIndex);
    }

    return false;
}

bool Storage::UpdateSeed(
    const std::string& id,
    const std::string& hash,
    const std::string& alias)
{
    if (!id.empty() && !hash.empty()) {
        // Block reads while updating seed map
        std::unique_lock<std::mutex> seedLock(seed_lock_);

        std::string newAlias = alias;

        // If no alias was passed in, attempt to preserving existing alias
        if (alias.empty() && !seeds_[id].second.empty()) {
            newAlias = seeds_[id].second;
        }

        seeds_[id].first = hash;
        seeds_[id].second = newAlias;

        if (default_seed_.empty()) {
            default_seed_ = id;
        }

        return UpdateSeeds(seedLock);
    }

    return false;
}

bool Storage::UpdateSeedAlias(const std::string& id, const std::string& alias)
{
    if (!id.empty() && !alias.empty()) {

        // Block reads while updating seed map
        std::unique_lock<std::mutex> seedLock(seed_lock_);
        seeds_[id].second = alias;

        return UpdateSeeds(seedLock);
    }

    return false;
}

bool Storage::UpdateSeedDefault(const std::string& id)
{
    if (!id.empty()) {

        // Block reads while updating default seed
        std::unique_lock<std::mutex> seedLock(default_seed_lock_);
        default_seed_ = id;

        return UpdateSeeds(seedLock);
    }

    return false;
}

bool Storage::UpdateSeeds(std::unique_lock<std::mutex>& seedlock)
{
    proto::StorageSeeds seedIndex;
    seedIndex.set_version(1);
    seedIndex.set_defaultseed(default_seed_);

    for (auto& seed : seeds_) {
        if (!seed.first.empty() && !seed.second.first.empty()) {
            proto::StorageItemHash* item = seedIndex.add_seed();
            item->set_version(1);
            item->set_itemid(seed.first);
            item->set_hash(seed.second.first);
            item->set_alias(seed.second.second);
        }
    }
    seedlock.unlock();

    if (!proto::Check(seedIndex, 0, 0xFFFFFFFF)) {
        abort();
    }

    if (StoreProto(seedIndex)) {
        return UpdateItems(seedIndex);
    }

    return false;
}

bool Storage::UpdateServer(
    const std::string& id,
    const std::string& hash,
    const std::string& alias)
{
    if (!id.empty() && !hash.empty()) {

        // Block reads while updating server map
        std::unique_lock<std::mutex> serverlock(server_lock_);
        std::string newAlias = alias;

        // If no alias was passed in, attempt to preserving existing alias
        if (alias.empty() && !servers_[id].second.empty()) {
            newAlias = servers_[id].second;
        }

        servers_[id].first = hash;
        servers_[id].second = newAlias;

        return UpdateServers(serverlock);
    }

    return false;
}


bool Storage::UpdateServerAlias(const std::string& id, const std::string& alias)
{
    if (!id.empty() && !alias.empty()) {

        // Block reads while updating server map
        std::unique_lock<std::mutex> serverlock(server_lock_);
        servers_[id].second = alias;

        return UpdateServers(serverlock);
    }

    return false;
}

bool Storage::UpdateServers(std::unique_lock<std::mutex>& serverlock)
{
    proto::StorageServers serverIndex;
    serverIndex.set_version(1);
    for (auto& server : servers_) {
        if (!server.first.empty() && !server.second.first.empty()) {
            proto::StorageItemHash* item = serverIndex.add_server();
            item->set_version(1);
            item->set_itemid(server.first);
            item->set_hash(server.second.first);
            item->set_alias(server.second.second);
        }
    }
    serverlock.unlock();

    if (!proto::Check(serverIndex, 0, 0xFFFFFFFF)) {
        abort();
    }

    if (StoreProto(serverIndex)) {
        return UpdateItems(serverIndex);
    }

    return false;
}

bool Storage::UpdateUnit(
    const std::string& id,
    const std::string& hash,
    const std::string& alias)
{
    // Do not test for existing object - we always regenerate from scratch
    if (!id.empty() && !hash.empty()) {

        // Block reads while updating credential map
        std::unique_lock<std::mutex> unitlock(unit_lock_);
        std::string newAlias = alias;

        // If no alias was passed in, attempt to preserving existing alias
        if (alias.empty() && !units_[id].second.empty()) {
            newAlias = units_[id].second;
        }

        units_[id].first = hash;
        units_[id].second = newAlias;

        return UpdateUnits(unitlock);
    }

    return false;
}

bool Storage::UpdateUnitAlias(const std::string& id, const std::string& alias)
{
    if (!id.empty() && !alias.empty()) {

        // Block reads while updating unit map
        std::unique_lock<std::mutex> unitlock(unit_lock_);
        units_[id].second = alias;

        return UpdateUnits(unitlock);
    }

    return false;
}

bool Storage::UpdateUnits(std::unique_lock<std::mutex>& unitlock)
{
    proto::StorageUnits unitIndex;
    unitIndex.set_version(1);
    for (auto& unit : units_) {
        if (!unit.first.empty() && !unit.second.first.empty()) {
            proto::StorageItemHash* item = unitIndex.add_unit();
            item->set_version(1);
            item->set_itemid(unit.first);
            item->set_hash(unit.second.first);
            item->set_alias(unit.second.second);
        }
    }
    unitlock.unlock();

    if (!proto::Check(unitIndex, 0, 0xFFFFFFFF)) {
        abort();
    }

    if (StoreProto(unitIndex)) {
        return UpdateItems(unitIndex);
    }

    return false;
}


bool Storage::UpdateItems(const proto::StorageCredentials& creds)
{
    // Reuse existing object, since it may contain more than just creds
    std::shared_ptr<proto::StorageItems> items;

    if (!LoadProto(items_, items, true)) {
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

        if (!proto::Check(*items, 0, 0xFFFFFFFF)) {
            abort();
        }

        if (StoreProto(*items)) {
            return UpdateRoot(*items);
        }
    }

    return false;
}

bool Storage::UpdateItems(const proto::StorageNymList& nyms)
{
    // Reuse existing object, since it may contain more than just nyms
    std::shared_ptr<proto::StorageItems> items;

    if (!LoadProto(items_, items, true)) {
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

        if (!proto::Check(*items, 0, 0xFFFFFFFF)) {
            abort();
        }

        if (StoreProto(*items)) {
            return UpdateRoot(*items);
        }
    }

    return false;
}

bool Storage::UpdateItems(const proto::StorageSeeds& seeds)
{
    // Reuse existing object, since it may contain more than just seeds
    std::shared_ptr<proto::StorageItems> items;

    if (!LoadProto(items_, items, true)) {
        items = std::make_shared<proto::StorageItems>();
        items->set_version(1);
    } else {
        items->clear_seeds();
    }

    if (digest_) {
        std::string plaintext = ProtoAsString(seeds);
        std::string hash;
        digest_(Storage::HASH_TYPE, plaintext, hash);

        items->set_seeds(hash);

        if (!proto::Check(*items, 0, 0xFFFFFFFF)) {
            abort();
        }

        if (StoreProto(*items)) {
            return UpdateRoot(*items);
        }
    }

    return false;
}

bool Storage::UpdateItems(const proto::StorageServers& servers)
{
    // Reuse existing object, since it may contain more than just servers
    std::shared_ptr<proto::StorageItems> items;

    if (!LoadProto(items_, items, true)) {
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

        if (!proto::Check(*items, 0, 0xFFFFFFFF)) {
            abort();
        }

        if (StoreProto(*items)) {
            return UpdateRoot(*items);
        }
    }

    return false;
}

bool Storage::UpdateItems(const proto::StorageUnits& units)
{
    // Reuse existing object, since it may contain more than just units
    std::shared_ptr<proto::StorageItems> items;

    if (!LoadProto(items_, items, true)) {
        items = std::make_shared<proto::StorageItems>();
        items->set_version(1);
    } else {
        items->clear_units();
    }

    if (digest_) {
        std::string plaintext = ProtoAsString<proto::StorageUnits>(units);
        std::string hash;
        digest_(Storage::HASH_TYPE, plaintext, hash);

        items->set_units(hash);

        if (!proto::Check(*items, 0, 0xFFFFFFFF)) {
            abort();
        }

        if (StoreProto(*items)) {
            return UpdateRoot(*items);
        }
    }

    return false;
}

bool Storage::UpdateRoot(const proto::StorageItems& items)
{
    // Reuse existing object to preserve current settings
    std::shared_ptr<proto::StorageRoot> root;

    if (!LoadProto(root_hash_, root, true)) {
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

        if (!proto::Check(*root, 0, 0xFFFFFFFF)) {
            abort();
        }

        if (StoreProto(*root)) {
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

        if (!proto::Check(root, 0, 0xFFFFFFFF)) {
            abort();
        }

        if (StoreProto(root)) {
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

    bool loaded = LoadProto(root_hash_, root);

    assert(loaded);

    if (loaded && digest_) {
        gc_running_.store(false);
        root->set_gc(false);

        if (!proto::Check(*root, 0, 0xFFFFFFFF)) {
            abort();
        }

        if (StoreProto(*root)) {
            std::string hash;
            std::string plaintext = ProtoAsString<proto::StorageRoot>(*root);
            digest_(Storage::HASH_TYPE, plaintext, hash);

            root_hash_ = hash;

            return StoreRoot(hash);
        }
    }

    return false;
}

std::string Storage::DefaultSeed()
{
    if (!isLoaded_.load()) { Read(); }

    // block writes to default_seed_
    std::lock_guard<std::mutex> seedLock(default_seed_lock_);

    return default_seed_;
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
        hash = it->second.first;
    }
    cred_lock_.unlock();

    if (found) {
        return LoadProto(hash, cred, checking);
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
    std::shared_ptr<proto::CredentialIndex>& nym,
    const bool checking)
{
    std::string notUsed;

    return Load(id, nym, notUsed, checking);
}

bool Storage::Load(
    const std::string& id,
    std::shared_ptr<proto::CredentialIndex>& nym,
    std::string& alias,
    const bool checking)
{
    if (!isLoaded_.load()) { Read(); }

    bool found = false;
    std::string hash;

    // block writes while searching nym map
    std::unique_lock<std::mutex> nymLock(nym_lock_);
    auto it = nyms_.find(id);
    if (it != nyms_.end()) {
        found = true;
        hash = it->second.first;
        alias = it->second.second;
    }
    nymLock.unlock();

    if (found) {
        std::shared_ptr<proto::StorageNym> nymIndex;

        if (LoadProto(hash, nymIndex, checking)) {
            std::string credListHash = nymIndex->credlist().hash();

            if (LoadProto<proto::CredentialIndex>
                (credListHash, nym, checking)) {

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

bool Storage::Load(
    const std::string& id,
    std::shared_ptr<proto::Seed>& seed,
    const bool checking)
{
    std::string notUsed;

    return Load(id, seed, notUsed, checking);
}

bool Storage::Load(
    const std::string& id,
    std::shared_ptr<proto::Seed>& seed,
    std::string& alias,
    const bool checking)
{
    if (!isLoaded_.load()) { Read(); }

    bool found = false;
    std::string hash;

    // block writes while searching seed map
    std::unique_lock<std::mutex> seedLock(seed_lock_);

    auto it = seeds_.find(id);
    if (it != seeds_.end()) {
        found = true;
        hash = it->second.first;
        alias = it->second.second;
    }
    seedLock.unlock();

    if (found) {
        return LoadProto(hash, seed, checking);
    }

    if (!checking) {
        std::cout << __FUNCTION__ << ": Error: seed with id " << id
        << " does not exist in the map of stored seeds."
        << std::endl;
    }

    return false;
}


bool Storage::Load(
    const std::string& id,
    std::shared_ptr<proto::ServerContract>& contract,
    const bool checking)
{
    std::string notUsed;

    return Load(id, contract, notUsed, checking);
}

bool Storage::Load(
    const std::string& id,
    std::shared_ptr<proto::ServerContract>& contract,
    std::string& alias,
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
        hash = it->second.first;
        alias = it->second.second;
    }
    serverLock.unlock();

    if (found) {
        return LoadProto(hash, contract, checking);
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
    std::shared_ptr<proto::UnitDefinition>& contract,
    const bool checking)
{
    std::string notUsed;

    return Load(id, contract, notUsed, checking);
}

bool Storage::Load(
    const std::string& id,
    std::shared_ptr<proto::UnitDefinition>& contract,
    std::string& alias,
    const bool checking)
{
    if (!isLoaded_.load()) { Read(); }

    bool found = false;
    std::string hash;

    // block writes while searching unit definition map
    std::unique_lock<std::mutex> unitLock(unit_lock_);
    auto it = units_.find(id);
    if (it != units_.end()) {
        found = true;
        hash = it->second.first;
        alias = it->second.second;
    }
    unitLock.unlock();

    if (found) {
        return LoadProto(hash, contract, checking);
    }

    if (!checking) {
        std::cout << __FUNCTION__ << ": Error: unit definition with id " << id
        << " does not exist in the map of stored definitions."
        << std::endl;
    }

    return false;
}

bool Storage::SetDefaultSeed(const std::string& id)
{
    if (!isLoaded_.load()) { Read(); }

    // block writes while searching seed map
    std::lock_guard<std::mutex> writeLock(write_lock_);

    // do not set the default seed to an id that's not present in the map
    bool found = (seeds_.find(id) != seeds_.end());

    if (found) {

        return UpdateSeedDefault(id);
    }

    return false;
}

bool Storage::SetNymAlias(const std::string& id, const std::string& alias)
{
    if (!isLoaded_.load()) { Read(); }

    // block writes while searching nym map
    std::lock_guard<std::mutex> writeLock(write_lock_);

    bool found = (nyms_.find(id) != nyms_.end());

    if (found) {

        return UpdateNymAlias(id, alias);
    }

    return false;
}

bool Storage::SetSeedAlias(const std::string& id, const std::string& alias)
{
    if (!isLoaded_.load()) { Read(); }

    // block writes while searching seed map
    std::lock_guard<std::mutex> writeLock(write_lock_);

    bool found = (seeds_.find(id) != seeds_.end());

    if (found) {

        return UpdateSeedAlias(id, alias);
    }

    return false;
}

bool Storage::SetServerAlias(const std::string& id, const std::string& alias)
{
    if (!isLoaded_.load()) { Read(); }

    // block writes while searching server map
    std::lock_guard<std::mutex> writeLock(write_lock_);

    bool found = (servers_.find(id) != servers_.end());

    if (found) {

        return UpdateServerAlias(id, alias);
    }

    return false;
}

bool Storage::SetUnitDefinitionAlias(
    const std::string& id,
    const std::string& alias)
{
    if (!isLoaded_.load()) { Read(); }

    // block writes while searching server map
    std::lock_guard<std::mutex> writeLock(write_lock_);

    bool found = (units_.find(id) != units_.end());

    if (found) {

        return UpdateUnitAlias(id, alias);
    }

    return false;
}

std::string Storage::ServerAlias(const std::string& id)
{
    if (!isLoaded_.load()) { Read(); }

    // block writes while searching server map
    std::lock_guard<std::mutex> serverLock(server_lock_);
    bool found = (servers_.find(id) != servers_.end());

    if (!found) { return ""; }

    return servers_[id].second;
}

Storage::ObjectList Storage::ServerList()
{
    if (!isLoaded_.load()) { Read(); }

    Storage::ObjectList servers;
    // block writes while iterating the server map
    std::unique_lock<std::mutex> serverLock(server_lock_);
    for (auto& server : servers_) {
        servers.push_back({server.first, server.second.second});
    }
    serverLock.unlock();

    return servers;
}

bool Storage::Store(const proto::Credential& data)
{
    if (!isLoaded_.load()) { Read(); }

    // Avoid overwriting private credentials with public credentials
    bool existingPrivate = false;
    std::shared_ptr<proto::Credential> existing;
    const std::string& id = data.id();

    if (Load(id, existing, true)) { // suppress "not found" error
        existingPrivate = (proto::KEYMODE_PRIVATE == existing->mode());
    }

    if (existingPrivate && (proto::KEYMODE_PRIVATE != data.mode())) {
        std::cout << "Skipping update of existing private credential with "
                  << "non-private version." << std::endl;

        return true;
    }

    std::string key;
    std::lock_guard<std::mutex> writeLock(write_lock_);

    if (StoreProto(data, key)) {

        return UpdateCredentials(id, key);
    }

    return false;
}

bool Storage::Store(const proto::CredentialIndex& data, const std::string alias)
{
    if (!isLoaded_.load()) { Read(); }

    // Avoid overwriting a newer version with an older version
    bool haveNewerVerion = false;
    std::shared_ptr<proto::CredentialIndex> existing;
    const std::string& id = data.nymid();

    if (Load(id, existing, true)) { // suppress "not found" error
        haveNewerVerion = (existing->revision() >= data.revision());
    }

    if (haveNewerVerion) {
        std::cout << "Skipping overwrite of existing nym with "
                  << "older revision." << std::endl
                  << "Existing revision: " << existing->revision() << std::endl
                  << "Provided revision: " << data.revision() << std::endl;

        return true;
    }

    std::string key, plaintext;
    std::lock_guard<std::mutex> writeLock(write_lock_);

    if (StoreProto(data, key, plaintext)) {
        if (config_.auto_publish_nyms_ && config_.dht_callback_) {
            config_.dht_callback_(id, plaintext);
        }

        return UpdateNymCreds(id, key, alias);
    }

    return false;
}

bool Storage::Store(const proto::Seed& data, const std::string alias)
{
    if (!isLoaded_.load()) { Read(); }
    const std::string& id = data.fingerprint();

    std::string key;
    std::lock_guard<std::mutex> writeLock(write_lock_);

    if (StoreProto(data, key)) {

        return UpdateSeed(id, key, alias);
    }

    return false;
}

bool Storage::Store(const proto::ServerContract& data, const std::string alias)
{
    if (!isLoaded_.load()) { Read(); }

    auto storageVersion(data);
    storageVersion.clear_publicnym();
    const std::string& id = storageVersion.id();

    if (!proto::Check(storageVersion, 0, 0xFFFFFFFF)) { return false; }

    std::string key, plaintext;
    std::lock_guard<std::mutex> writeLock(write_lock_);

    if (StoreProto(data, key, plaintext)) {
        if (config_.auto_publish_servers_ && config_.dht_callback_) {
            config_.dht_callback_(id, plaintext);
        }

        return UpdateServer(id, key, alias);
    }

    return false;
}

bool Storage::Store(const proto::UnitDefinition& data, const std::string alias)
{
    if (!isLoaded_.load()) { Read(); }

    auto storageVersion(data);
    storageVersion.clear_publicnym();
    const std::string& id = storageVersion.id();

    if (!proto::Check(storageVersion, 0, 0xFFFFFFFF)) { return false; }

    std::string key, plaintext;
    std::lock_guard<std::mutex> writeLock(write_lock_);

    if (StoreProto(data, key)) {
        if (config_.auto_publish_units_ && config_.dht_callback_) {
            config_.dht_callback_(id, plaintext);
        }

        return UpdateUnit(id, key, alias);
    }

    return false;
}

std::string Storage::UnitDefinitionAlias(const std::string& id)
{
    if (!isLoaded_.load()) { Read(); }

    // block writes while searching unit map
    std::lock_guard<std::mutex> unitLock(unit_lock_);
    bool found = (units_.find(id) != units_.end());

    if (!found) { return ""; }

    return units_[id].second;
}

Storage::ObjectList Storage::UnitDefinitionList()
{
    if (!isLoaded_.load()) { Read(); }

    Storage::ObjectList units;
    // block writes while iterating the unit map
    std::unique_lock<std::mutex> unitLock(unit_lock_);
    for (auto& unit : units_) {
        units.push_back({unit.first, unit.second.second});
    }
    unitLock.unlock();

    return units;
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

        if (!LoadProto(root_hash_, root, true)) {
            // If there is no root object, then there's nothing to gc
            gc_running_.store(false);
            return;
        }
        gcitems = root->items();
        updated = UpdateRoot(*root, gcroot);
        writeLock.unlock();
    } else {
        gcroot = old_gc_root_;

        if (!LoadProto(old_gc_root_, root)) {
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

    if (!LoadProto(gcitems, items)) {
        gc_running_.store(false);
        return;
    }

    if (!items->creds().empty()) {
        MigrateKey(items->creds());
        std::shared_ptr<proto::StorageCredentials> creds;

        if (!LoadProto(items->creds(), creds)) {
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

        if (!LoadProto(items->nyms(), nyms)) {
            gc_running_.store(false);
            return;
        }

        for (auto& it : nyms->nym()) {
            MigrateKey(it.hash());
            std::shared_ptr<proto::StorageNym> nym;

            if (!LoadProto(it.hash(), nym)) {
                gc_running_.store(false);
                return;
            }

            MigrateKey(nym->credlist().hash());
        }
    }

    if (!items->seeds().empty()) {
        MigrateKey(items->seeds());
        std::shared_ptr<proto::StorageSeeds> seeds;

        if (!LoadProto(items->seeds(), seeds)) {
            gc_running_.store(false);
            return;
        }

        for (auto& it : seeds->seed()) {
            MigrateKey(it.hash());
        }
    }

    if (!items->servers().empty()) {
        MigrateKey(items->servers());
        std::shared_ptr<proto::StorageServers> servers;

        if (!LoadProto(items->servers(), servers)) {
            gc_running_.store(false);
            return;
        }

        for (auto& it : servers->server()) {
            MigrateKey(it.hash());
        }
    }

    if (!items->units().empty()) {
        MigrateKey(items->units());
        std::shared_ptr<proto::StorageUnits> units;

        if (!LoadProto(items->units(), units)) {
            gc_running_.store(false);
            return;
        }

        for (auto& it : units->unit()) {
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
