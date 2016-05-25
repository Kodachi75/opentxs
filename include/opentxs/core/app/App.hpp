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

/**\defgroup native Native API
 *
 */

#ifndef OPENTXS_CORE_APP_APP_HPP
#define OPENTXS_CORE_APP_APP_HPP

#include <opentxs/storage/Storage.hpp>
#include <opentxs/core/app/Dht.hpp>
#include <opentxs/core/app/Identity.hpp>
#include <opentxs/core/app/Settings.hpp>
#include <opentxs/core/app/Wallet.hpp>
#include <opentxs/core/crypto/CryptoEngine.hpp>

#include <atomic>
#include <chrono>
#include <functional>
#include <limits>
#include <list>
#include <memory>
#include <thread>
#include <tuple>

namespace opentxs
{

//
/** \brief Singlton class for providing an interface to process-level resources.
 *  \ingroup native
 */
class App
{
public:
    typedef std::function<void()> PeriodicTask;

private:
    // Last performed, Interval, Task
    typedef std::tuple<time64_t, time64_t, PeriodicTask> TaskItem;
    typedef std::list<TaskItem> TaskList;

    static App* instance_pointer_;

    Settings* config_ = nullptr;
    CryptoEngine* crypto_ = nullptr;
    Dht* dht_ = nullptr;
    Storage* storage_ = nullptr;
    std::unique_ptr<Wallet> contract_manager_;
    std::unique_ptr<class Identity> identity_;

    std::mutex task_list_lock_;

    bool server_mode_ = false;
    std::atomic<bool> shutdown_;
    TaskList periodic_task_list;
    int64_t nym_publish_interval_ = std::numeric_limits<int64_t>::max();
    int64_t nym_refresh_interval_ = std::numeric_limits<int64_t>::max();
    int64_t server_publish_interval_ = std::numeric_limits<int64_t>::max();
    int64_t server_refresh_interval_ = std::numeric_limits<int64_t>::max();
    int64_t unit_publish_interval_ = std::numeric_limits<int64_t>::max();
    int64_t unit_refresh_interval_ = std::numeric_limits<int64_t>::max();

    App(const bool serverMode);
    App() = delete;
    App(const App&) = delete;
    App& operator=(const App&) = delete;

    void Periodic();

    void Init_Config();
    void Init_Contracts();
    void Init_Crypto();
    void Init_Dht();
    void Init_Identity();
    void Init_Periodic();
    void Init_Storage();
    void Init();

public:
    static App& Me(const bool serverMode = false);

    Settings& Config();
    Wallet& Contract();
    CryptoEngine& Crypto();
    Storage& DB();
    Dht& DHT();
    class Identity& Identity();

    // Adds a task to the periodic task list with the specified interval.
    // By default, schedules for immediate execution.
    void Schedule(
        const time64_t& interval,
        const PeriodicTask& task,
        const time64_t& last = 0);

    void Cleanup();
    ~App();
};

}  // namespace opentxs
#endif // OPENTXS_CORE_APP_APP_HPP
