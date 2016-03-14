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

#ifndef OPENTXS_CLIENT_OTWALLET_HPP
#define OPENTXS_CLIENT_OTWALLET_HPP

#include <opentxs/core/String.hpp>
#include <opentxs/core/crypto/NymParameters.hpp>

#include <map>
#include <memory>
#include <set>
#include <string>

namespace opentxs
{

class Account;
class UnitDefinition;
class Contract;
class Identifier;
class Message;
class OTPassword;
class OTPasswordData;
class Nym;
class Purse;
class String;
class OTSymmetricKey;

typedef std::map<std::string, Account*> mapOfAccounts;
typedef std::map<std::string, Nym*> mapOfNyms;
typedef std::map<std::string, std::shared_ptr<OTSymmetricKey>>
    mapOfSymmetricKeys;
typedef std::set<Identifier> setOfIdentifiers;

class OTWallet
{
public:
    EXPORT OTWallet();
    ~OTWallet();

    EXPORT bool IsNymOnCachedKey(const Identifier& needle) const; // needle
                                                                  // and
                                                                  // haystack.
    EXPORT bool ConvertNymToCachedKey(Nym& theNym);

    EXPORT Nym* GetOrLoadPrivateNym(
        const Identifier& NYM_ID, bool bChecking = false,
        const char* szFuncName = nullptr,
        const OTPasswordData* pPWData = nullptr,
        const OTPassword* pImportPassword = nullptr);

    EXPORT Nym* reloadAndGetPrivateNym(
        const Identifier& NYM_ID, bool bChecking = false,
        const char* szFuncName = nullptr,
        const OTPasswordData* pPWData = nullptr,
        const OTPassword* pImportPassword = nullptr);

    EXPORT Account* LoadAccount(const Nym& theNym, const Identifier& ACCT_ID,
                                const Identifier& NOTARY_ID,
                                const char* szFuncName = nullptr);

    EXPORT Account* GetOrLoadAccount(const Nym& theNym,
                                     const Identifier& ACCT_ID,
                                     const Identifier& NOTARY_ID,
                                     const char* szFuncName = nullptr);
    // Used by high-level wrapper.

    EXPORT int32_t GetNymCount();
    EXPORT int32_t GetAccountCount();
    EXPORT Nym * CreateNym(const NymParameters& nymParameters);
    EXPORT bool GetNym(int32_t iIndex, Identifier& NYM_ID, String& NYM_NAME);
    EXPORT bool GetAccount(int32_t iIndex, Identifier& THE_ID,
                           String& THE_NAME);

    EXPORT void DisplayStatistics(String& strOutput);

    EXPORT Nym* GetPrivateNymByID(const Identifier& NYM_ID);
    EXPORT Nym* GetNymByIDPartialMatch(std::string PARTIAL_ID); // wallet name
                                                                // for nym also
                                                                // accepted.
    EXPORT void AddPrivateNym(const Nym& theNym);
    EXPORT void AddAccount(const Account& theAcct);

    bool VerifyAssetAccount(const Nym& theNym, Account& theAcct,
                            const Identifier& NOTARY_ID,
                            const String& strAcctID,
                            const char* szFuncName = nullptr);
    EXPORT Account* GetAccount(const Identifier& theAccountID);
    EXPORT Account* GetAccountPartialMatch(std::string PARTIAL_ID); // wallet
                                                                    // name for
                                                                    // account
                                                                    // also
                                                                    // accepted.
    EXPORT Account* GetIssuerAccount(
        const Identifier& theInstrumentDefinitionID);
    // While waiting on server response to a withdrawal, we keep the private
    // coin
    // data here so we can unblind the response.
    // This information is so important (as important as the digital cash token
    // itself, until the unblinding is done) that we need to save the file right
    // away.
    EXPORT void AddPendingWithdrawal(const Purse& thePurse);
    void RemovePendingWithdrawal();
    inline Purse* GetPendingWithdrawal() const
    {
        return m_pWithdrawalPurse;
    }
    EXPORT bool LoadWallet(const char* szFilename = nullptr);
    EXPORT bool SaveWallet(const char* szFilename = nullptr);
    bool SaveContract(String& strContract); // For saving the wallet to a
                                            // string.

    EXPORT bool SignContractWithFirstNymOnList(
        Contract& theContract); // todo : follow-up on this and see what it's
                                // about.
    // When the wallet's master passphrase changes, the extra symmetric keys
    // need to be updated to reflect that.
    EXPORT bool ChangePassphrasesOnExtraKeys(const OTPassword& oldPassphrase,
                                             const OTPassword& newPassphrase);
    // These allow the client application to encrypt its own sensitive data.
    // For example, let's say the client application is storing your Bitmessage
    // username and password in its database. It can't store those in the clear,
    // so it encrypts the DB's sensitive data using Encrypt_ByKeyID("sql_db")
    // and accesses the data using Decrypt_ByKeyID("sql_db").
    // The string acts as a key to look up a symmetric key which is normally
    // stored in encrypted form, using the wallet's master key. Whenever the
    // wallet's master key is available (until it times out) the client app will
    // thus be able to use these symmetric keys without having to ask the user
    // to type a passphrase.
    // (We do this for Nyms already. These methods basically give us the same
    // functionality for symmetric keys as we already had for the wallet's
    // Nyms.)
    //
    EXPORT bool Encrypt_ByKeyID(const std::string& key_id,
                                const String& strPlaintext, String& strOutput,
                                const String* pstrDisplay = nullptr,
                                bool bBookends = true);

    EXPORT bool Decrypt_ByKeyID(const std::string& key_id,
                                const String& strCiphertext, String& strOutput,
                                const String* pstrDisplay = nullptr);

    EXPORT std::shared_ptr<OTSymmetricKey> getOrCreateExtraKey(
        const std::string& str_KeyID,
        const std::string* pReason = nullptr); // Use this one.

    EXPORT std::shared_ptr<OTSymmetricKey> getExtraKey(
        const std::string& str_id) const; // Low level.

    EXPORT bool addExtraKey(const std::string& str_id,
                            std::shared_ptr<OTSymmetricKey> pKey); // Low level.
    // These functions are low-level. They don't check for dependent data before
    // deleting,
    // and they don't save the wallet after they do.
    //
    // (You have to handle that at a higher level.)
    // higher level version of these two will require a server message,
    // in addition to removing from wallet. (To delete them on server side.)
    //
    EXPORT bool RemoveAccount(const Identifier& theTargetID);
    EXPORT bool RemovePrivateNym(const Identifier& theTargetID,
                                 bool bRemoveFromCachedKey=true,
                                 String * pStrOutputName=nullptr);
    EXPORT std::string GetHDWordlist() const;

private:
    void AddNym(const Nym& theNym, mapOfNyms& map);
    bool RemoveNym(const Identifier& theTargetID, mapOfNyms& map,
                   bool bRemoveFromCachedKey=true,
                   String * pStrOutputName=nullptr);
    void Release();

private:
    mapOfNyms m_mapPrivateNyms;
    mapOfAccounts m_mapAccounts;

    setOfIdentifiers m_setNymsOnCachedKey; // All the Nyms that use the Master
                                           // key are listed here (makes it easy
                                           // to see which ones are converted
                                           // already.)

    String m_strName;
    String m_strVersion;

    // Let's say you have some private data that you want to store safely.
    // For example, your Bitmessage user/pass. Perhaps you want to throw
    // your Bitmessage connect string into your client-side sql*lite DB.
    // But you can't leave the password there in plaintext form! So instead,
    // you create a symmetric key to encrypt it with (stored here on this
    // map.)
    // Therefore your data, such as your Bitmessage password, is stored in
    // encrypted form to a symmetric key stored in the wallet. Then that
    // symmetric key is encrypted to the master password in the wallet.
    // If the master password ever changes, the symmetric keys on this map
    // can be re-encrypted to the new master password. Meanwhile the Bitmessage
    // connection string ITSELF, in your sql*lite DB, doesn't need to be re-
    // encrypted at all, since it's encrypted to the symmetric key, which,
    // though itself may be re-encrypted to another master password, the actual
    // contents of the symmetric key haven't changed.
    //
    // (This way you can change the wallet master passphrase, WITHOUT having
    // to go through your sql*lite database re-encrypting all the crap in there
    // that you might have encrypted previously before you changed your wallet
    // password.)
    //
    // That's why these are "extra" keys -- because you can create as many of
    // them as you want, and just use them for encrypting various data on the
    // client side.
    //
    mapOfSymmetricKeys m_mapExtraKeys;

    // While waiting on server response to withdrawal,
    // store private coin data here for unblinding
    Purse* m_pWithdrawalPurse;
    uint32_t next_hd_key_ = 0;

public:
    inline uint32_t NextHDSeed() const {
        return next_hd_key_;
    }

    String m_strFilename;
    String m_strDataFolder;
};

} // namespace opentxs

#endif // OPENTXS_CLIENT_OTWALLET_HPP
