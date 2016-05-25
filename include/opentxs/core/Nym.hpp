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

#ifndef OPENTXS_CORE_OTPSEUDONYM_HPP
#define OPENTXS_CORE_OTPSEUDONYM_HPP

#include <deque>
#include <map>
#include <list>
#include <set>
#include <memory>

#include <czmq.h>
#include <opentxs-proto/verify/VerifyContracts.hpp>

#include <opentxs/core/crypto/NymParameters.hpp>
#include <opentxs/core/NymIDSource.hpp>
#include "crypto/OTASCIIArmor.hpp"
#include "Identifier.hpp"
#include "Types.hpp"

namespace opentxs
{

class OTAsymmetricKey;
class CredentialSet;
class Item;
class OTKeypair;
class Ledger;
class Message;
class OTPassword;
class OTPasswordData;
class ServerContract;
class Credential;
class OTTransaction;
class Tag;
class Wallet;

typedef std::deque<Message*> dequeOfMail;
typedef std::map<std::string, int64_t> mapOfRequestNums;
typedef std::map<std::string, int64_t> mapOfHighestNums;
typedef std::deque<int64_t> dequeOfTransNums;
typedef std::map<std::string, dequeOfTransNums*> mapOfTransNums;
typedef std::map<std::string, Identifier> mapOfIdentifiers;
typedef std::map<std::string, CredentialSet*> mapOfCredentialSets;
typedef std::list<OTAsymmetricKey*> listOfAsymmetricKeys;
typedef proto::CredentialIndex serializedCredentialIndex;
typedef bool CredentialIndexModeFlag;

class Nym
{
    friend class Wallet;
public:
    static const CredentialIndexModeFlag ONLY_IDS = true;
    static const CredentialIndexModeFlag FULL_CREDS = false;
    Nym(const Nym&) = default;
private:
    std::string alias_;
    uint32_t credential_index_version_ = 0;
    uint64_t credential_index_revision_ = 0;
    Nym& operator=(const Nym&);

    bool m_bPrivate = false;
    bool m_bMarkForDeletion; // Default FALSE. When set to true, saves a
                             // "DELETED" flag with this Nym,
    // for easy cleanup later when the server is doing some maintenance.
    String m_strNymfile; // This contains the request numbers and other user
                         // acct info. XML.
    String m_strVersion;    // This goes with the Nymfile
    std::shared_ptr<NymIDSource> source_; // Hash this to form the NymID. Can
                                          // be a
                                // public key, or a URL, or DN info from a
                                // cert, etc.
    String m_strDescription;
    Identifier m_nymID; // Hashed-ID formed by hashing the Nym's public key.
    Identifier m_NymboxHash; // (Server-side) Hash of the Nymbox

    mapOfIdentifiers m_mapNymboxHash; // (Client-side) Hash of latest DOWNLOADED
                                      // Nymbox (OTIdentifier) mapped by
                                      // NotaryID (std::string)
    mapOfIdentifiers m_mapRecentHash; // (Client-side) Hash of Nymbox according
                                      // to Server, based on some recent reply.
                                      // (May be newer...)
    mapOfIdentifiers m_mapInboxHash;  // Whenever client downloads Inbox, its
                                      // hash is stored here. (When downloading
                                      // account, can compare ITS inbox hash to
                                      // this one, to see if I already have
                                      // latest one.)
    mapOfIdentifiers m_mapOutboxHash; // Whenever client downloads Outbox, its
                                      // hash is stored here. (When downloading
                                      // account, can compare ITS outbox hash to
                                      // this one, to see if I already have
                                      // latest one.)
    // NOTE: these dequeOfMail objects are only currently stored in the Nym for
    // convenience.
    // They don't have to be stored in here.
    //
    dequeOfMail m_dequeMail; // Any mail messages received by this Nym. (And not
                             // yet deleted.)
    dequeOfMail m_dequeOutmail; // Any mail messages sent by this Nym. (And not
                                // yet deleted.)
    dequeOfMail m_dequeOutpayments; // Any outoing payments sent by this Nym.
                                    // (And not yet deleted.) (payments screen.)
    mapOfRequestNums m_mapRequestNum; // Whenever this user makes a request to a
                                      // transaction server
    // he must use the latest request number. Each user has a request
    // number for EACH transaction server he accesses.

    mapOfTransNums m_mapTransNum; // Each Transaction Request must be
                                  // accompanied by a fresh transaction #,
    // one that has previously been issued to the Nym by the Server. This list
    // is used so that I know WHICH transaction numbers I still have to USE.

    mapOfTransNums m_mapIssuedNum; // If the server has issued me (1,2,3,4,5)
                                   // and I have already used 1-3,
    // then (4,5) are the only remaining numbers on the ABOVE list, but the
    // entire (1,2,3,4,5) are still on THIS list--each only to be removed
    // when I have ACCEPTED THE RECEIPT IN MY NYMBOX FOR EACH ONE. This list
    // is so I can do agreements with the server concerning which RECEIPTS I'VE
    // ACCEPTED.

    // When I accept a transaction number, I put it on this list. Then when I
    // receive the server reply, I add the # to the
    // actual lists (m_maps TransNum and IssuedNum) and remove it from this
    // list. If it's NOT on this list when I receive
    // the server reply, then the server is trying to trick me! into accepting a
    // number I never asked to sign for. The real
    // reason I added this member was so the server could drop notices into my
    // Nymbox about these new transaction numbers
    // (for cases where the actual network message was lost, the server reply, I
    // realized a good backup plan is to have the
    // server always drop notices into your nymbox as well, so you won't get out
    // of sync, since the notice is there even if
    // the network fails before you get the server's reply.) I think this is
    // also a GREAT backup plan for withdrawing CASH.
    //
    mapOfTransNums m_mapTentativeNum;
    // We store the highest transaction number accepted for any given server,
    // and we refuse, in the future, to accept anything lower.
    // This prevents a sneaky server from sending you an old number, getting you
    // to sign it out again, then then using that to run
    // through an old instrument (such as a cheque) that still has your old
    // (valid) signature on it.
    //
    mapOfHighestNums m_mapHighTransNo; // Mapped, a single int64_t to each
                                       // server (just like request numbers
                                       // are.)
    // Although it says "mapOfTransNums", in this case, request numbers are
    // stored. I used mapOfTransNums and its associated
    // generic manipulation functions, since they already existed. The
    // AcknowledgedNums are for optimization only, as they enable
    // us to avoid downloading many Box Receipts we'd other have to download.
    // (Specifically, replyNotices, which are referenced
    // by their request number.)
    //
    mapOfTransNums m_mapAcknowledgedNum;
    // (SERVER side)
    std::set<int64_t> m_setOpenCronItems; // Until these Cron Items are closed
                                          // out, the server-side Nym keeps a
                                          // list of them handy.

    // (SERVER side)
    // Using strings here to avoid juggling memory crap.
    std::set<std::string> m_setAccounts; // A list of asset account IDs. Server
                                         // side only (client side uses wallet;
                                         // has multiple servers.)
    // (SERVER side.)
    int64_t m_lUsageCredits; // Server-side. The usage credits available for
                             // this Nym. Infinite if negative.
    mapOfCredentialSets m_mapCredentialSets; // The credentials for this Nym.
                                             // (Each with a master key
                                             // credential and various
                                             // child credentials.)
    mapOfCredentialSets m_mapRevokedSets; // We keep track of old master
                                          // credentials after they are revoked.
    String::List m_listRevokedIDs; // std::string list, any revoked Credential
                                   // IDs. (Mainly for child credentials)
public:
    EXPORT std::string Alias() const { return alias_; }
    EXPORT void SetAlias(const std::string& alias) { alias_ = alias; }
    EXPORT uint64_t Revision() const { return credential_index_revision_; }
    EXPORT void GetPrivateCredentials(String& strCredList,
                                      String::Map* pmapCredFiles = nullptr);
    EXPORT const serializedCredentialIndex asPublicNym() const;
    EXPORT size_t GetMasterCredentialCount() const;
    EXPORT size_t GetRevokedCredentialCount() const;
    EXPORT CredentialSet* GetRevokedCredential(const String& strID);
    EXPORT const CredentialSet* GetMasterCredentialByIndex(int32_t nIndex) const;
    EXPORT const CredentialSet* GetRevokedCredentialByIndex(
        int32_t nIndex) const;
    EXPORT const Credential* GetChildCredential(
        const String& strMasterID, const String& strChildCredID) const;
    EXPORT bool GetNymboxHashServerSide(const Identifier& theNotaryID,
                                        Identifier& theOutput); // server-side
    EXPORT void SetNymboxHashServerSide(
        const Identifier& theInput); // server-side
    EXPORT std::shared_ptr<const proto::Credential> MasterCredentialContents(
        const std::string& id) const;
    EXPORT std::shared_ptr<const proto::Credential> RevokedCredentialContents(
        const std::string& id) const;
    EXPORT int32_t ChildCredentialCount(const std::string& masterID) const;
    EXPORT std::string ChildCredentialID(
        const std::string& masterID,
        const uint32_t index) const;
    EXPORT std::shared_ptr<const proto::Credential> ChildCredentialContents(
        const std::string& masterID,
        const std::string& childID) const;

private:
    const CredentialSet* MasterCredential(const String& strID) const;
    CredentialSet* GetMasterCredential(const String& strID);
    // Generic function used by the below functions.
    bool GetHash(const mapOfIdentifiers& the_map, const std::string& str_id,
                 Identifier& theOutput) const; // client-side
    bool SetHash(mapOfIdentifiers& the_map, const std::string& str_id,
                 const Identifier& theInput); // client-side
    void SetAsPrivate(bool isPrivate = true);
    bool isPrivate() const;

public:
    // This value is only updated on client side, when the actual latest
    // nymbox has been downloaded.
    EXPORT bool GetNymboxHash(const std::string& notary_id,
                              Identifier& theOutput) const; // client-side
    EXPORT bool SetNymboxHash(const std::string& notary_id,
                              const Identifier& theInput); // client-side
    // Whereas THIS value is updated when various server replies are received.
    // (So we can see the most recent version of the same hash on server side.)
    // If this doesn't match the hash above, then it's time to download your
    // nymbox
    // because it's old.
    EXPORT bool GetRecentHash(const std::string& notary_id,
                              Identifier& theOutput) const; // client-side
    EXPORT bool SetRecentHash(const std::string& notary_id,
                              const Identifier& theInput); // client-side
    // This functions are for the latest downloaded inbox's hash.
    // (If the hash that appears in the account is different, then
    // your inbox is old -- download it again.)
    //
    // This saves you having to download it many times when it has not even
    // changed.
    //
    EXPORT bool GetInboxHash(const std::string& acct_id,
                             Identifier& theOutput) const; // client-side
    EXPORT bool SetInboxHash(const std::string& acct_id,
                             const Identifier& theInput); // client-side
    // This functions are for the latest downloaded outbox's hash.
    // (If the hash that appears in the account is different, then
    // your outbox is old -- download it again.)
    //
    // This saves you having to download it many times when it has not even
    // changed.
    //
    EXPORT bool GetOutboxHash(const std::string& acct_id,
                              Identifier& theOutput) const; // client-side
    EXPORT bool SetOutboxHash(const std::string& acct_id,
                              const Identifier& theInput); // client-side
    EXPORT const int64_t& GetUsageCredits() const
    {
        return m_lUsageCredits;
    }
    EXPORT void SetUsageCredits(const int64_t& lUsage)
    {
        m_lUsageCredits = lUsage;
    }
    inline void MarkForDeletion()
    {
        m_bMarkForDeletion = true;
    }
    inline bool IsMarkedForDeletion() const
    {
        return m_bMarkForDeletion;
    }
    inline void MarkAsUndeleted()
    {
        m_bMarkForDeletion = false;
    }

    // Server-side. Helps the server keep track of the accounts for a certain
    // Nym, and the cron items.
    inline std::set<int64_t>& GetSetOpenCronItems()
    {
        return m_setOpenCronItems;
    }
    inline std::set<std::string>& GetSetAssetAccounts()
    {
        return m_setAccounts;
    } // stores acct IDs as std::string
    EXPORT Nym();
    EXPORT Nym(const NymParameters& nymParameters);
    EXPORT Nym(const Identifier& nymID);
    EXPORT Nym(const String& strNymID);
private:
    EXPORT Nym(const String& name, const String& filename, const String& nymID);
public:
    EXPORT virtual ~Nym();
    EXPORT void Initialize();
    EXPORT void ReleaseTransactionNumbers();
    EXPORT bool VerifyPseudonym() const;

    // Some messages require "transaction agreement" as opposed to "balance
    // agreement."
    // That is, cases where only transactions change and not balances.
    //
    EXPORT Item* GenerateTransactionStatement(
        const OTTransaction& theOwner); // like balance agreement
                                        // SET PUBLIC KEY BASED ON INPUT STRING

    // CALLER is responsible to delete the Nym ptr being returned
    // in this functions!
    //
    EXPORT static Nym* LoadPrivateNym(
        const Identifier& NYM_ID, bool bChecking = false,
        const String* pstrName = nullptr, const char* szFuncName = nullptr,
        const OTPasswordData* pPWData = nullptr,
        const OTPassword* pImportPassword = nullptr);
    EXPORT bool HasPublicKey() const;
    EXPORT bool HasPrivateKey() const;
    EXPORT const OTAsymmetricKey& GetPublicAuthKey() const; // Authentication
    const OTAsymmetricKey& GetPrivateAuthKey() const;
    EXPORT const OTAsymmetricKey& GetPublicEncrKey() const; // Encryption
    const OTAsymmetricKey& GetPrivateEncrKey() const;
    EXPORT const OTAsymmetricKey& GetPublicSignKey() const; // Signing
    const OTAsymmetricKey& GetPrivateSignKey() const;
    // OT uses the signature's metadata to narrow down its search for the
    // correct public key.
    EXPORT int32_t GetPublicKeysBySignature(
        listOfAsymmetricKeys& listOutput, const OTSignature& theSignature,
        char cKeyType = '0') const; // 'S' (signing key) or
                                    // 'E' (encryption key)
                                    // or 'A'
                                    // (authentication key)
    EXPORT bool SaveCredentialIDs() const;
private:
    EXPORT void SaveCredentialsToTag(Tag& parent,
                                     String::Map* pmapPubInfo = nullptr,
                                     String::Map* pmapPriInfo = nullptr) const;
    serializedCredentialIndex SerializeCredentialIndex(
        const CredentialIndexModeFlag mode = ONLY_IDS) const;

public:
    bool LoadCredentialIndex(const serializedCredentialIndex& index);
    EXPORT bool LoadCredentials(bool bLoadPrivate = false, // Loads public
                                                           // credentials by
                                // default. For private, pass true.
                                const OTPasswordData* pPWData = nullptr,
                                const OTPassword* pImportPassword = nullptr);
    // Like for when you are exporting a Nym from the wallet.
    EXPORT bool ReEncryptPrivateCredentials(
        bool bImporting,
        const OTPasswordData* pPWData = nullptr, // bImporting=true, or
                                                 // false if exporting.
        const OTPassword* pImportPassword = nullptr);
    // The signer is whoever wanted to make sure these nym files haven't
    // changed.
    // Usually that means the server nym.  Most of the time, m_nymServer will be
    // used as signer.
    EXPORT bool LoadSignedNymfile(Nym& SIGNER_NYM);
    EXPORT bool SaveSignedNymfile(Nym& SIGNER_NYM);
    EXPORT bool LoadNymFromString(const String& strNym,
                               String::Map* pMapCredentials =
                                   nullptr, // pMapCredentials can be passed, if
                                            // you prefer to use a specific set,
                               // instead of just loading the actual
                               // set from storage (such as during
                               // registration, when the credentials
                               // have been sent inside a message.)
                               String* pstrReason = nullptr,
                               const OTPassword* pImportPassword = nullptr);
    EXPORT bool LoadPublicKey();
    EXPORT bool SavePseudonymWallet(Tag& parent) const;
    EXPORT bool SavePseudonym(); // saves to filename m_strNymfile
protected:
    EXPORT bool SavePseudonym(const char* szFoldername, const char* szFilename);
public:
    EXPORT bool SavePseudonym(String& strNym);
    EXPORT bool CompareID(const Identifier& theIdentifier) const
    {
        return (theIdentifier == m_nymID);
    }

    EXPORT bool CompareID(const Nym& RHS) const;
    EXPORT const NymIDSource& Source() const
    {
        return *source_;
    } // Source for NymID for this credential. (Hash it to get ID.)
    EXPORT const String& GetDescription() const
    {
        return m_strDescription;
    } // Alternate download location for Nym's credential IDs. (Primary location
      // being the source itself, but sometimes that's not feasible.)

    EXPORT void SetSource(const NymIDSource& source)
    {
        std::shared_ptr<NymIDSource> pSource =
        std::make_shared<NymIDSource>(source);
        source_ = pSource;
    }
    EXPORT void SetDescription(const String& strLocation)
    {
        m_strDescription = strLocation;
    }
private:
    EXPORT void SerializeNymIDSource(Tag& parent) const;
public:
    EXPORT const Identifier& GetConstID() const
    {
        return m_nymID;
    } // CONST VERSION

    EXPORT void GetIdentifier(Identifier& theIdentifier) const; // BINARY
                                                                // VERSION
    EXPORT const Identifier& ID() const { return m_nymID; }
    EXPORT void SetIdentifier(const Identifier& theIdentifier);

    EXPORT void GetIdentifier(String& theIdentifier) const; // STRING VERSION
    EXPORT void SetIdentifier(const String& theIdentifier);
    EXPORT void HarvestTransactionNumbers(
        const Identifier& theNotaryID, Nym& SIGNER_NYM,
        Nym& theOtherNym,   // OtherNym is used as a container for the
                            // server to send
        bool bSave = true); // us new transaction numbers.

    EXPORT void HarvestIssuedNumbers(
        const Identifier& theNotaryID, Nym& SIGNER_NYM,
        Nym& theOtherNym,    // OtherNym is used as container for us to
                             // send a list
        bool bSave = false); // of issued numbers to the server (for balance
                             // agreement)

    EXPORT bool ClawbackTransactionNumber(
        const Identifier& theNotaryID,
        const int64_t& lTransClawback, // the number being clawed back.
        bool bSave = false, Nym* pSIGNER_NYM = nullptr);
    EXPORT void IncrementRequestNum(Nym& SIGNER_NYM,
                                    const String& strNotaryID); // Increment
                                                                // the counter
                                                                // or create a
                                                                // new one for
                                                                // this
                                                                // notaryID
                                                                // starting at
                                                                // 1
    EXPORT void OnUpdateRequestNum(Nym& SIGNER_NYM, const String& strNotaryID,
                                   int64_t lNewRequestNumber); // if the server
                                                               // sends us a
    // getRequestNumberResponse
    EXPORT bool GetCurrentRequestNum(const String& strNotaryID,
                                     int64_t& lReqNum) const; // get the current
    // request number for
    // the notaryID

    EXPORT bool GetHighestNum(const String& strNotaryID,
                              int64_t& lHighestNum) const; // get the
                                                           // last/current
    // highest transaction
    // number for the notaryID.
    EXPORT int64_t UpdateHighestNum(Nym& SIGNER_NYM, const String& strNotaryID,
                                    std::set<int64_t>& setNumbers,
                                    std::set<int64_t>& setOutputGood,
                                    std::set<int64_t>& setOutputBad,
                                    bool bSave = false); // Returns 0 if
                                                         // success, otherwise #
                                                         // of the violator.

    inline mapOfTransNums& GetMapTransNum()
    {
        return m_mapTransNum;
    }
    inline mapOfTransNums& GetMapIssuedNum()
    {
        return m_mapIssuedNum;
    }
    inline mapOfTransNums& GetMapTentativeNum()
    {
        return m_mapTentativeNum;
    }
    inline mapOfTransNums& GetMapAcknowledgedNum()
    {
        return m_mapAcknowledgedNum;
    } // This one actually stores request numbers.

    EXPORT void RemoveAllNumbers(const String* pstrNotaryID = nullptr,
                                 bool bRemoveHighestNum = true); // for
                                                                 // transaction
                                                                 // numbers
    EXPORT void RemoveReqNumbers(
        const String* pstrNotaryID = nullptr); // for request numbers (entirely
                                               // different animal)
    EXPORT bool UnRegisterAtServer(const String& strNotaryID); // Removes the
                                                               // request num
                                                               // for a
                                                               // specific
                                                               // server, if
                                                               // it was there
                                                               // before.
    EXPORT bool IsRegisteredAtServer(const String& strNotaryID) const; // You
                                                                       // can't
    // go using a
    // Nym at a
    // certain
    // server, if
    // it's not
    // registered
    // there...
    //
    // ** ResyncWithServer **
    //
    // Not for normal use! (Since you should never get out of sync with the
    // server in the first place.)
    // However, in testing, or if some bug messes up some data, or whatever, and
    // you absolutely need to
    // re-sync with a server, and you trust that server not to lie to you, then
    // this function will do the trick.
    // NOTE: Before calling this, you need to do a getNymbox() to download the
    // latest Nymbox, and you need to do
    // a registerNym() to download the server's copy of your Nym. You then
    // need to load that Nymbox from
    // local storage, and you need to load the server's message Nym out of the
    // registerNymResponse reply, so that
    // you can pass both of those objects into this function, which must assume
    // that those pieces were already done
    // just prior to this call.
    EXPORT bool ResyncWithServer(const Ledger& theNymbox,
                                 const Nym& theMessageNym);
    // HIGH LEVEL:
    EXPORT bool AddTransactionNum(Nym& SIGNER_NYM, const String& strNotaryID,
                                  int64_t lTransNum,
                                  bool bSave); // We have received a new trans
                                               // num from server. Store it.
    EXPORT bool GetNextTransactionNum(Nym& SIGNER_NYM,
                                      const String& strNotaryID,
                                      int64_t& lTransNum,
                                      bool bSave = true); // Get the next
                                                          // available
                                                          // transaction number
                                                          // for the notaryID
                                                          // passed. Saves by
                                                          // default.
    EXPORT bool RemoveIssuedNum(Nym& SIGNER_NYM, const String& strNotaryID,
                                const int64_t& lTransNum,
                                bool bSave); // SAVE OR NOT (your choice)
    bool RemoveTentativeNum(Nym& SIGNER_NYM, const String& strNotaryID,
                            const int64_t& lTransNum, bool bSave);
    EXPORT bool RemoveAcknowledgedNum(Nym& SIGNER_NYM,
                                      const String& strNotaryID,
                                      const int64_t& lRequestNum,
                                      bool bSave); // Used on both client and
                                                   // server sides for
                                                   // optimization.
    EXPORT bool VerifyIssuedNum(const String& strNotaryID,
                                const int64_t& lTransNum) const; // verify user
                                                                 // is
    // still responsible
    // for (signed for) a
    // certain trans#
    // that was previous
    // issued to him.
    // (i.e. it's been
    // used, but not yet
    // accepted receipt
    // through inbox.)
    EXPORT bool VerifyTransactionNum(const String& strNotaryID,
                                     const int64_t& lTransNum) const; // server
    // verifies that
    // nym has this
    // TransNum
    // available for
    // use.
    EXPORT bool VerifyTentativeNum(
        const String& strNotaryID,
        const int64_t& lTransNum) const; // Client-side
                                         // verifies that
                                         // it actually
                                         // tried to sign
                                         // for this number
                                         // (so it knows if
                                         // the reply is
                                         // valid.)
    EXPORT bool VerifyAcknowledgedNum(
        const String& strNotaryID,
        const int64_t& lRequestNum) const; // Client
                                           // verifies
                                           // it has
                                           // already
                                           // seen a
    // server reply. Server acknowledges client
    // has seen reply (so client can remove
    // from list, so server can as well.)
    // These two functions are for when you re-download your
    // nym/account/inbox/outbox, and you
    // need to verify it against the last signed receipt to make sure you aren't
    // getting screwed.
    //
    EXPORT bool VerifyIssuedNumbersOnNym(Nym& THE_NYM);
    EXPORT bool VerifyTransactionStatementNumbersOnNym(Nym& THE_NYM);
    // These functions are for transaction numbers that were assigned to me,
    // until I accept the receipts or put stop payment onto them.
    //
    EXPORT int32_t
        GetIssuedNumCount(const Identifier& theNotaryID) const; // count
    EXPORT int64_t GetIssuedNum(const Identifier& theNotaryID,
                                int32_t nIndex) const; // index

    EXPORT bool AddIssuedNum(const String& strNotaryID,
                             const int64_t& lTransNum); // doesn't save

    EXPORT bool RemoveIssuedNum(Nym& SIGNER_NYM, const String& strNotaryID,
                                const int64_t& lTransNum); // saves
    EXPORT bool RemoveIssuedNum(const String& strNotaryID,
                                const int64_t& lTransNum); // doesn't save
    // These functions are for transaction numbers that I still have available
    // to use.
    //
    EXPORT int32_t
        GetTransactionNumCount(const Identifier& theNotaryID) const; // count
    EXPORT int64_t GetTransactionNum(const Identifier& theNotaryID,
                                     int32_t nIndex) const; // index

    EXPORT bool AddTransactionNum(const String& strNotaryID,
                                  int64_t lTransNum); // doesn't save

    EXPORT bool RemoveTransactionNum(Nym& SIGNER_NYM, const String& strNotaryID,
                                     const int64_t& lTransNum); // server
                                                                // removes spent
                                                                // number from
                                                                // nym file.
                                                                // Saves.
    EXPORT bool RemoveTransactionNum(const String& strNotaryID,
                                     const int64_t& lTransNum); // doesn't save.
    // These functions are for tentative transaction numbers that I am trying to
    // sign for.
    // They are in my Nymbox. I sign to accept them, and then store them here.
    // The server
    // replies with success, and then I remove them from this list, and move
    // them onto the
    // two lists above. For good measure, the server also puts a success note
    // into my Nymbox,
    // so if the network transport is lost, I will still have the chance to get
    // my Nymbox,
    // and see the notices. By this time, the numbers are DEFNITELY ALREADY
    // CONFIRMED, and
    // the notices can simply be discarded if the numbers aren't on list
    // "Tentative" list.
    // That means they already went through, and were already removed from this
    // list as
    // described higher in this paragraph. HOWEVER, if I somehow lost the
    // message (the
    // original server success reply when I signed for the numbers) then they
    // will STILL be
    // stuck on this list! The notice gives me a chance to officially move them
    // to the right
    // place. After all, my transactions won't work until I do, because my
    // balance agreements
    // will be wrong.
    //
    EXPORT int64_t GetTentativeNum(const Identifier& theNotaryID,
                                   int32_t nIndex) const; // index

    EXPORT bool AddTentativeNum(const String& strNotaryID,
                                const int64_t& lTransNum); // doesn't save

    EXPORT bool RemoveTentativeNum(Nym& SIGNER_NYM, const String& strNotaryID,
                                   const int64_t& lTransNum);
    EXPORT bool RemoveTentativeNum(const String& strNotaryID,
                                   const int64_t& lTransNum); // doesn't save.
    // On the client side, whenever the client is DEFINITELY made aware of the
    // existence of a
    // server reply, he adds its request number to this list, which is sent
    // along with all client-side
    // requests to the server.
    // The server reads the list on the incoming client message (and it uses
    // these same functions
    // to store its own internal list.) If the # already appears on its internal
    // list, then it does
    // nothing. Otherwise, it loads up the Nymbox and removes the replyNotice,
    // and then adds the #
    // to its internal list.
    // For any numbers on the internal list but NOT on the client's list, the
    // server removes from
    // the internal list. (The client removed them when it saw the server's
    // internal list, which the
    // server sends with its replies.)
    //
    // This entire protocol, densely described, is unnecessary for OT to
    // function, but is great for
    // optimization, as it enables OT to avoid downloading all Box Receipts
    // containing replyNotices,
    // as long as the original reply was properly received when the request was
    // originally sent (which
    // is MOST of the time...)
    // Thus we can eliminate most replyNotice downloads, and likely a large % of
    // box receipt downloads
    // as well.
    //
    EXPORT int32_t
        GetAcknowledgedNumCount(const Identifier& theNotaryID) const; // count
    EXPORT int64_t GetAcknowledgedNum(const Identifier& theNotaryID,
                                      int32_t nIndex) const; // index

    EXPORT bool AddAcknowledgedNum(const String& strNotaryID,
                                   const int64_t& lRequestNum); // doesn't save

    EXPORT bool RemoveAcknowledgedNum(Nym& SIGNER_NYM,
                                      const String& strNotaryID,
                                      const int64_t& lRequestNum);
    EXPORT bool RemoveAcknowledgedNum(const String& strNotaryID,
                                      const int64_t& lRequestNum); // doesn't
                                                                   // save.
    // The "issued" numbers and the "transaction" numbers both use these
    // functions
    // to do the actual work (just avoiding code duplication.) "tentative" as
    // well,
    // and "Acknowledged". (For acknowledged replies.)
    //
    EXPORT bool VerifyGenericNum(const mapOfTransNums& THE_MAP,
                                 const String& strNotaryID,
                                 const int64_t& lTransNum) const;

    EXPORT bool RemoveGenericNum(mapOfTransNums& THE_MAP, Nym& SIGNER_NYM,
                                 const String& strNotaryID,
                                 const int64_t& lTransNum); // saves
    EXPORT bool RemoveGenericNum(mapOfTransNums& THE_MAP,
                                 const String& strNotaryID,
                                 const int64_t& lTransNum); // doesn't save

    EXPORT bool AddGenericNum(mapOfTransNums& THE_MAP,
                              const String& strNotaryID,
                              int64_t lTransNum); // doesn't save

    EXPORT int32_t GetGenericNumCount(const mapOfTransNums& THE_MAP,
                                      const Identifier& theNotaryID) const;
    EXPORT int64_t GetGenericNum(const mapOfTransNums& THE_MAP,
                                 const Identifier& theNotaryID,
                                 int32_t nIndex) const;
    // Whenever a Nym receives a message via his Nymbox, and then the Nymbox is
    // processed, (which happens automatically)
    // that processing will drop all mail messages into this deque for
    // safe-keeping, after Nymbox is cleared.
    //
    EXPORT void AddMail(Message& theMessage); // a mail message is the
                                              // original OTMessage from the
                                              // sender, transported via
                                              // Nymbox of recipient (me).
    EXPORT int32_t GetMailCount() const; // How many mail messages does this Nym
                                         // currently store?
    EXPORT Message* GetMailByIndex(int32_t nIndex) const; // Get a
                                                          // specific
    // piece of mail, at
    // a specific index.
    EXPORT bool RemoveMailByIndex(int32_t nIndex); // if returns false,
    // mail index was bad
    // (or something else
    // must have gone
    // seriously wrong.)

    EXPORT void ClearMail(); // called by the destructor. (Not intended to erase
                             // messages from local storage.)
    // Whenever a Nym sends a message, a copy is dropped into his Outmail.
    //
    EXPORT void AddOutmail(Message& theMessage); // a mail message is the
                                                 // original OTMessage that
                                                 // this Nym sent.
    EXPORT int32_t
        GetOutmailCount() const; // How many outmail messages does this Nym
                                 // currently store?
    EXPORT Message* GetOutmailByIndex(int32_t nIndex) const; // Get a
                                                             // specific
                                                             // piece of
    // outmail, at a
    // specific
    // index.
    EXPORT bool RemoveOutmailByIndex(int32_t nIndex); // if returns false,
                                                      // outmail index was
                                                      // bad (or something
                                                      // else must have
                                                      // gone seriously
                                                      // wrong.)

    EXPORT void ClearOutmail(); // called by the destructor. (Not intended to
                                // erase messages from local storage.)
    // Whenever a Nym sends a payment, a copy is dropped into his Outpayments.
    // (Payments screen.)
    //
    EXPORT void AddOutpayments(Message& theMessage); // a payments message is
                                                     // the original OTMessage
                                                     // that this Nym sent.
    EXPORT int32_t
        GetOutpaymentsCount() const; // How many outpayments messages does
                                     // this Nym currently store?
    EXPORT Message* GetOutpaymentsByIndex(int32_t nIndex) const; // Get a
                                                                 // specific
                                                                 // piece of
                                                                 // outpayments,
                                                                 // at a
    // specific index.
    EXPORT bool RemoveOutpaymentsByIndex(int32_t nIndex,
                                         bool bDeleteIt = true); // if returns
                                                                 // false,
    // outpayments index was bad
    // (or something else must
    // have gone seriously
    // wrong.)

    EXPORT void ClearOutpayments(); // called by the destructor. (Not intended
                                    // to erase messages from local storage.)
    void ClearCredentials();
    void ClearAll();
    EXPORT void DisplayStatistics(String& strOutput);

    EXPORT bool WriteCredentials() const;
    std::unique_ptr<proto::ContactData> ContactData() const;
    bool SetContactData(const proto::ContactData& data);

    std::unique_ptr<proto::VerificationSet> VerificationSet() const;
    bool SetVerificationSet(const proto::VerificationSet& data);

    bool Sign(
        proto::Verification& verification,
        const OTPasswordData* pPWData = nullptr) const;
    proto::Verification Sign(
        const std::string& claim,
        const bool polarity,
        const int64_t start = 0,
        const int64_t end = 0,
        const OTPasswordData* pPWData = nullptr) const;
    bool Sign(proto::ServerContract& contract) const;
    bool Sign(
        const proto::UnitDefinition& contract,
        proto::Signature& sig) const;
    bool Verify(const OTData& plaintext, const proto::Signature& sig) const;
    bool Verify(const proto::Verification& item) const;
    zcert_t* TransportKey() const;
};

} // namespace opentxs

#endif // OPENTXS_CORE_OTPSEUDONYM_HPP
