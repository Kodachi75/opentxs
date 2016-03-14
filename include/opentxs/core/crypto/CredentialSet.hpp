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

#ifndef OPENTXS_CORE_CRYPTO_CREDENTIALSET_HPP
#define OPENTXS_CORE_CRYPTO_CREDENTIALSET_HPP

#include "MasterCredential.hpp"
#include <opentxs/core/Nym.hpp>
#include <opentxs/core/String.hpp>
#include <opentxs/core/crypto/NymParameters.hpp>
#include <opentxs/core/NymIDSource.hpp>

#include <opentxs/core/crypto/Credential.hpp>

#include <memory>

// A nym contains a list of credential sets.
// The whole purpose of a Nym is to be an identity, which can have
// master credentials.
//
// Each CredentialSet contains list of Credentials. One of the
// Credentials is a MasterCredential, and the rest are ChildCredentials
// signed by the MasterCredential.
//
// A Credential may contain keys, in which case it is a KeyCredential.
//
// Credentials without keys might be an interface to a hardware device
// or other kind of external encryption and authentication system.
//
// Non-key Credentials are not yet implemented.
//
// Each KeyCredential has 3 OTKeypairs: encryption, signing, and authentication.
// Each OTKeypair has 2 OTAsymmetricKeys (public and private.)
//
// A MasterCredential must be a KeyCredential, and is only used to sign
// ChildCredentials
//
// ChildCredentials are used for all other actions, and never sign other
// Credentials

namespace opentxs
{

class Identifier;
class OTPassword;
class OTPasswordData;
class Credential;
class ChildKeyCredential;
class Tag;

typedef std::map<std::string, Credential*> mapOfCredentials;
typedef std::shared_ptr<proto::CredentialSet> SerializedCredentialSet;

// CredentialSet
//
// Contains a MasterCredential, and a list of child credentials signed by that master.
// Each child credential can generate its own Credential contract,
// even the MasterCredential, so a CredentialSet object
// includes many Credentials. (That is, each may be issued at separate times,
// each may be registered on a server at separate times, etc.)
//
// Each nym has multiple CredentialSets because there may be
// several master keys, each with their own child credentials.
//
// Two things to verify on a credential set:
//
// 1. If you hash m_pstrSourceForNymID, you should get m_pstrNymID.
// 2. m_pstrSourceForNymID should somehow verify m_MasterCredential.GetContents().
//    For example, if m_pstrSourceForNymID contains CA DN info, then GetContents
//    should contain a verifiable Cert with that same DN info. Another example,
//    if m_pstrSourceForNymID contains a public key, then m_MasterCredential.GetContents
//    should contain that same public key, or a cert that contains it. Another
//    example, if m_pstrSourceForNymID contains a URL, then m_MasterCredential.GetContents
//    should contain a public key found at that URL, or a public key that, when
//    hashed, matches one of the hashes posted at that URL.
//
class CredentialSet
{
private:
    std::shared_ptr<MasterCredential> m_MasterCredential;
    mapOfCredentials m_mapCredentials;
    mapOfCredentials m_mapRevokedCredentials;
    String m_strNymID;
    std::shared_ptr<NymIDSource> nym_id_source_;
    const OTPassword* m_pImportPassword = nullptr; // Not owned. Just here for
                                         // convenience.
                                    // Sometimes it will be set, so that when
                                    // loading something up (and decrypting it)
                                    // the password is already available, so the
                                    // user doesn't have to type it a million
                                    // times (such as during import.) So we use
                                    // it when it's available. And usually
                                    // whoever set it, will immediately set it
                                    // back to nullptr when he's done.
    CredentialSet();
    uint32_t version_;
public:
    void SetSource(const std::shared_ptr<NymIDSource>& source);
                                                           // The source is
                                                           // the
                                                           // URL/DN/pubkey
                                                           // that hashes to
                                                           // form the
                                                           // NymID. Any
                                                           // credential
                                                           // must verify
                                                           // against its
                                                           // own source.
    CredentialSet(const proto::CredentialSet& serializedCredentialSet);
    EXPORT CredentialSet(
        const NymParameters& nymParameters,
        const OTPasswordData* pPWData = nullptr);
    EXPORT const OTPassword* GetImportPassword() const
    {
        return m_pImportPassword;
    }
    EXPORT void SetImportPassword(const OTPassword* pImportPassword)
    {
        m_pImportPassword = pImportPassword;
    }

    EXPORT String MasterAsString() const;

    static CredentialSet* LoadMaster(
        const String& strNymID, // Caller is responsible to delete.
        const String& strMasterCredID,
        const OTPasswordData* pPWData = nullptr);
    static CredentialSet* LoadMasterFromString(
        const String& strInput,
        const String& strNymID, // Caller is responsible to delete.
        const String& strMasterCredID,
        OTPasswordData* pPWData = nullptr,
        const OTPassword* pImportPassword = nullptr);

    EXPORT bool Load_Master(const String& strNymID,
                            const String& strMasterCredID,
                            const OTPasswordData* pPWData = nullptr);
    EXPORT bool Load_MasterFromString(
        const String& strInput, const String& strNymID,
        const String& strMasterCredID,
        const OTPasswordData* pPWData = nullptr,
        const OTPassword* pImportPassword = nullptr);

    EXPORT bool ReEncryptPrivateCredentials(const OTPassword& theExportPassword,
                                            bool bImporting); // Like for when
                                                              // you are
                                                              // exporting a Nym
                                                              // from the
                                                              // wallet.
    EXPORT bool LoadChildKeyCredential(const String& strSubID);
    EXPORT bool LoadChildKeyCredential(const proto::Credential& serializedCred);
    EXPORT bool LoadChildKeyCredentialFromString(
        const String& strInput,
        const String& strSubID,
        const OTPassword* pImportPassword = nullptr);
    EXPORT size_t GetChildCredentialCount() const;
    EXPORT const Credential* GetChildCredential(
        const String& strSubID,
        const String::List* plistRevokedIDs = nullptr) const;
    EXPORT const Credential* GetChildCredentialByIndex(int32_t nIndex) const;
    EXPORT const std::string GetChildCredentialIDByIndex(size_t nIndex) const;
    EXPORT const serializedCredential GetSerializedPubCredential() const; // Returns: m_MasterCredential's
                                                                          // public credential
                                                                          // protobuf.
    EXPORT const String GetMasterCredID() const;   // Returns: Master
                                                   // Credential ID!
    EXPORT const String& GetNymID() const;
    EXPORT const NymIDSource& Source() const;

    EXPORT bool HasPublic() const;
    EXPORT bool HasPrivate() const;

    // listRevokedIDs should contain a list of std::strings for IDs of
    // already-revoked credentials.
    // That way, SerializeIDs will know whether to mark them as valid while
    // serializing them.
    // bShowRevoked allows us to include/exclude the revoked credentials from
    // the output (filter for valid-only.)
    // bValid=true means we are saving OTPseudonym::m_mapCredentials. Whereas
    // bValid=false means we're saving m_mapRevoked.
    //
    SerializedCredentialSet Serialize(const CredentialIndexModeFlag mode) const;
    EXPORT void SerializeIDs(Tag& parent, const String::List& listRevokedIDs,
                             String::Map* pmapPubInfo = nullptr,
                             String::Map* pmapPriInfo = nullptr,
                             bool bShowRevoked = false,
                             bool bValid = true) const;
    EXPORT bool VerifyInternally() const;
    EXPORT const MasterCredential& GetMasterCredential() const
    {
        return *m_MasterCredential;
    }
    EXPORT int32_t GetPublicKeysBySignature(
        listOfAsymmetricKeys& listOutput, const OTSignature& theSignature,
        char cKeyType = '0') const; // 'S' (signing key) or
                                    // 'E' (encryption key)
                                    // or 'A'
                                    // (authentication key)
    EXPORT const OTAsymmetricKey& GetPublicAuthKey(
        const String::List* plistRevokedIDs = nullptr) const;
    EXPORT const OTAsymmetricKey& GetPublicEncrKey(
        const String::List* plistRevokedIDs = nullptr) const;
    EXPORT const OTAsymmetricKey& GetPublicSignKey(
        const String::List* plistRevokedIDs = nullptr) const;
    EXPORT const OTAsymmetricKey& GetPrivateSignKey(
        const String::List* plistRevokedIDs = nullptr) const;
    EXPORT const OTAsymmetricKey& GetPrivateEncrKey(
        const String::List* plistRevokedIDs = nullptr) const;
    EXPORT const OTAsymmetricKey& GetPrivateAuthKey(
        const String::List* plistRevokedIDs = nullptr) const;
    EXPORT const OTKeypair& GetAuthKeypair(
        const String::List* plistRevokedIDs = nullptr) const;
    EXPORT const OTKeypair& GetEncrKeypair(
        const String::List* plistRevokedIDs = nullptr) const;
    EXPORT const OTKeypair& GetSignKeypair(
        const String::List* plistRevokedIDs = nullptr) const;
    EXPORT void ClearChildCredentials();
    EXPORT ~CredentialSet();
    EXPORT bool WriteCredentials() const;

    bool GetContactData(std::shared_ptr<proto::ContactData>& contactData) const;
    void RevokeContactCredentials(std::list<std::string>& contactCredentialIDs);
    bool AddContactCredential(const proto::ContactData& contactData);

    bool GetVerificationSet(
        std::shared_ptr<proto::VerificationSet>& verificationSet) const;
    void RevokeVerificationCredentials(
        std::list<std::string>& verificationCredentialIDs);
    bool AddVerificationCredential(
        const proto::VerificationSet& verificationSet);

    bool Sign(
        const OTData& plaintext,
        proto::Signature& sig,
        const OTPasswordData* pPWData = nullptr,
        const OTPassword* exportPassword = nullptr,
        const proto::SignatureRole role = proto::SIGROLE_ERROR,
        proto::KeyRole key = proto::KEYROLE_SIGN) const;
    bool Sign(
        const Credential& plaintext,
        proto::Signature& sig,
        const OTPasswordData* pPWData = nullptr,
        const OTPassword* exportPassword = nullptr,
        const proto::SignatureRole role = proto::SIGROLE_PUBCREDENTIAL) const;
    bool Sign(
        const MasterCredential& credential,
        const NymParameters& nymParameters,
        proto::Signature& sig,
        const OTPasswordData* pPWData = nullptr) const;

    bool Verify(
        const OTData& plaintext,
        const proto::Signature& sig,
        const proto::KeyRole key = proto::KEYROLE_SIGN) const;
    bool Verify(const proto::Verification& item) const;
    bool TransportKey(
        unsigned char* publicKey,
        unsigned char* privateKey) const;
};

} // namespace opentxs

#endif // OPENTXS_CORE_CRYPTO_CREDENTIALSET_HPP
