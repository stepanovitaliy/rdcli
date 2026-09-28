#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>

namespace rdcli::core {

struct KeyPair {
    std::array<uint8_t, 32> pub;
    std::array<uint8_t, 32> priv;
};

KeyPair generate_keypair();

// X25519 shared secret (crypto_box_beforenm equivalent).
std::array<uint8_t, 32> derive_shared_secret(const std::array<uint8_t, 32>& our_priv,
                                             const std::array<uint8_t, 32>& their_pub);

// Secretbox stream encryptor with sequential little-endian nonces.
class Encryptor {
public:
    explicit Encryptor(std::array<uint8_t, 32> key);
    std::string encrypt(const std::string& plaintext);
    std::optional<std::string> decrypt(const std::string& ciphertext);

private:
    std::array<uint8_t, 32> key_;
    uint64_t send_count_ = 0;
    uint64_t recv_count_ = 0;
};

std::array<uint8_t, 24> make_nonce(uint64_t counter);

// Raw secretbox open with an explicit nonce (used for stored-password blobs).
std::optional<std::string> secretbox_open(const std::string& ciphertext,
                                          const std::array<uint8_t, 24>& nonce,
                                          const std::array<uint8_t, 32>& key);

// Ed25519 detached-signature verify (signature-first layout).
bool verify_signature(const std::string& sig, const std::string& msg,
                      const std::array<uint8_t, 32>& ed_pub);

struct SignedId {
    std::string id;
    std::array<uint8_t, 32> pk;  // X25519 public key
};

// Verifies sig(64) || IdPk_proto and returns id + embedded X25519 pubkey.
std::optional<SignedId> verify_signed_id(const std::string& signed_blob,
                                         const std::array<uint8_t, 32>& ed_pub);

struct SymKeyMsg {
    std::array<uint8_t, 32> asym;  // ephemeral X25519 public key
    std::string sym_sealed;        // box-sealed secretbox key
    std::array<uint8_t, 32> key;   // the secretbox key
};

SymKeyMsg create_symmetric_key_msg(const std::array<uint8_t, 32>& their_pk);

std::optional<std::array<uint8_t, 32>> decrypt_symmetric_key(
    const std::string& sym, const std::array<uint8_t, 32>& asym,
    const std::array<uint8_t, 32>& our_priv);

std::array<uint8_t, 32> sha256(const std::string& data);

}  // namespace rdcli::core
