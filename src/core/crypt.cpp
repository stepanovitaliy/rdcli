#include "core/crypt.h"

#include <cstring>
#include <stdexcept>

#include <sodium.h>

#include "proto/message.pb.h"

namespace rdcli::core {

namespace {

std::array<uint8_t, 32> to_array32(const uint8_t* p) {
    std::array<uint8_t, 32> out{};
    std::memcpy(out.data(), p, out.size());
    return out;
}

}  // namespace

KeyPair generate_keypair() {
    KeyPair kp{};
    if (crypto_box_keypair(kp.pub.data(), kp.priv.data()) != 0) {
        throw std::runtime_error("hbb: box keypair generation failed");
    }
    return kp;
}

std::array<uint8_t, 32> derive_shared_secret(const std::array<uint8_t, 32>& our_priv,
                                             const std::array<uint8_t, 32>& their_pub) {
    std::array<uint8_t, 32> shared{};
    if (crypto_box_beforenm(shared.data(), their_pub.data(), our_priv.data()) != 0) {
        throw std::runtime_error("hbb: box precompute failed");
    }
    return shared;
}

Encryptor::Encryptor(std::array<uint8_t, 32> key) : key_(key) {}

std::string Encryptor::encrypt(const std::string& plaintext) {
    send_count_++;
    const auto nonce = make_nonce(send_count_);
    std::string out(plaintext.size() + crypto_secretbox_MACBYTES, '\0');
    if (crypto_secretbox_easy(reinterpret_cast<uint8_t*>(out.data()),
                              reinterpret_cast<const uint8_t*>(plaintext.data()),
                              plaintext.size(), nonce.data(), key_.data()) != 0) {
        throw std::runtime_error("hbb: secretbox encryption failed");
    }
    return out;
}

std::optional<std::string> Encryptor::decrypt(const std::string& ciphertext) {
    recv_count_++;
    const auto nonce = make_nonce(recv_count_);
    if (ciphertext.size() < crypto_secretbox_MACBYTES) {
        return std::nullopt;
    }
    std::string out(ciphertext.size() - crypto_secretbox_MACBYTES, '\0');
    if (crypto_secretbox_open_easy(reinterpret_cast<uint8_t*>(out.data()),
                                   reinterpret_cast<const uint8_t*>(ciphertext.data()),
                                   ciphertext.size(), nonce.data(), key_.data()) != 0) {
        return std::nullopt;
    }
    return out;
}

std::array<uint8_t, 24> make_nonce(uint64_t counter) {
    std::array<uint8_t, 24> nonce{};
    for (int i = 0; i < 8; i++) {
        nonce[i] = static_cast<uint8_t>((counter >> (8 * i)) & 0xFF);
    }
    return nonce;
}

std::optional<std::string> secretbox_open(const std::string& ciphertext,
                                          const std::array<uint8_t, 24>& nonce,
                                          const std::array<uint8_t, 32>& key) {
    if (ciphertext.size() < crypto_secretbox_MACBYTES) {
        return std::nullopt;
    }
    std::string out(ciphertext.size() - crypto_secretbox_MACBYTES, '\0');
    if (crypto_secretbox_open_easy(reinterpret_cast<uint8_t*>(out.data()),
                                   reinterpret_cast<const uint8_t*>(ciphertext.data()),
                                   ciphertext.size(), nonce.data(), key.data()) != 0) {
        return std::nullopt;
    }
    return out;
}

bool verify_signature(const std::string& sig, const std::string& msg,
                      const std::array<uint8_t, 32>& ed_pub) {
    if (sig.size() != crypto_sign_BYTES) {
        return false;
    }
    return crypto_sign_verify_detached(reinterpret_cast<const uint8_t*>(sig.data()),
                                       reinterpret_cast<const uint8_t*>(msg.data()),
                                       msg.size(), ed_pub.data()) == 0;
}

std::optional<SignedId> verify_signed_id(const std::string& signed_blob,
                                         const std::array<uint8_t, 32>& ed_pub) {
    if (signed_blob.size() <= crypto_sign_BYTES) {
        return std::nullopt;
    }
    const std::string sig = signed_blob.substr(0, crypto_sign_BYTES);
    const std::string msg = signed_blob.substr(crypto_sign_BYTES);
    if (!verify_signature(sig, msg, ed_pub)) {
        return std::nullopt;
    }
    hbb::IdPk idpk;
    if (!idpk.ParseFromString(msg)) {
        return std::nullopt;
    }
    if (idpk.pk().size() != 32) {
        return std::nullopt;
    }
    SignedId out;
    out.id = idpk.id();
    out.pk = to_array32(reinterpret_cast<const uint8_t*>(idpk.pk().data()));
    return out;
}

SymKeyMsg create_symmetric_key_msg(const std::array<uint8_t, 32>& their_pk) {
    SymKeyMsg m{};
    std::array<uint8_t, 32> our_priv{};
    if (crypto_box_keypair(m.asym.data(), our_priv.data()) != 0) {
        throw std::runtime_error("hbb: ephemeral box keypair failed");
    }
    randombytes_buf(m.key.data(), m.key.size());

    std::array<uint8_t, 24> nonce{};
    std::string sealed(32 + crypto_box_MACBYTES, '\0');
    if (crypto_box_easy(reinterpret_cast<uint8_t*>(sealed.data()), m.key.data(), m.key.size(),
                        nonce.data(), their_pk.data(), our_priv.data()) != 0) {
        throw std::runtime_error("hbb: box seal failed");
    }
    m.sym_sealed = std::move(sealed);
    return m;
}

std::optional<std::array<uint8_t, 32>> decrypt_symmetric_key(
    const std::string& sym, const std::array<uint8_t, 32>& asym,
    const std::array<uint8_t, 32>& our_priv) {
    if (sym.size() != 32 + crypto_box_MACBYTES) {
        return std::nullopt;
    }
    std::array<uint8_t, 24> nonce{};
    std::array<uint8_t, 32> key{};
    if (crypto_box_open_easy(key.data(), reinterpret_cast<const uint8_t*>(sym.data()),
                             sym.size(), nonce.data(), asym.data(), our_priv.data()) != 0) {
        return std::nullopt;
    }
    return key;
}

std::array<uint8_t, 32> sha256(const std::string& data) {
    std::array<uint8_t, 32> out{};
    crypto_hash_sha256(out.data(), reinterpret_cast<const uint8_t*>(data.data()), data.size());
    return out;
}

}  // namespace rdcli::core
