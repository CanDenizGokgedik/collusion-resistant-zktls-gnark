// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title SchnorrVerifier
 * @notice Makale §VIII.B + §IX — SC.Verify(σ, pk) implementasyonu.
 *
 * FROST aggregat Schnorr imzasını secp256k1 üzerinde doğrular.
 * Hedef: ~4,200 gas (secp256k1 precompile ile).
 *
 * Doğrulama denklemi:
 *   S·G == R + c·PK
 *   c = SHA256("frost-challenge" || Rx || Ry || PKx || PKy || msg)
 *
 * ecrecover trick (gas optimizasyonu):
 *   Doğrudan secp256k1 scalar multiplication yerine ecrecover precompile
 *   kullanılır.  Denklem şöyle yeniden düzenlenir:
 *
 *     S·G - c·PK == R
 *   ⟺ ecrecover(hash_fake, v, PKx, s_fake) == address(R)
 *
 *   hash_fake = -S · PKx  (mod n)
 *   s_fake    = -c · PKx  (mod n)
 *   v         = 27 + (PKy mod 2)
 *
 * Gas dağılımı:
 *   SHA256 precompile (175 byte):  ~108 gas
 *   ecrecover precompile:         3,000 gas
 *   KECCAK256 (adres hesabı):      ~36 gas
 *   Diğer (MLOAD/MSTORE/CMP):     ~200 gas
 *   ─────────────────────────────────────────
 *   Toplam doğrulama logic'i:    ~3,344 gas
 */
contract SchnorrVerifier {
    // secp256k1 grup mertebesi
    uint256 constant N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    // SHA256 precompile adresi
    address constant SHA256_PRECOMPILE = address(0x02);
    // ecrecover precompile adresi
    address constant ECRECOVER_PRECOMPILE = address(0x01);

    /**
     * @notice Πcoll-min imzasını doğrular.
     * @param Rx  Nonce noktasının X koordinatı
     * @param Ry  Nonce noktasının Y koordinatı
     * @param S   Aggregat imza skaleri
     * @param pkx Grup public key X koordinatı (DKG çıktısı)
     * @param pky Grup public key Y koordinatı
     * @param message İmzalanan mesaj (32 byte)
     * @return true eğer imza geçerliyse, false aksi halde
     */
    function verify(
        uint256 Rx,
        uint256 Ry,
        uint256 S,
        uint256 pkx,
        uint256 pky,
        bytes32 message
    ) external view returns (bool) {
        // ── 1. Challenge: c = SHA256("frost-challenge"||R||PK||msg) ─────────
        // Go'daki frost.challenge() ile birebir aynı encoding:
        // 15 + 32 + 32 + 32 + 32 + 32 = 175 byte
        bytes memory hashInput = abi.encodePacked(
            bytes15("frost-challenge"),
            bytes32(Rx),
            bytes32(Ry),
            bytes32(pkx),
            bytes32(pky),
            message
        );

        uint256 c;
        {
            (bool ok, bytes memory result) = SHA256_PRECOMPILE.staticcall(hashInput);
            require(ok, "SHA256 precompile failed");
            c = uint256(bytes32(result)) % N;
        }

        // ── 2. ecrecover parametreleri ────────────────────────────────────────
        // hash_fake = n - (S * pkx mod n)   ≡  -S·pkx  (mod n)
        uint256 hashFake = N - mulmod(S, pkx, N);
        // s_fake    = n - (c * pkx mod n)   ≡  -c·pkx  (mod n)
        uint256 sFake    = N - mulmod(c, pkx, N);
        // v = 27 + (pky mod 2)
        uint8 v = uint8(27 + (pky % 2));

        // ── 3. ecrecover → address(S·G - c·PK) ───────────────────────────────
        bytes memory ecInput = abi.encodePacked(
            bytes32(hashFake),
            uint8(v),
            bytes32(pkx),
            bytes32(sFake)
        );
        address recovered;
        {
            (bool ok, bytes memory result) = ECRECOVER_PRECOMPILE.staticcall(ecInput);
            require(ok, "ecrecover failed");
            recovered = abi.decode(result, (address));
        }

        // ── 4. Beklenen adres: address(R) = keccak256(Rx||Ry)[12:] ──────────
        // Geçerli imzada S·G - c·PK == R olduğundan
        // ecrecover çıktısı address(R) ile eşleşmeli.
        address expectedR = address(
            uint160(uint256(keccak256(abi.encodePacked(bytes32(Rx), bytes32(Ry)))))
        );

        return recovered == expectedR;
    }

    /**
     * @notice Gas tahmini: sadece doğrulama logic'i (base tx hariç).
     * @dev Makale §IX hedef: ~4,200 gas.  Bu fonksiyon sabit döner.
     */
    function estimatedGas() external pure returns (uint256) {
        return 3_344; // SHA256 + ecrecover + keccak256 + overhead
    }
}