// edtest.cpp - Ed25519 known-answer tests against RFC 8032 Section 7.1.
// Validates against the trustworthy knowns: public-key derivation for Tests 1
// and 2, and Test 2's signature (sign + verify), plus a roundtrip and a
// tamper-negative.
#include <cstdio>
#include <cstring>
#include <cstdint>
#include "../src/sdk/hz_ed25519.h"

static int hx(char c){ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; if(c>='A'&&c<='F')return c-'A'+10; return -1; }
static size_t unhex(const char* s, uint8_t* out, size_t cap){
    size_t n=0; for(; s[0]&&s[1] && n<cap; s+=2){ out[n++]=(uint8_t)((hx(s[0])<<4)|hx(s[1])); } return n;
}
static bool eq(const uint8_t* a, const uint8_t* b, size_t n){ return memcmp(a,b,n)==0; }

int main(){
    bool pass = true;

    const char* SEED1="9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const char* PK1  ="d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const char* SEED2="4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
    const char* PK2  ="3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
    const char* MSG2 ="72";
    const char* SIG2 ="92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
                      "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";

    uint8_t seed[32], pkWant[32], sk[64], pkGot[32], msg[8], sigWant[64], sigGot[64];

    // KAT 1: seed -> public key
    unhex(SEED1, seed, 32); unhex(PK1, pkWant, 32);
    hz::ed::keypair_from_seed(pkGot, sk, seed);
    { bool ok=eq(pkGot,pkWant,32); printf("KAT1 pubkey derive : %s\n", ok?"[PASS]":"[FAIL]"); pass&=ok; }

    // KAT 2: seed -> public key, plus sign and verify against RFC sig
    unhex(SEED2, seed, 32); unhex(PK2, pkWant, 32);
    hz::ed::keypair_from_seed(pkGot, sk, seed);
    { bool ok=eq(pkGot,pkWant,32); printf("KAT2 pubkey derive : %s\n", ok?"[PASS]":"[FAIL]"); pass&=ok; }

    size_t mlen = unhex(MSG2, msg, 8);
    unhex(SIG2, sigWant, 64);
    hz::ed::sign_detached(sigGot, msg, mlen, sk);
    { bool ok=eq(sigGot,sigWant,64); printf("KAT2 sign == RFC   : %s\n", ok?"[PASS]":"[FAIL]"); pass&=ok;
      if(!ok){ printf("  got: "); for(int i=0;i<64;i++)printf("%02x",sigGot[i]); printf("\n"); } }

    { bool ok=hz::ed::verify_detached(sigWant, msg, mlen, pkWant); printf("KAT2 verify RFC sig: %s\n", ok?"[PASS]":"[FAIL]"); pass&=ok; }

    // Roundtrip + tamper-negative with a non-trivial message.
    const char* text="HZProtect license: hwid=ANY expiry=never features=0xFF";
    hz::ed::sign_detached(sigGot, (const uint8_t*)text, strlen(text), sk);
    { bool ok=hz::ed::verify_detached(sigGot,(const uint8_t*)text,strlen(text),pkWant); printf("roundtrip verify   : %s\n", ok?"[PASS]":"[FAIL]"); pass&=ok; }
    sigGot[10]^=1;
    { bool bad=hz::ed::verify_detached(sigGot,(const uint8_t*)text,strlen(text),pkWant); printf("tampered sig reject : %s\n", (!bad)?"[PASS]":"[FAIL]"); pass&=(!bad); }
    sigGot[10]^=1;
    { bool bad=hz::ed::verify_detached(sigGot,(const uint8_t*)text,strlen(text)-1,pkWant); printf("tampered msg reject : %s\n", (!bad)?"[PASS]":"[FAIL]"); pass&=(!bad); }

    printf("\n%s\n", pass?"ALL PASS":"FAILURE");
    return pass?0:1;
}
