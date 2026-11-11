/*
Most of the code in this file implements the preprocessing algorithms presented in Figure 3 from the paper ``Pool: Pool: A Practical OT-based OPRF from Learning with Rounding".
The `main` function implements the algorithms from Figure 4 to have a working example of the online phase.

The nomenclature "Phase one" and "Phase two" refer to the two main phases of the preprocessing procedure, denoted (2) and (3) respectively in Figure 3.

Most functions have the same structure in that they implement either a sender or a receiver for a specific OT extender, and they are named accordingly.

The executable obtained from compiling this file allows to benchmark preprocessing phases using several different combination of OT extenders as building blocks.
Once all the different combinations are benchmarked, the executable proceeds to a final preprocessing phase followed by an execution of the online phase.

The code relies on the `libOTe` library for the OT primitives.

------------------------------------------------------------------------------------------------
Two-machine version.

The client and the server now run as separate processes, possibly on different machines:

    server machine:  ./oprf server 0.0.0.0     <port> [all|online] [num_rounds]
    client machine:  ./oprf client <server-ip> <port> [all|online] [num_rounds]
    single machine:  ./oprf local  127.0.0.1   <port> [all|online] [num_rounds]

`all` (default) first runs the alternative preprocessing benchmarks (benchmark_alt_preproc),
like the original binary; `online` skips them and only runs the preprocessing needed for the
online phase followed by the online phase.

Roles (as in the paper / the original comments): the client is the phase one sender and the
phase two receiver, the server is the phase one receiver and the phase two sender.

Networking: the libOTe/coproto AsioSocket (TCP, TCP_NODELAY) that the original code already
used, but with a single connection for the whole run (the server listens, the client connects)
instead of one localhost connection per phase. Before every measured phase both parties run a
1-byte barrier (not counted, not timed) so that both machines start timing at the same protocol
point. Byte counts come from the coproto socket counters and therefore include coproto's 8-byte
per-message header.

Online phase: in the original single-process code, Request, BlindEval and Finalize were executed
back to back in one process and the communication was computed analytically. Here the request
`(e_1, \bar{b}')` is actually sent from the client to the server and the answer
`(y_0, ..., y_{delta-1})` is sent back. Messages are bit-packed (lg_q bits per e_i, lg_delta bits
for \bar{b}', lg_p bits per y_i), i.e. their payload matches the analytic communication of the
paper (up to rounding to whole bytes). The server's key-dependent correction \bar{b} = b xor sk
(n bits) is sent once, at the end of the preprocessing.
------------------------------------------------------------------------------------------------
*/

#include "libOTe/Base/MasnyRindalKyber.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h"
#include "libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Silent/SilentOtExtSender.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"
#include "libOTe/Tools/Coproto.h"
#include "cryptoTools/Common/BitVector.h"
#include "coproto/Socket/AsioSocket.h"
#include "cryptoTools/Common/Timer.h"
#include <cryptoTools/Crypto/RandomOracle.h>

#include <algorithm>
#include <cstdlib>
#include "cryptoTools/Crypto/AES.h"
#include <array>
#include <ctime>
#include <iostream>
#include <string>
#include <thread>

/*
Parameters for the preprocessing.
Variable names are chosen to match the paper's notation. `lg_X` denotes the binary logarithm of `X`.
When changing the parameters, one should be careful to make sure that they are consistent.
For example, `tau` should be big enough for `num_rounds` of OPRF rounds to be executed in the online phase.

As is, the parameters allow to measure numbers used in Table 4 for `# evals` set at 2^13.
*/
const uint n = 482;
// number of preprocessed evaluations; in `batch` mode it is set to the batch size at runtime
uint tau = 1 << 16;
const uint lg_q = 12;
const uint q = 1 << lg_q;
const uint lg_lg_p = 3;
const uint lg_p = 1 << lg_lg_p;
const uint p = 1 << lg_p;
const uint lg_delta = lg_q - lg_p;
const uint delta = 1 << lg_delta;

// refer to appendix A of the paper for the definition of kappa
const uint kappa = 6144;

// base OT count for Silent OTs
const uint baseOtCount = 128;

// default number of OPRF rounds to execute in the online phase (can be overridden on the command line)
const uint default_num_rounds = 10;

// preprocessing for the online phase: Silent OT (default) or upstream's IKNP + KKRT; see below
bool silent_preproc = true;

// statistical security parameter for KKRT
const uint statisticalSecurityParam = 40;

// sizes of the online messages (bit-packed)
const uint request_bits = n * lg_q + lg_delta;
const uint request_bytes = (request_bits + 7) / 8;
const uint response_bits = delta * lg_p;
const uint response_bytes = (response_bits + 7) / 8;

using Clock = std::chrono::steady_clock;

/////////////////////////////////////////////////////////////////////////////////////////////////
// Networking / measurement helpers
/////////////////////////////////////////////////////////////////////////////////////////////////

// 1-byte ping-pong so that both parties start the next measured section together.
// Always executed outside of every timed/counted region.
void barrier(coproto::Socket &sock, bool isServer)
{
    osuCrypto::u8 token = 0;
    if (isServer)
    {
        coproto::sync_wait(sock.recv(token));
        coproto::sync_wait(sock.send(token));
    }
    else
    {
        coproto::sync_wait(sock.send(token));
        coproto::sync_wait(sock.recv(token));
    }
    coproto::sync_wait(sock.flush());
}

// coproto frames carry a 32-bit length, so one message must stay below 4 GiB (the 2^20 PSI request
// is ~12 GB). Large buffers are sent as consecutive 1 GiB messages; the receiver splits its
// (equally sized) buffer the same way. Payload is unchanged; each extra chunk adds an 8-byte header.
const size_t max_msg_bytes = size_t(1) << 30;

void send_chunked(coproto::Socket &sock, std::vector<osuCrypto::u8> &buf)
{
    for (size_t off = 0; off < buf.size(); off += max_msg_bytes)
    {
        osuCrypto::span<osuCrypto::u8> part(buf.data() + off, std::min(max_msg_bytes, buf.size() - off));
        coproto::sync_wait(sock.send(part));
    }
}

void recv_chunked(coproto::Socket &sock, std::vector<osuCrypto::u8> &buf)
{
    for (size_t off = 0; off < buf.size(); off += max_msg_bytes)
    {
        osuCrypto::span<osuCrypto::u8> part(buf.data() + off, std::min(max_msg_bytes, buf.size() - off));
        coproto::sync_wait(sock.recv(part));
    }
}

// Time and traffic of one phase, from one party's point of view.
struct PhaseStats
{
    long long ms = 0;
    size_t sent = 0;
    size_t recv = 0;

    PhaseStats operator+(const PhaseStats &o) const
    {
        return {ms + o.ms, sent + o.sent, recv + o.recv};
    }
};

// Snapshot of the socket byte counters, to measure the traffic of a single phase on a shared socket.
struct TrafficMeter
{
    coproto::Socket &sock;
    size_t sent0, recv0;
    explicit TrafficMeter(coproto::Socket &s) : sock(s), sent0(s.bytesSent()), recv0(s.bytesReceived()) {}
    size_t sent() const { return sock.bytesSent() - sent0; }
    size_t recv() const { return sock.bytesReceived() - recv0; }
};

void print_stats(const std::string &label, const PhaseStats &s)
{
    std::cout << label << " in " << s.ms << "ms, sent " << s.sent << " bytes and received " << s.recv << " bytes" << std::endl;
}

// LSB-first bit packing of values of arbitrary width (<= 32 bits).
class BitWriter
{
public:
    explicit BitWriter(std::vector<osuCrypto::u8> &out) : out_(out) { std::fill(out_.begin(), out_.end(), 0); }
    void put(uint64_t v, unsigned width)
    {
        acc_ |= (v & ((1ull << width) - 1)) << bits_;
        bits_ += width;
        while (bits_ >= 8)
        {
            out_[pos_++] = static_cast<osuCrypto::u8>(acc_);
            acc_ >>= 8;
            bits_ -= 8;
        }
    }
    void finish()
    {
        if (bits_)
            out_[pos_++] = static_cast<osuCrypto::u8>(acc_);
        acc_ = 0;
        bits_ = 0;
    }

private:
    std::vector<osuCrypto::u8> &out_;
    uint64_t acc_ = 0;
    unsigned bits_ = 0;
    size_t pos_ = 0;
};

class BitReader
{
public:
    explicit BitReader(const std::vector<osuCrypto::u8> &in) : in_(in) {}
    uint get(unsigned width)
    {
        while (bits_ < width)
        {
            acc_ |= static_cast<uint64_t>(in_[pos_++]) << bits_;
            bits_ += 8;
        }
        uint v = static_cast<uint>(acc_ & ((1ull << width) - 1));
        acc_ >>= width;
        bits_ -= width;
        return v;
    }
    // skip the padding bits up to the next byte boundary (counterpart of BitWriter::finish)
    void align()
    {
        acc_ = 0;
        bits_ = 0;
    }

private:
    const std::vector<osuCrypto::u8> &in_;
    uint64_t acc_ = 0;
    unsigned bits_ = 0;
    size_t pos_ = 0;
};

// Process CPU time (all threads) in milliseconds.
double cpu_ms()
{
    timespec ts;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
    return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
}

// Wall time, process CPU time and traffic of a whole phase, printed as a machine-readable line
// (same format as Leap's oprf-batch).
struct ResultMeter
{
    coproto::Socket &sock;
    Clock::time_point wall0;
    double cpu0;
    size_t sent0, recv0;
    explicit ResultMeter(coproto::Socket &s) : sock(s), wall0(Clock::now()), cpu0(cpu_ms()), sent0(s.bytesSent()), recv0(s.bytesReceived()) {}
    void report(const char *role, const char *phase, size_t batch, double compute_ms = -1)
    {
        double wall = std::chrono::duration<double, std::milli>(Clock::now() - wall0).count();
        std::cout << "RESULT protocol=pool preproc=" << (silent_preproc ? "silent" : "iknp") << " role=" << role
                  << " phase=" << phase << " batch=" << batch
                  << " wall_ms=" << wall << " cpu_ms=" << cpu_ms() - cpu0
                  << " sent=" << sock.bytesSent() - sent0 << " recv=" << sock.bytesReceived() - recv0;
        if (compute_ms >= 0)
            std::cout << " compute_ms=" << compute_ms;
        std::cout << std::endl;
    }
};

/////////////////////////////////////////////////////////////////////////////////////////////////
// Preprocessing for the online phase
/////////////////////////////////////////////////////////////////////////////////////////////////

// true (default): the paper's cheapest preprocessing, Silent OT in both phases:
//   phase one: n random OTs, each stretched with a PRG to all tau evaluations (the receiver's
//              choice bits b, which the key correction b_bar = b xor sk refers to, are the same
//              in every evaluation, so n OTs on PRG seeds suffice);
//   phase two: lg_delta random OTs per evaluation, turned into one random 1-out-of-delta OT
//              (Naor-Pinkas, below).
// false (POOL_PREPROC=iknp): upstream's online example, IKNP with n * tau OTs and KKRT.
// (silent_preproc is defined with the parameters at the top.)

uint low32(const osuCrypto::block &b)
{
    uint v;
    memcpy(&v, &b, sizeof(v));
    return v;
}

// One term of the 1-out-of-delta OT value for index k: a correlation-robust hash of the l-th
// random OT message m, tweaked by (l, k).
inline osuCrypto::block np_term(const osuCrypto::block &m, uint l, uint k)
{
    return osuCrypto::mAesFixedKey.hashBlock(m ^ osuCrypto::toBlock(l, k));
}

// Sender: from lg_delta random OTs (m_{l,0}, m_{l,1}) the delta values
// S[k] = xor_l H(m_{l, k_l}, l, k), k = sum_l k_l 2^l.
void np_sender(const std::array<osuCrypto::block, 2> *m, osuCrypto::block *S)
{
    for (uint k = 0; k < delta; k++)
    {
        osuCrypto::block acc = osuCrypto::ZeroBlock;
        for (uint l = 0; l < lg_delta; l++)
            acc = acc ^ np_term(m[l][(k >> l) & 1], l, k);
        S[k] = acc;
    }
}

// Receiver with random choice bits c_l and messages m_{l, c_l}: learns S[c] for c = sum_l c_l 2^l
// (and nothing about S[k], k != c: each such term uses a message it does not know).
uint np_receiver(const osuCrypto::BitVector &c, size_t offset, const osuCrypto::block *m, osuCrypto::block &out)
{
    uint k = 0;
    for (uint l = 0; l < lg_delta; l++)
        k |= uint(c[offset + l]) << l;
    osuCrypto::block acc = osuCrypto::ZeroBlock;
    for (uint l = 0; l < lg_delta; l++)
        acc = acc ^ np_term(m[l], l, k);
    out = acc;
    return k;
}

/////////////////////////////////////////////////////////////////////////////////////////////////
// Random oracle and plaintext PRF
/////////////////////////////////////////////////////////////////////////////////////////////////

// The random oracle H(x, j) -> Z_q^n that gives the LWR sample a.
// Upstream called RandomOracle(2n) and read 2n bytes from Final(), but BLAKE2b outputs at most
// 64 bytes, so only the first 32 coordinates were hash output and the rest was read past the end
// of the digest buffer (not a function of the input, so a second party cannot recompute it). Here
// BLAKE2b gives a 128-bit seed that the AES PRG expands to the n 16-bit samples.
void hash_to_a(osuCrypto::block x, osuCrypto::u64 j, uint *a)
{
    osuCrypto::RandomOracle ro(sizeof(osuCrypto::block));
    ro.Update(x);
    ro.Update(j);
    osuCrypto::block seed;
    ro.Final(seed);
    // n 16-bit samples fit in (2n + 15) / 16 = 61 AES blocks; 64 avoids a second refill
    osuCrypto::PRNG prng(seed, 64);
    std::array<osuCrypto::u16, n> samples;
    prng.get(samples.data(), n);
    for (uint i = 0; i < n; i++)
        a[i] = samples[i] & (q - 1);
}

// F_sk(a) = floor(<a, sk> / delta) mod p, in the clear (q = p * delta, both powers of two).
uint pool_prf(const osuCrypto::BitVector &sk, const uint *a)
{
    // n * (q - 1) < 2^32
    uint sum = 0;
    for (uint i = 0; i < n; i++)
        if (sk[i])
            sum += a[i];
    return (sum >> lg_delta) & (p - 1);
}

/////////////////////////////////////////////////////////////////////////////////////////////////
// PSI from the OPRF
/////////////////////////////////////////////////////////////////////////////////////////////////

// Every PSI element gets a 128-bit OPRF output: evals_per_element Pool evaluations of lg_p bits each,
// on the LWR samples a = H(x, 0), ..., H(x, evals_per_element - 1), all under the same key sk.
const uint psi_output_bits = 128;
const uint evals_per_element = (psi_output_bits + lg_p - 1) / lg_p;

struct PsiParams
{
    size_t client_size = 0;
    size_t server_size = 0;
    size_t intersection = 0;
};
PsiParams psi_params;

using Out128 = std::array<osuCrypto::u64, 2>;

// Synthetic sets, generated identically by both parties from fixed seeds (testing only).
// The client's first `intersection` elements are spread over the server set; the rest are fresh.
void make_psi_sets(const PsiParams &ps, std::vector<osuCrypto::block> &server, std::vector<osuCrypto::block> &client)
{
    osuCrypto::PRNG server_prng(osuCrypto::toBlock(0x505349, 1));
    server.resize(ps.server_size);
    server_prng.get(server.data(), server.size());
    osuCrypto::PRNG client_prng(osuCrypto::toBlock(0x505349, 2));
    client.resize(ps.client_size);
    for (size_t i = 0; i < ps.client_size; i++)
        client[i] = i < ps.intersection ? server[i * ps.server_size / ps.intersection] : client_prng.get<osuCrypto::block>();
}

// Packs the evals_per_element PRF values of one element (lg_p bits each) into 128 bits.
Out128 pack_output(const uint *z)
{
    unsigned __int128 acc = 0;
    for (uint j = 0; j < evals_per_element; j++)
        if (j * lg_p < 128)
            acc |= static_cast<unsigned __int128>(z[j]) << (j * lg_p);
    return {static_cast<osuCrypto::u64>(acc), static_cast<osuCrypto::u64>(acc >> 64)};
}

/////////////////////////////////////////////////////////////////////////////////////////////////
// Compact storage of the preprocessed correlations for the online phase
/////////////////////////////////////////////////////////////////////////////////////////////////

// Pool's online arithmetic is mod q = 2^lg_q or mod p = 2^lg_p, and it only ever reads the low 32
// bits of an OT value (then masks). Storing just the bits that matter (16 for phase one, 8 for
// phase two) keeps every computed value and message identical while cutting the memory of the
// materialized preprocessing 4-16x (upstream keeps one or two 16-byte blocks per value).
static_assert(lg_q <= 16 && lg_p <= 8 && lg_delta <= 8, "compact storage needs q <= 2^16, p <= 2^8");
using ClientOts = std::vector<std::array<osuCrypto::u16, 2>>; // client, phase one: (m_0, m_1) per (eval, i)
using ServerOts = std::vector<osuCrypto::u16>;                 // server, phase one: m_b per (eval, i)
using ServerTable = std::vector<osuCrypto::u8>;                // server, phase two: S[e][k] at e*delta + k
using ClientChoice = std::vector<osuCrypto::u8>;               // client, phase two: its index bpr[e]
using ClientValue = std::vector<osuCrypto::u8>;                // client, phase two: S[e][bpr[e]]

/////////////////////////////////////////////////////////////////////////////////////////////////
// Preprocessing building blocks.
// Phase one: sender = client, receiver = server.
// Phase two: sender = server, receiver = client.
/////////////////////////////////////////////////////////////////////////////////////////////////

// Phase one receiver using the IKNP OT extender.
// This phase one preprocessing implementation is used to obtain the random OTs that are used in the online phase.
PhaseStats phase_one_iknp_receive(coproto::Socket &sock, osuCrypto::BitVector &b, osuCrypto::AlignedUnVector<osuCrypto::block> &Rs_r)
{
    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());
    TrafficMeter meter(sock);
    auto start = Clock::now();

    // prepare IKNP OT extender
    osuCrypto::IknpOtExtReceiver receiver = osuCrypto::IknpOtExtReceiver{};
    std::vector<std::array<osuCrypto::block, 2>> baseOtSenderMsgs(receiver.baseOtCount());

    osuCrypto::MasnyRindalKyber baseOt;

    coproto::sync_wait(baseOt.send(baseOtSenderMsgs, prng, sock));
    receiver.setBaseOts(baseOtSenderMsgs);

    // onto actual OT

    // initialize bit vector `b` with repeated random bits
    osuCrypto::BitVector b_n(n);
    b_n.randomize(prng);
    for (int j = 0; j < tau; j++)
    {
        for (int i = 0; i < n; i++)
        {
            b[j * n + i] = b_n[i];
        }
    }

    // perform random OTs and write results to Rs_r
    coproto::sync_wait(receiver.receive(b, Rs_r, prng, sock));
    coproto::sync_wait(sock.flush());

    PhaseStats s{std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start).count(), meter.sent(), meter.recv()};
    print_stats("[Server] phase one iknp receiver", s);
    return s;
}

// Phase one sender using the IKNP OT extender.
// This phase one preprocessing implementation is used to obtain the random OTs that are used in the online phase.
PhaseStats phase_one_iknp_send(coproto::Socket &sock, osuCrypto::AlignedUnVector<std::array<osuCrypto::block, 2>> &Sc)
{
    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());
    TrafficMeter meter(sock);
    auto start = Clock::now();

    // prepare IKNP OT extender
    osuCrypto::IknpOtExtSender sender = osuCrypto::IknpOtExtSender{};

    osuCrypto::MasnyRindalKyber baseOt;

    osuCrypto::BitVector baseOtBv(sender.baseOtCount());
    baseOtBv.randomize(prng);

    std::vector<osuCrypto::block> baseOtRcvMsgs(sender.baseOtCount());

    coproto::sync_wait(baseOt.receive(baseOtBv, baseOtRcvMsgs, prng, sock));
    sender.setBaseOts(baseOtRcvMsgs, baseOtBv);

    // onto actual OT
    // perform random OTs and write the random OTs to Sc
    coproto::sync_wait(sender.send(Sc, prng, sock));
    coproto::sync_wait(sock.flush());

    PhaseStats s{std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start).count(), meter.sent(), meter.recv()};
    print_stats("[Client] phase one iknp sender", s);
    return s;
}

// Phase one receiver using the "unwasteful" IKNP OT extender.
// This phase one preprocessing implementation is benchmarked to obtain the numbers presented in the paper under IKNP.
PhaseStats phase_one_iknp_unwasteful_receive(coproto::Socket &sock, osuCrypto::BitVector &b, osuCrypto::AlignedUnVector<osuCrypto::block> &Rs_r)
{
    osuCrypto::Timer timer;

    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());
    TrafficMeter meter(sock);

    // prepare IKNP OT extender
    osuCrypto::IknpOtExtReceiver receiver = osuCrypto::IknpOtExtReceiver{};
    std::vector<std::array<osuCrypto::block, 2>> baseOtSenderMsgs(receiver.baseOtCount());

    osuCrypto::MasnyRindalKyber baseOt;
    osuCrypto::Timer::timeUnit baseOtStart = timer.setTimePoint("phase 1 iknp base ot start");

    coproto::sync_wait(baseOt.send(baseOtSenderMsgs, prng, sock));
    receiver.setBaseOts(baseOtSenderMsgs);

    osuCrypto::Timer::timeUnit baseOtEnd = timer.setTimePoint("phase 1 iknp base ot end");

    // onto actual OT
    osuCrypto::BitVector b_n(n);
    b_n.randomize(prng);
    for (int j = 0; j < kappa; j++)
    {
        for (int i = 0; i < n; i++)
        {
            b[j * n + i] = b_n[i];
        }
    }

    osuCrypto::Timer::timeUnit start = timer.setTimePoint("phase 1 iknp receive start");

    // perform random OTs and write results to Rs_r
    coproto::sync_wait(receiver.receive(b, Rs_r, prng, sock));
    coproto::sync_wait(sock.flush());

    osuCrypto::Timer::timeUnit end = timer.setTimePoint("phase 1 iknp receive end");
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(baseOtEnd - baseOtStart + end - start).count();

    PhaseStats s{ms, meter.sent(), meter.recv()};
    print_stats("[Server] phase one iknp unwasteful receiver", s);
    return s;
}

// Phase one sender using the "unwasteful" IKNP OT extender.
// This phase one preprocessing implementation is benchmarked to obtain the numbers presented in the paper under IKNP.
PhaseStats phase_one_iknp_unwasteful_send(coproto::Socket &sock, osuCrypto::AlignedUnVector<std::array<osuCrypto::block, 2>> &Sc)
{
    osuCrypto::Timer timer;

    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());
    TrafficMeter meter(sock);

    // prepare IKNP OT extender
    osuCrypto::IknpOtExtSender sender = osuCrypto::IknpOtExtSender{};

    osuCrypto::MasnyRindalKyber baseOt;

    osuCrypto::BitVector baseOtBv(sender.baseOtCount());
    baseOtBv.randomize(prng);

    std::vector<osuCrypto::block> baseOtRcvMsgs(sender.baseOtCount());

    osuCrypto::Timer::timeUnit baseOtStart = timer.setTimePoint("phase 1 iknp base ot start");

    coproto::sync_wait(baseOt.receive(baseOtBv, baseOtRcvMsgs, prng, sock));
    sender.setBaseOts(baseOtRcvMsgs, baseOtBv);

    osuCrypto::Timer::timeUnit baseOtEnd = timer.setTimePoint("phase 1 iknp base ot end");

    // onto actual OT
    osuCrypto::Timer::timeUnit start = timer.setTimePoint("phase 1 iknp send start");

    // perform random OTs and write the random OTs to Sc
    coproto::sync_wait(sender.send(Sc, prng, sock));
    coproto::sync_wait(sock.flush());

    osuCrypto::Timer::timeUnit end = timer.setTimePoint("phase 1 iknp send end");
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(baseOtEnd - baseOtStart + end - start).count();

    PhaseStats s{ms, meter.sent(), meter.recv()};
    print_stats("[Client] phase one iknp unwasteful sender", s);
    return s;
}

// Phase one receiver using the Silent OT extender.
// This phase one preprocessing implementation is benchmarked to obtain the numbers presented in the paper under Silent OT (n OTs).
PhaseStats phase_one_sot_receive(coproto::Socket &sock, osuCrypto::BitVector &b, osuCrypto::AlignedUnVector<osuCrypto::block> &Rs_r)
{
    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());
    TrafficMeter meter(sock);

    // prepare Silent OT extender
    std::vector<std::array<osuCrypto::block, 2>> baseOtSendMsgs(baseOtCount);

    osuCrypto::Timer timer;
    osuCrypto::Timer::timeUnit start = timer.setTimePoint("phase 1 silent ot receive start");

    osuCrypto::MasnyRindalKyber baseOt;
    coproto::sync_wait(baseOt.send(baseOtSendMsgs, prng, sock));

    osuCrypto::SilentOtExtReceiver receiver;
    receiver.setBaseOts(baseOtSendMsgs);
    receiver.configure(n, 2, 1, osuCrypto::SilentSecType::SemiHonest);

    // perform random OTs and write results to Rs_r
    coproto::sync_wait(receiver.silentReceive(b, Rs_r, prng, sock, osuCrypto::OTType::Random));
    coproto::sync_wait(sock.flush());

    osuCrypto::Timer::timeUnit end = timer.setTimePoint("phase 1 silent ot receive end");
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    PhaseStats s{ms, meter.sent(), meter.recv()};
    print_stats("[Server] phase one silent ot receiver", s);
    return s;
}

// Phase one sender using the Silent OT extender.
// This phase one preprocessing implementation is benchmarked to obtain the numbers presented in the paper under Silent OT (n OTs).
PhaseStats phase_one_sot_send(coproto::Socket &sock, osuCrypto::AlignedUnVector<std::array<osuCrypto::block, 2>> &Sc)
{
    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());
    TrafficMeter meter(sock);

    // prepare Silent OT extender
    osuCrypto::BitVector baseOtBv(baseOtCount);
    baseOtBv.randomize(prng);
    std::vector<osuCrypto::block> baseOtRecvMsgs(baseOtCount);

    osuCrypto::Timer timer;
    osuCrypto::Timer::timeUnit start = timer.setTimePoint("phase 1 silent ot send start");

    osuCrypto::MasnyRindalKyber baseOt;
    coproto::sync_wait(baseOt.receive(baseOtBv, baseOtRecvMsgs, prng, sock));

    osuCrypto::SilentOtExtSender sender;
    sender.configure(n, 2, 1, osuCrypto::SilentSecType::SemiHonest);
    sender.setBaseOts(baseOtRecvMsgs, baseOtBv);

    // perform random OTs and write the random OTs to Sc
    coproto::sync_wait(sender.silentSend(Sc, prng, sock));
    coproto::sync_wait(sock.flush());

    osuCrypto::Timer::timeUnit end = timer.setTimePoint("phase 1 silent ot send end");
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    PhaseStats s{ms, meter.sent(), meter.recv()};
    print_stats("[Client] phase one silent ot sender", s);
    return s;
}

// Phase one receiver using the Silent OT extender.
// This phase one preprocessing implementation is benchmarked to obtain the numbers presented in the paper under Silent OT (n * kappa OTs).
PhaseStats phase_one_sot_unwasteful_receive(coproto::Socket &sock, osuCrypto::BitVector &b, osuCrypto::AlignedUnVector<osuCrypto::block> &Rs_r)
{
    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());
    TrafficMeter meter(sock);

    // prepare Silent OT extender
    std::vector<std::array<osuCrypto::block, 2>> baseOtSendMsgs(baseOtCount);

    osuCrypto::Timer timer;
    osuCrypto::Timer::timeUnit start = timer.setTimePoint("phase 1 silent ot receive start");

    osuCrypto::MasnyRindalKyber baseOt;
    coproto::sync_wait(baseOt.send(baseOtSendMsgs, prng, sock));

    osuCrypto::SilentOtExtReceiver receiver;
    receiver.setBaseOts(baseOtSendMsgs);
    receiver.configure(n * kappa, 2, 1, osuCrypto::SilentSecType::SemiHonest);

    // perform random OTs and write results to Rs_r
    coproto::sync_wait(receiver.silentReceive(b, Rs_r, prng, sock, osuCrypto::OTType::Random));
    coproto::sync_wait(sock.flush());

    osuCrypto::Timer::timeUnit end = timer.setTimePoint("phase 1 silent ot receive end");
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    PhaseStats s{ms, meter.sent(), meter.recv()};
    print_stats("[Server] phase one silent ot unwasteful receiver", s);
    return s;
}

// Phase one sender using the Silent OT extender.
// This phase one preprocessing implementation is benchmarked to obtain the numbers presented in the paper under Silent OT (n * kappa OTs).
PhaseStats phase_one_sot_unwasteful_send(coproto::Socket &sock, osuCrypto::AlignedUnVector<std::array<osuCrypto::block, 2>> &Sc)
{
    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());
    TrafficMeter meter(sock);

    // prepare Silent OT extender
    osuCrypto::BitVector baseOtBv(baseOtCount);
    baseOtBv.randomize(prng);
    std::vector<osuCrypto::block> baseOtRecvMsgs(baseOtCount);

    osuCrypto::Timer timer;
    osuCrypto::Timer::timeUnit start = timer.setTimePoint("phase 1 silent ot send start");

    osuCrypto::MasnyRindalKyber baseOt;
    coproto::sync_wait(baseOt.receive(baseOtBv, baseOtRecvMsgs, prng, sock));

    osuCrypto::SilentOtExtSender sender;
    sender.configure(n * kappa, 2, 1, osuCrypto::SilentSecType::SemiHonest);
    sender.setBaseOts(baseOtRecvMsgs, baseOtBv);

    // perform random OTs and write the random OTs to Sc
    coproto::sync_wait(sender.silentSend(Sc, prng, sock));
    coproto::sync_wait(sock.flush());

    osuCrypto::Timer::timeUnit end = timer.setTimePoint("phase 1 silent ot send end");
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    PhaseStats s{ms, meter.sent(), meter.recv()};
    print_stats("[Client] phase one silent ot unwasteful sender", s);
    return s;
}

// Phase two receiver using the KKRT OT extender.
// This phase two preprocessing implementation is used to obtain the random OTs that are used in the online phase.
PhaseStats phase_two_kkrt_receive(coproto::Socket &sock, std::vector<osuCrypto::u64> &bpr, osuCrypto::AlignedVector<osuCrypto::block> &Rc_r)
{
    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());
    TrafficMeter meter(sock);
    auto startTime = Clock::now();

    osuCrypto::KkrtNcoOtReceiver receiver;

    auto receiveRoutine = [&]() -> coproto::task<>
    {
        receiver.configure(false, statisticalSecurityParam, lg_delta);

        co_await (receiver.init(tau, prng, sock));

        int step = 1 << 10; // iterate over 2^10 OTs at a time before sending a correction.
        int i;

        for (i = 0; i < tau;)
        {
            int min = std::min<osuCrypto::u64>(tau - i, step);
            for (int j = 0; j < min; j++, i++)
            {
                bpr[i] = static_cast<osuCrypto::u64>(prng.get<osuCrypto::u8>() & (delta - 1));
                receiver.encode(i, &bpr[i], &Rc_r[i]);
            }

            co_await (receiver.sendCorrection(sock, min));
        }

        co_await (receiver.check(sock, prng.get()));

        co_await (sock.flush());
    };

    coproto::sync_wait(receiveRoutine());

    PhaseStats s{std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - startTime).count(), meter.sent(), meter.recv()};
    print_stats("[Client] phase two kkrt receiver", s);
    return s;
}

// Phase two sender using the KKRT OT extender.
// This phase two preprocessing implementation is used to obtain the random OTs that are used in the online phase.
PhaseStats phase_two_kkrt_send(coproto::Socket &sock, osuCrypto::Matrix<osuCrypto::block> &Ss)
{
    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());
    TrafficMeter meter(sock);
    auto startTime = Clock::now();

    osuCrypto::KkrtNcoOtSender sender;

    auto sendRoutine = [&]() -> coproto::task<>
    {
        sender.configure(false, statisticalSecurityParam, lg_delta);

        co_await (sender.init(tau, prng, sock));

        int step = 1 << 10; // iterate over 2^10 OTs at a time before sending a correction.
        int i;

        for (i = 0; i < tau;)
        {
            int min = std::min<osuCrypto::u64>(tau - i, step);

            co_await (sender.recvCorrection(sock, min));

            for (int j = 0; j < min; j++, i++)
            {
                for (int k = 0; k < delta; k++)
                {
                    osuCrypto::block choice = static_cast<osuCrypto::block>(k);
                    sender.encode(i, &choice, &Ss[i][k]);
                }
            }
        }
        co_await (sender.check(sock, osuCrypto::ZeroBlock));

        co_await (sock.flush());
    };

    coproto::sync_wait(sendRoutine());

    PhaseStats s{std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - startTime).count(), meter.sent(), meter.recv()};
    print_stats("[Server] phase two kkrt sender", s);
    return s;
}

// Phase two receiver using the IKNP OT extender.
// This phase two preprocessing implementation is benchmarked to obtain the numbers presented in the paper under IKNP.
PhaseStats phase_two_iknp_receive(coproto::Socket &sock, osuCrypto::BitVector &b, osuCrypto::AlignedUnVector<osuCrypto::block> &Rs_r)
{
    osuCrypto::Timer timer;

    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());
    TrafficMeter meter(sock);

    // prepare IKNP OT extender
    osuCrypto::IknpOtExtReceiver receiver = osuCrypto::IknpOtExtReceiver{};
    std::vector<std::array<osuCrypto::block, 2>> baseOtSenderMsgs(receiver.baseOtCount());

    osuCrypto::MasnyRindalKyber baseOt;

    osuCrypto::Timer::timeUnit baseOtStart = timer.setTimePoint("phase 2 iknp base ot start");

    coproto::sync_wait(baseOt.send(baseOtSenderMsgs, prng, sock));
    receiver.setBaseOts(baseOtSenderMsgs);

    osuCrypto::Timer::timeUnit baseOtEnd = timer.setTimePoint("phase 2 iknp base ot end");

    // onto actual OT

    b.randomize(prng);

    osuCrypto::Timer::timeUnit start = timer.setTimePoint("phase 2 iknp receive start");

    // perform random OTs and write results to Rs_r
    coproto::sync_wait(receiver.receive(b, Rs_r, prng, sock));
    coproto::sync_wait(sock.flush());

    osuCrypto::Timer::timeUnit end = timer.setTimePoint("phase 2 iknp receive end");
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(baseOtEnd - baseOtStart + end - start).count();

    PhaseStats s{ms, meter.sent(), meter.recv()};
    print_stats("[Client] phase two iknp receiver", s);
    return s;
}

// Phase two sender using the IKNP OT extender.
// This phase two preprocessing implementation is benchmarked to obtain the numbers presented in the paper under IKNP.
PhaseStats phase_two_iknp_send(coproto::Socket &sock, osuCrypto::AlignedUnVector<std::array<osuCrypto::block, 2>> &Sc)
{
    osuCrypto::Timer timer;

    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());
    TrafficMeter meter(sock);

    // prepare IKNP OT extender
    osuCrypto::IknpOtExtSender sender = osuCrypto::IknpOtExtSender{};

    osuCrypto::MasnyRindalKyber baseOt;

    osuCrypto::BitVector baseOtBv(sender.baseOtCount());
    baseOtBv.randomize(prng);

    std::vector<osuCrypto::block> baseOtRcvMsgs(sender.baseOtCount());

    osuCrypto::Timer::timeUnit baseOtStart = timer.setTimePoint("phase 2 iknp base ot start");

    coproto::sync_wait(baseOt.receive(baseOtBv, baseOtRcvMsgs, prng, sock));
    sender.setBaseOts(baseOtRcvMsgs, baseOtBv);

    osuCrypto::Timer::timeUnit baseOtEnd = timer.setTimePoint("phase 2 iknp base ot end");

    // onto actual OT
    osuCrypto::Timer::timeUnit start = timer.setTimePoint("phase 2 iknp send start");

    // perform random OTs and write the random OTs to Sc
    coproto::sync_wait(sender.send(Sc, prng, sock));
    coproto::sync_wait(sock.flush());

    osuCrypto::Timer::timeUnit end = timer.setTimePoint("phase 2 iknp send end");
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(baseOtEnd - baseOtStart + end - start).count();

    PhaseStats s{ms, meter.sent(), meter.recv()};
    print_stats("[Server] phase two iknp sender", s);
    return s;
}

// Phase two receiver using the Silent OT extender.
// This phase two preprocessing implementation is benchmarked to obtain the numbers presented in the paper under Silent OT (n OTs and n * kappa OTs).
PhaseStats phase_two_sot_receive(coproto::Socket &sock, osuCrypto::BitVector &b, osuCrypto::AlignedUnVector<osuCrypto::block> &Rs_r)
{
    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());
    TrafficMeter meter(sock);

    // prepare Silent OT extender
    std::vector<std::array<osuCrypto::block, 2>> baseOtSendMsgs(baseOtCount);

    osuCrypto::Timer timer;
    osuCrypto::Timer::timeUnit start = timer.setTimePoint("phase 2 silent ot receive start");

    osuCrypto::MasnyRindalKyber baseOt;
    coproto::sync_wait(baseOt.send(baseOtSendMsgs, prng, sock));

    osuCrypto::SilentOtExtReceiver receiver;
    receiver.setBaseOts(baseOtSendMsgs);
    receiver.configure(lg_delta * tau, 2, 1, osuCrypto::SilentSecType::SemiHonest);

    // perform random OTs and write results to Rs_r
    coproto::sync_wait(receiver.silentReceive(b, Rs_r, prng, sock, osuCrypto::OTType::Random));
    coproto::sync_wait(sock.flush());

    osuCrypto::Timer::timeUnit end = timer.setTimePoint("phase 2 silent ot receive end");
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    PhaseStats s{ms, meter.sent(), meter.recv()};
    print_stats("[Client] phase two silent ot receiver", s);
    return s;
}

// Phase two sender using the Silent OT extender.
// This phase two preprocessing implementation is benchmarked to obtain the numbers presented in the paper under Silent OT (n OTs and n * kappa OTs).
PhaseStats phase_two_sot_send(coproto::Socket &sock, osuCrypto::AlignedUnVector<std::array<osuCrypto::block, 2>> &Sc)
{
    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());
    TrafficMeter meter(sock);

    // prepare Silent OT extender

    osuCrypto::BitVector baseOtBv(baseOtCount);
    baseOtBv.randomize(prng);
    std::vector<osuCrypto::block> baseOtRecvMsgs(baseOtCount);

    osuCrypto::Timer timer;
    osuCrypto::Timer::timeUnit start = timer.setTimePoint("phase 2 silent ot send start");

    osuCrypto::MasnyRindalKyber baseOt;
    coproto::sync_wait(baseOt.receive(baseOtBv, baseOtRecvMsgs, prng, sock));

    osuCrypto::SilentOtExtSender sender;
    sender.configure(lg_delta * tau, 2, 1, osuCrypto::SilentSecType::SemiHonest);
    sender.setBaseOts(baseOtRecvMsgs, baseOtBv);

    // perform random OTs and write the random OTs to Sc
    coproto::sync_wait(sender.silentSend(Sc, prng, sock));
    coproto::sync_wait(sock.flush());

    osuCrypto::Timer::timeUnit end = timer.setTimePoint("phase 2 silent ot send end");
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    PhaseStats s{ms, meter.sent(), meter.recv()};
    print_stats("[Server] phase two silent ot sender", s);
    return s;
}

/////////////////////////////////////////////////////////////////////////////////////////////////
// Alternative preprocessing benchmarks
/////////////////////////////////////////////////////////////////////////////////////////////////

// contains examples for all preprocessing procedures.
// these procedures were used to obtain the preprocessing measures given in the paper.
// client complexity is phase one sender + phase two receiver, and vice-versa for the server complexity.
// In the two-machine version each party only runs (and allocates) its own side, and prints its own totals.
void benchmark_alt_preproc(coproto::Socket &sock, bool isServer)
{
    const char *tag = isServer ? "[Server]" : "[Client]";
    std::cout << tag << " Benchmarking alternative preprocessing procedures..." << std::endl;

    PhaseStats p1_iknp, p2_iknp, p1_sot_n, ext_sot_n, p2_sot_n, p1_sot_nk, p2_sot_nk;

    // "unwasteful" IKNP phase one
    std::cout << "\n" << tag << " Benchmarking for phase one of preprocessing with \"unwasteful\" IKNP..." << std::endl;
    if (isServer)
    {
        osuCrypto::BitVector b(n * kappa);
        osuCrypto::AlignedUnVector<osuCrypto::block> Rs_r(n * kappa);
        barrier(sock, isServer);
        p1_iknp = phase_one_iknp_unwasteful_receive(sock, b, Rs_r);
    }
    else
    {
        osuCrypto::AlignedUnVector<std::array<osuCrypto::block, 2>> Sc(n * kappa);
        barrier(sock, isServer);
        p1_iknp = phase_one_iknp_unwasteful_send(sock, Sc);
    }

    // Naor-Pinkas phase two with IKNP
    std::cout << "\n" << tag << " Benchmarking for phase two of preprocessing with IKNP/Naor-Pinkas..." << std::endl;
    if (isServer)
    {
        osuCrypto::AlignedUnVector<std::array<osuCrypto::block, 2>> Sc(lg_delta * tau);
        barrier(sock, isServer);
        p2_iknp = phase_two_iknp_send(sock, Sc);
    }
    else
    {
        osuCrypto::BitVector b(lg_delta * tau);
        osuCrypto::AlignedUnVector<osuCrypto::block> Rs_r(lg_delta * tau);
        barrier(sock, isServer);
        p2_iknp = phase_two_iknp_receive(sock, b, Rs_r);
    }

    // phase one with Silent OT (n) + local extension to n * kappa values
    std::cout << "\n\n" << tag << " Benchmarking for phase one of preprocessing with Silent OT (n OTs)..." << std::endl;
    if (isServer)
    {
        osuCrypto::BitVector b_n(n);
        osuCrypto::AlignedUnVector<osuCrypto::block> Rs_r_n(n);
        barrier(sock, isServer);
        p1_sot_n = phase_one_sot_receive(sock, b_n, Rs_r_n);

        // extension of phase 1 OT results to n * kappa useful values (receiver side)
        std::cout << tag << " Extending phase one results..." << std::endl;
        auto startExt = Clock::now();
        osuCrypto::BitVector b(n * kappa);
        osuCrypto::AlignedUnVector<osuCrypto::block> Rs_r(n * kappa);
        for (int i = 0; i < n; i++)
        {
            osuCrypto::PRNG prng_res(Rs_r_n[i]);
            for (int j = 0; j < kappa; j++)
            {
                b[j * n + i] = b_n[i];
                Rs_r[j * n + i] = prng_res.get<osuCrypto::block>();
            }
        }
        ext_sot_n.ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - startExt).count();
        std::cout << tag << " Extension took " << ext_sot_n.ms << "ms" << std::endl;
    }
    else
    {
        osuCrypto::AlignedUnVector<std::array<osuCrypto::block, 2>> Sc_n(n);
        barrier(sock, isServer);
        p1_sot_n = phase_one_sot_send(sock, Sc_n);

        // extension of phase 1 OT results to n * kappa useful values (sender side)
        std::cout << tag << " Extending phase one results..." << std::endl;
        auto startExt = Clock::now();
        osuCrypto::AlignedUnVector<std::array<osuCrypto::block, 2>> Sc(n * kappa);
        for (int i = 0; i < n; i++)
        {
            osuCrypto::PRNG prng_msg_0(Sc_n[i][0]);
            osuCrypto::PRNG prng_msg_1(Sc_n[i][1]);
            for (int j = 0; j < kappa; j++)
            {
                Sc[j * n + i][0] = prng_msg_0.get<osuCrypto::block>();
                Sc[j * n + i][1] = prng_msg_1.get<osuCrypto::block>();
            }
        }
        ext_sot_n.ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - startExt).count();
        std::cout << tag << " Extension took " << ext_sot_n.ms << "ms" << std::endl;
    }

    // Naor-Pinkas phase two with Silent OT
    std::cout << "\n" << tag << " Benchmarking for phase two of preprocessing with Silent OT/Naor-Pinkas..." << std::endl;
    if (isServer)
    {
        osuCrypto::AlignedUnVector<std::array<osuCrypto::block, 2>> Sc(lg_delta * tau);
        barrier(sock, isServer);
        p2_sot_n = phase_two_sot_send(sock, Sc);
    }
    else
    {
        osuCrypto::BitVector b(lg_delta * tau);
        osuCrypto::AlignedUnVector<osuCrypto::block> Rs_r(lg_delta * tau);
        barrier(sock, isServer);
        p2_sot_n = phase_two_sot_receive(sock, b, Rs_r);
    }

    // phase one with Silent OT (n * kappa)
    std::cout << "\n\n" << tag << " Benchmarking for phase one of preprocessing with Silent OT (n * kappa OTs)..." << std::endl;
    if (isServer)
    {
        osuCrypto::BitVector b(n * kappa);
        osuCrypto::AlignedUnVector<osuCrypto::block> Rs_r(n * kappa);
        barrier(sock, isServer);
        p1_sot_nk = phase_one_sot_unwasteful_receive(sock, b, Rs_r);
    }
    else
    {
        osuCrypto::AlignedUnVector<std::array<osuCrypto::block, 2>> Sc(n * kappa);
        barrier(sock, isServer);
        p1_sot_nk = phase_one_sot_unwasteful_send(sock, Sc);
    }

    // Naor-Pinkas phase two with Silent OT
    std::cout << "\n" << tag << " Benchmarking for phase two of preprocessing with Silent OT/Naor-Pinkas..." << std::endl;
    if (isServer)
    {
        osuCrypto::AlignedUnVector<std::array<osuCrypto::block, 2>> Sc(lg_delta * tau);
        barrier(sock, isServer);
        p2_sot_nk = phase_two_sot_send(sock, Sc);
    }
    else
    {
        osuCrypto::BitVector b(lg_delta * tau);
        osuCrypto::AlignedUnVector<osuCrypto::block> Rs_r(lg_delta * tau);
        barrier(sock, isServer);
        p2_sot_nk = phase_two_sot_receive(sock, b, Rs_r);
    }

    std::cout << "\n" << tag << " Preprocessing totals for this party (phase one + phase two):" << std::endl;
    print_stats(std::string(tag) + "   IKNP                   ", p1_iknp + p2_iknp);
    print_stats(std::string(tag) + "   Silent OT (n)          ", p1_sot_n + ext_sot_n + p2_sot_n);
    print_stats(std::string(tag) + "   Silent OT (n * kappa)  ", p1_sot_nk + p2_sot_nk);
}


/////////////////////////////////////////////////////////////////////////////////////////////////
// Preprocessing + online phase (Figure 4), client side
/////////////////////////////////////////////////////////////////////////////////////////////////
// online: per-query round trips; batch: all evaluations in one round trip; psi: PSI on top of batch
enum class OnlineMode
{
    PerQuery,
    Batch,
    Psi
};

int online_client_batch(coproto::Socket &sock, ClientOts &Sc_uint, ClientChoice &bpr,
                        ClientValue &Rc_r, osuCrypto::BitVector &b_bar, uint batch);
int online_client_psi(coproto::Socket &sock, ClientOts &Sc_uint, ClientChoice &bpr,
                      ClientValue &Rc_r, osuCrypto::BitVector &b_bar);

int run_client(coproto::Socket &sock, bool alt, uint num_rounds, OnlineMode mode)
{
    // The following is for benchmarking purposes only.
    if (alt)
        benchmark_alt_preproc(sock, false);

    std::cout << "\n\n[Client] Computing preprocessing for online example..." << std::endl;
    barrier(sock, false);
    ResultMeter offline_meter(sock);

    // phase one (client = sender), followed by parsing of the values from the OTs
    ClientOts Sc_uint(size_t(n) * tau);
    PhaseStats pre1;
    if (silent_preproc)
    {
        // n random OTs, stretched to tau evaluations with a PRG (only the low 32 bits are used)
        osuCrypto::AlignedUnVector<std::array<osuCrypto::block, 2>> Sc_n(n);
        barrier(sock, false);
        pre1 = phase_one_sot_send(sock, Sc_n);
        auto start = Clock::now();
        for (uint i = 0; i < n; i++)
        {
            osuCrypto::PRNG prng0(Sc_n[i][0]);
            osuCrypto::PRNG prng1(Sc_n[i][1]);
            for (size_t j = 0; j < tau; j++)
            {
                Sc_uint[j * n + i][0] = static_cast<osuCrypto::u16>(low32(prng0.get<osuCrypto::block>()));
                Sc_uint[j * n + i][1] = static_cast<osuCrypto::u16>(low32(prng1.get<osuCrypto::block>()));
            }
        }
        long long ext_ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start).count();
        std::cout << "[Client] phase one PRG extension in " << ext_ms << "ms" << std::endl;
        pre1.ms += ext_ms;
    }
    else
    {
        osuCrypto::AlignedUnVector<std::array<osuCrypto::block, 2>> Sc(n * tau);
        barrier(sock, false);
        pre1 = phase_one_iknp_send(sock, Sc);

        // parse values from OTs
        for (int i = 0; i < n * tau; i++)
        {
            int32_t arr0[4];
            memcpy(arr0, &Sc[i][0], sizeof(arr0));
            int32_t arr1[4];
            memcpy(arr1, &Sc[i][1], sizeof(arr1));

            Sc_uint[i][0] = static_cast<osuCrypto::u16>(arr0[0]);
            Sc_uint[i][1] = static_cast<osuCrypto::u16>(arr1[0]);
        }
    }

    // phase two (client = receiver)
    ClientChoice bpr(tau);
    ClientValue Rc_r(tau);
    PhaseStats pre2;
    if (silent_preproc)
    {
        osuCrypto::BitVector c(lg_delta * tau);
        osuCrypto::AlignedUnVector<osuCrypto::block> R(lg_delta * tau);
        barrier(sock, false);
        pre2 = phase_two_sot_receive(sock, c, R);
        auto start = Clock::now();
        for (size_t e = 0; e < tau; e++)
        {
            osuCrypto::block value;
            bpr[e] = static_cast<osuCrypto::u8>(np_receiver(c, e * lg_delta, &R[e * lg_delta], value));
            Rc_r[e] = static_cast<osuCrypto::u8>(low32(value));
        }
        long long np_ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start).count();
        std::cout << "[Client] phase two Naor-Pinkas conversion in " << np_ms << "ms" << std::endl;
        pre2.ms += np_ms;
    }
    else
    {
        std::vector<osuCrypto::u64> bpr64(tau);
        osuCrypto::AlignedVector<osuCrypto::block> rc(tau);
        barrier(sock, false);
        pre2 = phase_two_kkrt_receive(sock, bpr64, rc);
        for (size_t e = 0; e < tau; e++)
        {
            bpr[e] = static_cast<osuCrypto::u8>(bpr64[e]);
            Rc_r[e] = static_cast<osuCrypto::u8>(low32(rc[e]));
        }
    }

    // receive the key-dependent correction \bar{b} = b xor sk from the server (n bits, once)
    osuCrypto::BitVector b_bar(n);
    barrier(sock, false);
    PhaseStats pre3;
    {
        TrafficMeter meter(sock);
        auto start = Clock::now();
        osuCrypto::span<osuCrypto::u8> b_bar_span(b_bar.data(), b_bar.sizeBytes());
        coproto::sync_wait(sock.recv(b_bar_span));
        pre3 = {std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start).count(), meter.sent(), meter.recv()};
        print_stats("[Client] key correction (b_bar) receive", pre3);
    }
    print_stats("[Client] preprocessing total for the online example", pre1 + pre2 + pre3);
    offline_meter.report("client", "offline", mode == OnlineMode::Psi ? psi_params.client_size : tau);

    if (mode == OnlineMode::Batch)
        return online_client_batch(sock, Sc_uint, bpr, Rc_r, b_bar, num_rounds);
    if (mode == OnlineMode::Psi)
        return online_client_psi(sock, Sc_uint, bpr, Rc_r, b_bar);

    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());

    // State variable `ctr` depicted in Figure 4 - Request.
    uint ctr = 0;

    std::cout << "\n[Client] Computing " << num_rounds << " evaluations of the Pool OPRF..." << std::endl;

    // Analytic communication complexity for one round of the Pool OPRF (as in the original code):
    // n * lg_q + lg_delta for the output values `(e_1, ..., e_n), \bar{b}'` of the `Request` phase (Fig. 4). We do not account for session-specific values.
    // delta * p for the output values `y_0, ..., y_{delta-1}` of the `BlindEval` phase (Fig. 4). Again, we ignore the session-specific values (e.g., `uid, ctr`).
    uint comm_compl = (n * lg_q + lg_delta + delta * lg_p) / 8;

    std::vector<osuCrypto::u8> request(request_bytes);
    std::vector<osuCrypto::u8> response(response_bytes);

    // kept only for the correctness check after the benchmark
    std::vector<std::vector<uint>> a_log;
    std::vector<uint> z_log;

    double sum_client_mus = 0, sum_latency_mus = 0;

    barrier(sock, false);
    TrafficMeter online_meter(sock);

    for (int round = 0; round < num_rounds; round++)
    {
        // Request (Fig. 4)
        auto req_start = Clock::now();

        // seeds for the random oracle. can be user-provided.
        int64_t t = prng.get<int64_t>();
        int64_t x = prng.get<int64_t>();

        osuCrypto::AlignedVector<uint> a(n);
        osuCrypto::AlignedVector<uint> e_0(n);
        osuCrypto::AlignedVector<uint> e_1(n);

        // need a larger type if n*(q-1) > uint::MAX
        uint c_sum = 0;

        hash_to_a(osuCrypto::toBlock(t, x), 0, a.data());

        for (int i = 0; i < n; i++)
        {
            e_0[i] = 0;

            uint c_i = (e_0[i] - (Sc_uint[(ctr * n) + i][b_bar[i]])) & (q - 1);
            e_1[i] = (a[i] + c_i + Sc_uint[(ctr * n) + i][1 - b_bar[i]]) & (q - 1);

            c_sum += c_i;
        }

        c_sum = c_sum & (q - 1);

        uint bpr_bar = ((c_sum & (delta - 1)) - bpr[ctr]) & (delta - 1);

        // serialize the request (e_0 is implicitly 0 and is not sent)
        {
            BitWriter w(request);
            for (int i = 0; i < n; i++)
                w.put(e_1[i], lg_q);
            w.put(bpr_bar, lg_delta);
            w.finish();
        }

        auto req_end = Clock::now();

        // send the request, wait for BlindEval's answer
        coproto::sync_wait(sock.send(request));
        coproto::sync_wait(sock.recv(response));

        auto resp_received = Clock::now();

        // Finalize (Fig. 4)
        osuCrypto::AlignedVector<uint> y(delta);
        {
            BitReader r(response);
            for (int i = 0; i < delta; i++)
                y[i] = r.get(lg_p);
        }

        uint Rc_r_uint = Rc_r[ctr];

        uint y_c_sum_mod_delta = y[c_sum & (delta - 1)];

        uint y_final = (y_c_sum_mod_delta - Rc_r_uint);
        uint temp_val = ((c_sum - (c_sum & (delta - 1))) >> lg_delta);

        uint z = (y_final - temp_val) & (p - 1);

        auto end = Clock::now();
        auto client_mus = std::chrono::duration_cast<std::chrono::microseconds>(end - resp_received + req_end - req_start).count();
        auto latency_mus = std::chrono::duration_cast<std::chrono::microseconds>(end - req_start).count();
        sum_client_mus += client_mus;
        sum_latency_mus += latency_mus;

        std::cout << "[Client] Result: " << z << " computed in " << client_mus << "µs of client computation, "
                  << latency_mus << "µs end-to-end latency (incl. network and server)" << std::endl;

        a_log.emplace_back(a.begin(), a.end());
        z_log.push_back(z);
        ctr++;
    }

    size_t online_sent = online_meter.sent();
    size_t online_recv = online_meter.recv();

    // Sanity check, outside of all measurements: the server reveals sk *for testing only*.
    osuCrypto::BitVector sk(n);
    osuCrypto::span<osuCrypto::u8> sk_span(sk.data(), sk.sizeBytes());
    coproto::sync_wait(sock.recv(sk_span));
    int failures = 0;
    for (size_t r = 0; r < z_log.size(); r++)
    {
        uint eval_z = 0;
        for (int i = 0; i < n; i++)
        {
            if (sk[i])
            {
                eval_z += a_log[r][i];
            }
        }
        eval_z = ((eval_z) >> lg_delta) & (p - 1);
        // checks that the computed value matches the expected value.
        failures += (eval_z != z_log[r]);
    }

    std::cout << "\n===== [Client] online summary over " << num_rounds << " evaluation(s) =====\n"
              << "  avg client computation:  " << sum_client_mus / num_rounds << " us\n"
              << "  avg end-to-end latency:  " << sum_latency_mus / num_rounds << " us\n"
              << "  traffic per evaluation:  sent " << online_sent / num_rounds << " B, received "
              << online_recv / num_rounds << " B (measured, incl. 8B coproto header per message)\n"
              << "  payload per evaluation:  request " << request_bytes << " B, response " << response_bytes
              << " B (analytic: " << comm_compl << " B)\n"
              << "  correctness failures:    " << failures << std::endl;

    coproto::sync_wait(sock.flush());
    return failures ? 1 : 0;
}

/////////////////////////////////////////////////////////////////////////////////////////////////
// Preprocessing + online phase (Figure 4), server side
/////////////////////////////////////////////////////////////////////////////////////////////////
int online_server_batch(coproto::Socket &sock, ServerOts &Rs_r,
                        ServerTable &Ss, osuCrypto::BitVector &sk, uint batch);
int online_server_psi(coproto::Socket &sock, ServerOts &Rs_r,
                      ServerTable &Ss, osuCrypto::BitVector &sk);

int run_server(coproto::Socket &sock, bool alt, uint num_rounds, OnlineMode mode)
{
    // The following is for benchmarking purposes only.
    if (alt)
        benchmark_alt_preproc(sock, true);

    std::cout << "\n\n[Server] Computing preprocessing for online example..." << std::endl;
    barrier(sock, true);
    ResultMeter offline_meter(sock);

    // phase one (server = receiver); only the first n choice bits are used (they repeat)
    osuCrypto::BitVector b;
    ServerOts Rs_r(size_t(n) * tau);
    PhaseStats pre1;
    if (silent_preproc)
    {
        b.resize(n);
        osuCrypto::AlignedUnVector<osuCrypto::block> Rs_r_n(n);
        barrier(sock, true);
        pre1 = phase_one_sot_receive(sock, b, Rs_r_n);
        auto start = Clock::now();
        for (uint i = 0; i < n; i++)
        {
            osuCrypto::PRNG prng_res(Rs_r_n[i]);
            for (size_t j = 0; j < tau; j++)
                Rs_r[j * n + i] = static_cast<osuCrypto::u16>(low32(prng_res.get<osuCrypto::block>()));
        }
        long long ext_ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start).count();
        std::cout << "[Server] phase one PRG extension in " << ext_ms << "ms" << std::endl;
        pre1.ms += ext_ms;
    }
    else
    {
        b.resize(n * tau);
        osuCrypto::AlignedUnVector<osuCrypto::block> rs(size_t(n) * tau);
        barrier(sock, true);
        pre1 = phase_one_iknp_receive(sock, b, rs);
        for (size_t i = 0; i < rs.size(); i++)
            Rs_r[i] = static_cast<osuCrypto::u16>(low32(rs[i]));
    }

    // phase two (server = sender)
    ServerTable Ss(size_t(tau) * delta);
    PhaseStats pre2;
    if (silent_preproc)
    {
        osuCrypto::AlignedUnVector<std::array<osuCrypto::block, 2>> P(lg_delta * tau);
        barrier(sock, true);
        pre2 = phase_two_sot_send(sock, P);
        auto start = Clock::now();
        for (size_t e = 0; e < tau; e++)
        {
            std::array<osuCrypto::block, delta> row;
            np_sender(&P[e * lg_delta], row.data());
            for (uint k = 0; k < delta; k++)
                Ss[e * delta + k] = static_cast<osuCrypto::u8>(low32(row[k]));
        }
        long long np_ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start).count();
        std::cout << "[Server] phase two Naor-Pinkas conversion in " << np_ms << "ms" << std::endl;
        pre2.ms += np_ms;
    }
    else
    {
        osuCrypto::Matrix<osuCrypto::block> ss(tau, delta);
        barrier(sock, true);
        pre2 = phase_two_kkrt_send(sock, ss);
        for (size_t e = 0; e < tau; e++)
            for (uint k = 0; k < delta; k++)
                Ss[e * delta + k] = static_cast<osuCrypto::u8>(low32(ss[e][k]));
    }

    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());

    // sample secret key and send the correction \bar{b} = b xor sk to the client (n bits, once)
    osuCrypto::BitVector sk(n);
    sk.randomize(prng);
    osuCrypto::BitVector b_bar(n);
    for (int i = 0; i < n; i++)
    {
        b_bar[i] = b[i] ^ sk[i];
    }

    barrier(sock, true);
    PhaseStats pre3;
    {
        TrafficMeter meter(sock);
        auto start = Clock::now();
        osuCrypto::span<osuCrypto::u8> b_bar_span(b_bar.data(), b_bar.sizeBytes());
        coproto::sync_wait(sock.send(b_bar_span));
        coproto::sync_wait(sock.flush());
        pre3 = {std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start).count(), meter.sent(), meter.recv()};
        print_stats("[Server] key correction (b_bar) send", pre3);
    }
    print_stats("[Server] preprocessing total for the online example", pre1 + pre2 + pre3);
    offline_meter.report("server", "offline", mode == OnlineMode::Psi ? psi_params.client_size : tau);

    if (mode == OnlineMode::Batch)
        return online_server_batch(sock, Rs_r, Ss, sk, num_rounds);
    if (mode == OnlineMode::Psi)
        return online_server_psi(sock, Rs_r, Ss, sk);

    // State variable `ctr` depicted in Figure 4.
    uint ctr = 0;

    std::cout << "\n[Server] Answering " << num_rounds << " evaluations of the Pool OPRF..." << std::endl;

    std::vector<osuCrypto::u8> request(request_bytes);
    std::vector<osuCrypto::u8> response(response_bytes);

    double sum_server_mus = 0;

    barrier(sock, true);
    TrafficMeter online_meter(sock);

    for (int round = 0; round < num_rounds; round++)
    {
        coproto::sync_wait(sock.recv(request));

        // BlindEval (Fig. 4)
        auto be_start = Clock::now();

        osuCrypto::AlignedVector<uint> e_0(n);
        osuCrypto::AlignedVector<uint> e_1(n);
        uint bpr_bar;
        {
            BitReader r(request);
            for (int i = 0; i < n; i++)
            {
                e_0[i] = 0;
                e_1[i] = r.get(lg_q);
            }
            bpr_bar = r.get(lg_delta);
        }

        osuCrypto::AlignedVector<std::array<uint, 2>> atil(n);

        uint atil_sum = 0;

        for (int i = 0; i < n; i++)
        {
            uint Rs_r_uint = Rs_r[(ctr * n) + i];

            atil[i][0] = (e_0[i] - Rs_r_uint) & (q - 1);
            atil[i][1] = (e_1[i] - Rs_r_uint) & (q - 1);

            atil_sum += atil[i][sk[i]];
        }

        atil_sum = atil_sum & (q - 1);

        osuCrypto::AlignedVector<uint> y(delta);

        for (int i = 0; i < delta; i++)
        {
            uint Ss_uint = Ss[size_t(ctr) * delta + ((i - bpr_bar) & (delta - 1))];

            y[i] = ((((atil_sum - i) & (q - 1)) >> lg_delta) + Ss_uint) & (p - 1);
        }

        {
            BitWriter w(response);
            for (int i = 0; i < delta; i++)
                w.put(y[i], lg_p);
            w.finish();
        }

        auto be_end = Clock::now();

        coproto::sync_wait(sock.send(response));

        auto server_mus = std::chrono::duration_cast<std::chrono::microseconds>(be_end - be_start).count();
        sum_server_mus += server_mus;
        std::cout << "[Server] BlindEval computed in " << server_mus << "µs" << std::endl;

        ctr++;
    }
    coproto::sync_wait(sock.flush());

    size_t online_sent = online_meter.sent();
    size_t online_recv = online_meter.recv();

    std::cout << "\n===== [Server] online summary over " << num_rounds << " evaluation(s) =====\n"
              << "  avg server computation:  " << sum_server_mus / num_rounds << " us\n"
              << "  traffic per evaluation:  sent " << online_sent / num_rounds << " B, received "
              << online_recv / num_rounds << " B (measured, incl. 8B coproto header per message)" << std::endl;

    // Sanity check support, outside of all measurements: reveal sk to the client *for testing only*.
    osuCrypto::span<osuCrypto::u8> sk_span(sk.data(), sk.sizeBytes());
    coproto::sync_wait(sock.send(sk_span));
    coproto::sync_wait(sock.flush());
    return 0;
}

/////////////////////////////////////////////////////////////////////////////////////////////////
// Batched online phase: the client sends the requests of all evaluations in one message, the
// server answers all of them in one message (same per-evaluation computation as above).
/////////////////////////////////////////////////////////////////////////////////////////////////

// Request (Fig. 4) for evaluations 0, ..., count - 1, packed into one message. Evaluation ctr uses
// preprocessing slot ctr and the LWR sample that fill_a(ctr, a) writes to a.
template <typename FillA>
void client_requests(ClientOts &Sc_uint, ClientChoice &bpr,
                     osuCrypto::BitVector &b_bar, size_t count, FillA fill_a,
                     std::vector<uint> &c_sums, std::vector<osuCrypto::u8> &request)
{
    request.assign(size_t(request_bytes) * count, 0);
    c_sums.resize(count);
    BitWriter w(request);
    std::array<uint, n> a;
    for (size_t ctr = 0; ctr < count; ctr++)
    {
        fill_a(ctr, a.data());

        // need a larger type if n*(q-1) > uint::MAX
        uint c_sum = 0;
        for (int i = 0; i < n; i++)
        {
            uint e_0 = 0;
            uint c_i = (e_0 - (Sc_uint[(ctr * n) + i][b_bar[i]])) & (q - 1);
            uint e_1 = (a[i] + c_i + Sc_uint[(ctr * n) + i][1 - b_bar[i]]) & (q - 1);
            w.put(e_1, lg_q);

            c_sum += c_i;
        }
        c_sum = c_sum & (q - 1);
        c_sums[ctr] = c_sum;

        uint bpr_bar = ((c_sum & (delta - 1)) - bpr[ctr]) & (delta - 1);
        w.put(bpr_bar, lg_delta);
        w.finish(); // each request is padded to whole bytes
    }
}

// Finalize (Fig. 4) for every evaluation of a batched response.
void client_finalize(const std::vector<osuCrypto::u8> &response, ClientValue &Rc_r,
                     const std::vector<uint> &c_sums, std::vector<uint> &z)
{
    z.resize(c_sums.size());
    BitReader r(response);
    std::vector<uint> y(delta);
    for (size_t ctr = 0; ctr < c_sums.size(); ctr++)
    {
        for (int i = 0; i < delta; i++)
            y[i] = r.get(lg_p);
        r.align();

        uint Rc_r_uint = Rc_r[ctr];
        uint c_sum = c_sums[ctr];

        uint y_c_sum_mod_delta = y[c_sum & (delta - 1)];
        uint y_final = (y_c_sum_mod_delta - Rc_r_uint);
        uint temp_val = ((c_sum - (c_sum & (delta - 1))) >> lg_delta);
        z[ctr] = (y_final - temp_val) & (p - 1);
    }
}

// BlindEval (Fig. 4) for evaluations 0, ..., count - 1 of a batched request.
void server_blind_eval(const std::vector<osuCrypto::u8> &request, ServerOts &Rs_r,
                       ServerTable &Ss, osuCrypto::BitVector &sk, size_t count,
                       std::vector<osuCrypto::u8> &response)
{
    response.assign(size_t(response_bytes) * count, 0);
    BitReader r(request);
    BitWriter w(response);
    std::vector<uint> y(delta);
    for (size_t ctr = 0; ctr < count; ctr++)
    {
        uint atil_sum = 0;
        for (int i = 0; i < n; i++)
        {
            uint e_0 = 0;
            uint e_1 = r.get(lg_q);

            uint Rs_r_uint = Rs_r[(ctr * n) + i];

            std::array<uint, 2> atil;
            atil[0] = (e_0 - Rs_r_uint) & (q - 1);
            atil[1] = (e_1 - Rs_r_uint) & (q - 1);

            atil_sum += atil[sk[i]];
        }
        uint bpr_bar = r.get(lg_delta);
        r.align();

        atil_sum = atil_sum & (q - 1);

        for (int i = 0; i < delta; i++)
        {
            uint Ss_uint = Ss[size_t(ctr) * delta + ((i - bpr_bar) & (delta - 1))];

            y[i] = ((((atil_sum - i) & (q - 1)) >> lg_delta) + Ss_uint) & (p - 1);
            w.put(y[i], lg_p);
        }
        w.finish();
    }
}

double ms_between(Clock::time_point a, Clock::time_point b)
{
    return std::chrono::duration<double, std::milli>(b - a).count();
}

int online_client_batch(coproto::Socket &sock, ClientOts &Sc_uint, ClientChoice &bpr,
                        ClientValue &Rc_r, osuCrypto::BitVector &b_bar, uint batch)
{
    // random inputs (kept for the correctness check)
    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());
    std::vector<osuCrypto::block> inputs(batch);
    prng.get(inputs.data(), inputs.size());
    std::vector<uint> c_sums, z_log;
    std::vector<osuCrypto::u8> request;
    std::vector<osuCrypto::u8> response(size_t(response_bytes) * batch);

    std::cout << "\n[Client] Computing a batch of " << batch << " evaluations of the Pool OPRF..." << std::endl;
    barrier(sock, false);
    ResultMeter meter(sock);

    auto req_start = Clock::now();
    client_requests(Sc_uint, bpr, b_bar, batch, [&](size_t ctr, uint *a)
                    { hash_to_a(inputs[ctr], 0, a); }, c_sums, request);
    auto req_end = Clock::now();

    send_chunked(sock, request);
    recv_chunked(sock, response);
    auto resp_received = Clock::now();

    client_finalize(response, Rc_r, c_sums, z_log);
    auto end = Clock::now();
    meter.report("client", "online", batch, ms_between(req_start, req_end) + ms_between(resp_received, end));

    // Sanity check, outside of all measurements: the server reveals sk *for testing only*.
    osuCrypto::BitVector sk(n);
    osuCrypto::span<osuCrypto::u8> sk_span(sk.data(), sk.sizeBytes());
    coproto::sync_wait(sock.recv(sk_span));
    size_t wrong = 0;
    std::array<uint, n> a;
    for (uint ctr = 0; ctr < batch; ctr++)
    {
        hash_to_a(inputs[ctr], 0, a.data());
        wrong += (pool_prf(sk, a.data()) != z_log[ctr]);
    }
    std::cout << "CORRECTNESS protocol=pool " << (wrong ? "FAIL" : "OK") << " (" << batch - wrong << "/" << batch
              << " outputs correct)" << std::endl;
    coproto::sync_wait(sock.flush());
    return wrong ? 1 : 0;
}

int online_server_batch(coproto::Socket &sock, ServerOts &Rs_r,
                        ServerTable &Ss, osuCrypto::BitVector &sk, uint batch)
{
    std::vector<osuCrypto::u8> request(size_t(request_bytes) * batch);
    std::vector<osuCrypto::u8> response;

    std::cout << "\n[Server] Answering a batch of " << batch << " evaluations of the Pool OPRF..." << std::endl;
    barrier(sock, true);
    ResultMeter meter(sock);

    recv_chunked(sock, request);
    auto be_start = Clock::now();
    server_blind_eval(request, Rs_r, Ss, sk, batch, response);
    auto be_end = Clock::now();

    send_chunked(sock, response);
    coproto::sync_wait(sock.flush());
    meter.report("server", "online", batch, ms_between(be_start, be_end));

    // Sanity check support, outside of all measurements: reveal sk to the client *for testing only*.
    osuCrypto::span<osuCrypto::u8> sk_span(sk.data(), sk.sizeBytes());
    coproto::sync_wait(sock.send(sk_span));
    coproto::sync_wait(sock.flush());
    return 0;
}

/////////////////////////////////////////////////////////////////////////////////////////////////
// PSI (online part). The client learns X ∩ Y:
//   1. OPRF: one batched round trip gives the client F(x) (128 bits) for every x in X;
//   2. set:  the server sends F(y) for every y in Y, shuffled, 16 B each; the client looks them up.
// Phase "online" covers both; the offline phase is the OPRF preprocessing for |X| elements.
/////////////////////////////////////////////////////////////////////////////////////////////////
int online_client_psi(coproto::Socket &sock, ClientOts &Sc_uint, ClientChoice &bpr,
                      ClientValue &Rc_r, osuCrypto::BitVector &b_bar)
{
    const PsiParams &ps = psi_params;
    std::vector<osuCrypto::block> server_set, client_set;
    make_psi_sets(ps, server_set, client_set);
    server_set = {}; // the client only knows its own set

    const size_t evals = ps.client_size * evals_per_element;
    std::vector<uint> c_sums, z;
    std::vector<osuCrypto::u8> request;
    std::vector<osuCrypto::u8> response(size_t(response_bytes) * evals);
    std::vector<osuCrypto::u8> encodings(sizeof(Out128) * ps.server_size);

    std::cout << "\n[Client] PSI: client set " << ps.client_size << ", server set " << ps.server_size << ", "
              << evals_per_element << " Pool evaluations per element" << std::endl;
    barrier(sock, false);
    ResultMeter online(sock);
    ResultMeter oprf(sock);

    // 1. OPRF on the client set
    auto req_start = Clock::now();
    client_requests(Sc_uint, bpr, b_bar, evals, [&](size_t ctr, uint *a)
                    { hash_to_a(client_set[ctr / evals_per_element], ctr % evals_per_element, a); }, c_sums, request);
    auto req_end = Clock::now();

    send_chunked(sock, request);
    recv_chunked(sock, response);
    auto resp_received = Clock::now();

    client_finalize(response, Rc_r, c_sums, z);
    std::vector<std::pair<Out128, size_t>> outputs(ps.client_size);
    for (size_t e = 0; e < ps.client_size; e++)
        outputs[e] = {pack_output(&z[e * evals_per_element]), e};
    auto oprf_end = Clock::now();
    double oprf_ms = ms_between(req_start, req_end) + ms_between(resp_received, oprf_end);
    oprf.report("client", "oprf", ps.client_size, oprf_ms);

    // 2. intersection with the server's PRF values
    ResultMeter set(sock);
    auto sort_start = Clock::now();
    std::sort(outputs.begin(), outputs.end());
    auto sort_end = Clock::now();

    recv_chunked(sock, encodings);
    auto lookup_start = Clock::now();
    std::vector<size_t> found;
    for (size_t s = 0; s < ps.server_size; s++)
    {
        Out128 v;
        memcpy(v.data(), &encodings[sizeof(Out128) * s], sizeof(Out128));
        auto it = std::lower_bound(outputs.begin(), outputs.end(), std::make_pair(v, size_t(0)));
        if (it != outputs.end() && it->first == v)
            found.push_back(it->second);
    }
    auto lookup_end = Clock::now();
    double set_ms = ms_between(sort_start, sort_end) + ms_between(lookup_start, lookup_end);
    set.report("client", "set", ps.client_size, set_ms);
    online.report("client", "online", ps.client_size, oprf_ms + set_ms);

    // correctness: exactly the first `intersection` client elements are in the server set
    std::sort(found.begin(), found.end());
    bool ok = found.size() == ps.intersection;
    for (size_t i = 0; ok && i < found.size(); i++)
        ok = (found[i] == i);
    std::cout << "PSI protocol=pool client_size=" << ps.client_size << " server_size=" << ps.server_size
              << " intersection=" << ps.intersection << " found=" << found.size()
              << " oprf_evaluations=" << evals << std::endl;
    std::cout << "CORRECTNESS protocol=pool " << (ok ? "OK" : "FAIL") << " (intersection " << found.size() << ", expected "
              << ps.intersection << ")" << std::endl;
    coproto::sync_wait(sock.flush());
    return ok ? 0 : 1;
}

int online_server_psi(coproto::Socket &sock, ServerOts &Rs_r,
                      ServerTable &Ss, osuCrypto::BitVector &sk)
{
    const PsiParams &ps = psi_params;
    std::vector<osuCrypto::block> server_set, client_set;
    make_psi_sets(ps, server_set, client_set);
    client_set = {}; // the server only knows its own set

    const size_t evals = ps.client_size * evals_per_element;
    std::vector<osuCrypto::u8> request(size_t(request_bytes) * evals);
    std::vector<osuCrypto::u8> response;
    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());

    std::cout << "\n[Server] PSI: client set " << ps.client_size << ", server set " << ps.server_size << std::endl;
    barrier(sock, true);
    ResultMeter online(sock);
    ResultMeter oprf(sock);

    // 1. OPRF
    recv_chunked(sock, request);
    auto be_start = Clock::now();
    server_blind_eval(request, Rs_r, Ss, sk, evals, response);
    auto be_end = Clock::now();
    send_chunked(sock, response);
    coproto::sync_wait(sock.flush());
    double oprf_ms = ms_between(be_start, be_end);
    oprf.report("server", "oprf", ps.client_size, oprf_ms);

    // 2. PRF values of the server set, in the clear, shuffled
    ResultMeter set(sock);
    auto enc_start = Clock::now();
    std::vector<Out128> enc(ps.server_size);
    std::array<uint, n> a;
    std::array<uint, evals_per_element> zs;
    for (size_t s = 0; s < ps.server_size; s++)
    {
        for (uint j = 0; j < evals_per_element; j++)
        {
            hash_to_a(server_set[s], j, a.data());
            zs[j] = pool_prf(sk, a.data());
        }
        enc[s] = pack_output(zs.data());
    }
    for (size_t i = enc.size(); i > 1; i--)
        std::swap(enc[i - 1], enc[prng.get<osuCrypto::u64>() % i]);
    std::vector<osuCrypto::u8> encodings(sizeof(Out128) * ps.server_size);
    memcpy(encodings.data(), enc.data(), encodings.size());
    auto enc_end = Clock::now();
    send_chunked(sock, encodings);
    coproto::sync_wait(sock.flush());
    double set_ms = ms_between(enc_start, enc_end);
    set.report("server", "set", ps.client_size, set_ms);
    online.report("server", "online", ps.client_size, oprf_ms + set_ms);
    return 0;
}

void usage(const char *prog)
{
    std::cout << "usage: " << prog << " {server|client|local} {ip} {port} [all|online|batch] [num_rounds]\n"
              << "       " << prog << " {server|client|local} {ip} {port} psi <client_set_size> [server_set_size] [intersection]\n"
              << "  server : listen on ip:port (e.g. 0.0.0.0)\n"
              << "  client : connect to the server at ip:port\n"
              << "  local  : run both roles in one process (two threads)\n"
              << "  all    : run the alternative preprocessing benchmarks first (default, as the original binary)\n"
              << "  online : only the preprocessing needed for the online phase + the online phase\n"
              << "  batch  : preprocessing for exactly num_rounds evaluations (tau = num_rounds), then all\n"
              << "           num_rounds evaluations in one batched round trip\n"
              << "  psi    : PSI with a 128-bit OPRF output per element (" << evals_per_element << " evaluations of "
              << lg_p << " bits); server_set_size defaults to client_set_size, intersection to half of the smaller set\n"
              << "  num_rounds: number of online OPRF evaluations (default " << default_num_rounds << ", at most tau = " << tau << ")\n"
              << "  `0`/`1` are accepted for server/client. Both parties must use the same arguments." << std::endl;
}

int main(int argc, char *argv[])
{
    if (argc < 4)
    {
        usage(argv[0]);
        return -1;
    }
    std::string role = argv[1];
    if (role == "0")
        role = "server";
    if (role == "1")
        role = "client";
    std::string mode_name = argc > 4 ? argv[4] : "all";
    uint num_rounds = default_num_rounds;
    OnlineMode mode = OnlineMode::PerQuery;
    if (mode_name == "psi")
    {
        mode = OnlineMode::Psi;
        if (argc < 6)
        {
            usage(argv[0]);
            return -1;
        }
        psi_params.client_size = std::stoull(argv[5]);
        psi_params.server_size = argc > 6 ? std::stoull(argv[6]) : psi_params.client_size;
        psi_params.intersection = argc > 7 ? std::stoull(argv[7]) : std::min(psi_params.client_size, psi_params.server_size) / 2;
        if (psi_params.client_size == 0 || psi_params.server_size == 0 ||
            psi_params.intersection > std::min(psi_params.client_size, psi_params.server_size))
        {
            usage(argv[0]);
            return -1;
        }
        tau = psi_params.client_size * evals_per_element; // preprocess exactly the PSI
    }
    else
    {
        if (mode_name == "batch")
            mode = OnlineMode::Batch;
        num_rounds = argc > 5 ? std::stoul(argv[5]) : default_num_rounds;
        if ((mode_name != "all" && mode_name != "online" && mode_name != "batch") || num_rounds == 0 ||
            (mode != OnlineMode::Batch && num_rounds > tau))
        {
            usage(argv[0]);
            return -1;
        }
        if (mode == OnlineMode::Batch)
            tau = num_rounds; // preprocess exactly the batch
    }
    if (role != "server" && role != "client" && role != "local")
    {
        usage(argv[0]);
        return -1;
    }
    bool alt = (mode_name == "all");
    if (const char *pre = std::getenv("POOL_PREPROC"))
        silent_preproc = std::string(pre) != "iknp";
    std::string ip = std::string(argv[2]) + ":" + argv[3];

    try
    {
        if (role == "server")
        {
            std::cout << "[Server] listening on " << ip << std::endl;
            auto sock = coproto::asioConnect(ip, true);
            return run_server(sock, alt, num_rounds, mode);
        }
        if (role == "client")
        {
            auto sock = coproto::asioConnect(ip, false);
            return run_client(sock, alt, num_rounds, mode);
        }

        // local: both roles in one process
        int client_ret = 0;
        auto clientThread = std::thread([&]
                                        {
            try {
                auto sock = coproto::asioConnect(ip, false);
                client_ret = run_client(sock, alt, num_rounds, mode);
            } catch (std::exception &e) {
                std::cerr << "[Client] " << e.what() << std::endl;
                client_ret = 1;
            } });
        int server_ret = 0;
        {
            auto sock = coproto::asioConnect(ip, true);
            server_ret = run_server(sock, alt, num_rounds, mode);
        }
        clientThread.join();
        return (client_ret || server_ret) ? 1 : 0;
    }
    catch (std::exception &e)
    {
        std::cerr << e.what() << std::endl;
        return 1;
    }
}
