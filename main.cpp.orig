/*
Most of the code in this file implements the preprocessing algorithms presented in Figure 3 from the paper ``Pool: Pool: A Practical OT-based OPRF from Learning with Rounding".
The `main` function implements the algorithms from Figure 4 to have a working example of the online phase.

The nomenclature "Phase one" and "Phase two" refer to the two main phases of the preprocessing procedure, denoted (2) and (3) respectively in Figure 3.

Most functions have the same structure in that they implement either a sender or a receiver for a specific OT extender, and they are named accordingly.

The executable obtained from compiling this file allows to benchmark preprocessing phases using several different combination of OT extenders as building blocks.
Once all the different combinations are benchmarked, the executable proceeds to a final preprocessing phase followed by an execution of the online phase.

The code relies on the `libOTe` library for the OT primitives.
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

#include <iostream>

/*
Parameters for the preprocessing.
Variable names are chosen to match the paper's notation. `lg_X` denotes the binary logarithm of `X`.
When changing the parameters, one should be careful to make sure that they are consistent.
For example, `tau` should be big enough for `num_rounds` of OPRF rounds to be executed in the online phase.

As is, the parameters allow to measure numbers used in Table 4 for `# evals` set at 2^13.
*/
const uint n = 482;
const uint tau = 1 << 16;
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

// number of OPRF rounds to execute in the online phase
const uint num_rounds = 10;

// Phase one receiver using the IKNP OT extender.
// This phase one preprocessing implementation is used to obtain the random OTs that are used in the online phase.
void phase_one_iknp_receive(osuCrypto::BitVector &b, osuCrypto::AlignedUnVector<osuCrypto::block> &Rs_r)
{
    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());

    auto sock = coproto::asioConnect("localhost:1212", false);

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

    try
    {
        // perform random OTs and write results to Rs_r
        coproto::sync_wait(receiver.receive(b, Rs_r, prng, sock));
    }
    catch (std::exception &e)
    {
        std::cerr << e.what() << std::endl;
        coproto::sync_wait(sock.close());
    }

    coproto::sync_wait(sock.flush());

    auto dataReceived = sock.bytesReceived();
    auto dataSent = sock.bytesSent();

    std::cout << "phase one iknp receiver, sent " << dataSent << " bytes and received " << dataReceived << " bytes" << std::endl;
}

// Phase one sender using the IKNP OT extender.
// This phase one preprocessing implementation is used to obtain the random OTs that are used in the online phase.
void phase_one_iknp_send(osuCrypto::AlignedUnVector<std::array<osuCrypto::block, 2>> &Sc)
{
    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());

    auto sock = coproto::asioConnect("localhost:1212", true);

    // prepare IKNP OT extender
    osuCrypto::IknpOtExtSender sender = osuCrypto::IknpOtExtSender{};

    osuCrypto::MasnyRindalKyber baseOt;

    osuCrypto::BitVector baseOtBv(sender.baseOtCount());
    baseOtBv.randomize(prng);

    std::vector<osuCrypto::block> baseOtRcvMsgs(sender.baseOtCount());

    coproto::sync_wait(baseOt.receive(baseOtBv, baseOtRcvMsgs, prng, sock));
    sender.setBaseOts(baseOtRcvMsgs, baseOtBv);

    // onto actual OT
    try
    {
        // perform random OTs and write the random OTs to Sc
        coproto::sync_wait(sender.send(Sc, prng, sock));
    }
    catch (std::exception &e)
    {
        std::cerr << e.what() << std::endl;
        coproto::sync_wait(sock.close());
    }

    coproto::sync_wait(sock.flush());

    auto dataReceived = sock.bytesReceived();
    auto dataSent = sock.bytesSent();

    std::this_thread::sleep_for(std::chrono::seconds(1));

    std::cout << "phase one iknp sender, sent " << dataSent << " bytes and received " << dataReceived << " bytes" << std::endl;
}

// Phase one receiver using the "unwasteful" IKNP OT extender.
// This phase one preprocessing implementation is benchmarked to obtain the numbers presented in the paper under IKNP.
void phase_one_iknp_unwasteful_receive(osuCrypto::BitVector &b, osuCrypto::AlignedUnVector<osuCrypto::block> &Rs_r)
{
    osuCrypto::Timer timer;

    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());

    auto sock = coproto::asioConnect("localhost:1212", false);

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

    try
    {
        // perform random OTs and write results to Rs_r
        coproto::sync_wait(receiver.receive(b, Rs_r, prng, sock));
    }
    catch (std::exception &e)
    {
        std::cerr << e.what() << std::endl;
        coproto::sync_wait(sock.close());
    }

    coproto::sync_wait(sock.flush());

    osuCrypto::Timer::timeUnit end = timer.setTimePoint("phase 1 iknp receive end");
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(baseOtEnd - baseOtStart + end - start).count();

    auto dataReceived = sock.bytesReceived();
    auto dataSent = sock.bytesSent();

    std::cout << "phase one iknp unwasteful receiver in " << ms << "ms, sent " << dataSent << " bytes and received " << dataReceived << " bytes" << std::endl;
}

// Phase one sender using the "unwasteful" IKNP OT extender.
// This phase one preprocessing implementation is benchmarked to obtain the numbers presented in the paper under IKNP.
void phase_one_iknp_unwasteful_send(osuCrypto::AlignedUnVector<std::array<osuCrypto::block, 2>> &Sc)
{
    osuCrypto::Timer timer;

    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());

    auto sock = coproto::asioConnect("localhost:1212", true);

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

    try
    {
        // perform random OTs and write the random OTs to Sc
        coproto::sync_wait(sender.send(Sc, prng, sock));
    }
    catch (std::exception &e)
    {
        std::cerr << e.what() << std::endl;
        coproto::sync_wait(sock.close());
    }

    coproto::sync_wait(sock.flush());

    osuCrypto::Timer::timeUnit end = timer.setTimePoint("phase 1 iknp send end");
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(baseOtEnd - baseOtStart + end - start).count();

    auto dataReceived = sock.bytesReceived();
    auto dataSent = sock.bytesSent();

    std::this_thread::sleep_for(std::chrono::seconds(1));

    std::cout << "phase one iknp unwasteful sender in " << ms << "ms, sent " << dataSent << " bytes and received " << dataReceived << " bytes" << std::endl;
}

// Phase one receiver using the Silent OT extender.
// This phase one preprocessing implementation is benchmarked to obtain the numbers presented in the paper under Silent OT (n OTs).
void phase_one_sot_receive(osuCrypto::BitVector &b, osuCrypto::AlignedUnVector<osuCrypto::block> &Rs_r)
{
    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());

    auto sock = coproto::asioConnect("localhost:1212", false);

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
    try
    {
        coproto::sync_wait(receiver.silentReceive(b, Rs_r, prng, sock, osuCrypto::OTType::Random));
    }
    catch (std::exception &e)
    {
        std::cerr << e.what() << std::endl;
        coproto::sync_wait(sock.close());
    }

    coproto::sync_wait(sock.flush());

    osuCrypto::Timer::timeUnit end = timer.setTimePoint("phase 1 silent ot receive end");
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    auto dataReceived = sock.bytesReceived();
    auto dataSent = sock.bytesSent();

    std::cout << "phase one silent ot receiver in " << ms << "ms, sent " << dataSent << " bytes and received " << dataReceived << " bytes" << std::endl;
}

// Phase one sender using the Silent OT extender.
// This phase one preprocessing implementation is benchmarked to obtain the numbers presented in the paper under Silent OT (n OTs).
void phase_one_sot_send(osuCrypto::AlignedUnVector<std::array<osuCrypto::block, 2>> &Sc)
{
    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());

    auto sock = coproto::asioConnect("localhost:1212", true);

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
    try
    {
        coproto::sync_wait(sender.silentSend(Sc, prng, sock));
    }
    catch (std::exception &e)
    {
        std::cerr << e.what() << std::endl;
    }

    coproto::sync_wait(sock.flush());

    osuCrypto::Timer::timeUnit end = timer.setTimePoint("phase 1 silent ot send end");
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    auto dataReceived = sock.bytesReceived();
    auto dataSent = sock.bytesSent();

    std::this_thread::sleep_for(std::chrono::seconds(1));

    std::cout << "phase one silent ot sender in " << ms << "ms, sent " << dataSent << " bytes and received " << dataReceived << " bytes" << std::endl;
}

// Phase one receiver using the Silent OT extender.
// This phase one preprocessing implementation is benchmarked to obtain the numbers presented in the paper under Silent OT (n * kappa OTs).
void phase_one_sot_unwasteful_receive(osuCrypto::BitVector &b, osuCrypto::AlignedUnVector<osuCrypto::block> &Rs_r)
{
    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());

    auto sock = coproto::asioConnect("localhost:1212", false);

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
    try
    {
        coproto::sync_wait(receiver.silentReceive(b, Rs_r, prng, sock, osuCrypto::OTType::Random));
    }
    catch (std::exception &e)
    {
        std::cerr << e.what() << std::endl;
        coproto::sync_wait(sock.close());
    }

    coproto::sync_wait(sock.flush());

    osuCrypto::Timer::timeUnit end = timer.setTimePoint("phase 1 silent ot receive end");
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    auto dataReceived = sock.bytesReceived();
    auto dataSent = sock.bytesSent();

    std::cout << "phase one silent ot unwasteful receiver in " << ms << "ms, sent " << dataSent << " bytes and received " << dataReceived << " bytes" << std::endl;
}

// Phase one sender using the Silent OT extender.
// This phase one preprocessing implementation is benchmarked to obtain the numbers presented in the paper under Silent OT (n * kappa OTs).
void phase_one_sot_unwasteful_send(osuCrypto::AlignedUnVector<std::array<osuCrypto::block, 2>> &Sc)
{
    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());

    auto sock = coproto::asioConnect("localhost:1212", true);

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
    try
    {
        coproto::sync_wait(sender.silentSend(Sc, prng, sock));
    }
    catch (std::exception &e)
    {
        std::cerr << e.what() << std::endl;
    }

    coproto::sync_wait(sock.flush());

    osuCrypto::Timer::timeUnit end = timer.setTimePoint("phase 1 silent ot send end");
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    auto dataReceived = sock.bytesReceived();
    auto dataSent = sock.bytesSent();

    std::this_thread::sleep_for(std::chrono::seconds(1));

    std::cout << "phase one silent ot unwasteful sender in " << ms << "ms, sent " << dataSent << " bytes and received " << dataReceived << std::endl;
}

// Phase two receiver using the KKRT OT extender.
// This phase two preprocessing implementation is used to obtain the random OTs that are used in the online phase.
void phase_two_kkrt_receive(uint statisticalSecurityParam, std::vector<osuCrypto::u64> &bpr, osuCrypto::AlignedVector<osuCrypto::block> &Rc_r)
{
    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());

    osuCrypto::KkrtNcoOtReceiver receiver;

    auto sock = coproto::asioConnect("localhost:1212", false);

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

    try
    {
        coproto::sync_wait(receiveRoutine());
    }
    catch (std::exception &e)
    {
        std::cerr << e.what() << std::endl;
    }

    auto dataReceived = sock.bytesReceived();
    auto dataSent = sock.bytesSent();

    std::cout << "phase two kkrt receiver, sent " << dataSent << " bytes and received " << dataReceived << " bytes" << std::endl;
}

// Phase two sender using the KKRT OT extender.
// This phase two preprocessing implementation is used to obtain the random OTs that are used in the online phase.
void phase_two_kkrt_send(uint statisticalSecurityParam, osuCrypto::Matrix<osuCrypto::block> &Ss)
{
    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());

    osuCrypto::KkrtNcoOtSender sender;

    auto sock = coproto::asioConnect("localhost:1212", true);

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

    try
    {
        coproto::sync_wait(sendRoutine());
    }
    catch (std::exception &e)
    {
        std::cerr << e.what() << std::endl;
    }

    std::this_thread::sleep_for(std::chrono::seconds(1));

    auto dataReceived = sock.bytesReceived();
    auto dataSent = sock.bytesSent();

    std::cout << "phase two kkrt sender, sent " << dataSent << " bytes and received " << dataReceived << " bytes" << std::endl;
}

// Phase two receiver using the IKNP OT extender.
// This phase two preprocessing implementation is benchmarked to obtain the numbers presented in the paper under IKNP.
void phase_two_iknp_receive(osuCrypto::BitVector &b, osuCrypto::AlignedUnVector<osuCrypto::block> &Rs_r)
{
    osuCrypto::Timer timer;

    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());

    auto sock = coproto::asioConnect("localhost:1212", false);

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

    try
    {
        // perform random OTs and write results to Rs_r
        coproto::sync_wait(receiver.receive(b, Rs_r, prng, sock));
    }
    catch (std::exception &e)
    {
        std::cerr << e.what() << std::endl;
        coproto::sync_wait(sock.close());
    }

    coproto::sync_wait(sock.flush());

    osuCrypto::Timer::timeUnit end = timer.setTimePoint("phase 2 iknp receive end");
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(baseOtEnd - baseOtStart + end - start).count();

    auto dataReceived = sock.bytesReceived();
    auto dataSent = sock.bytesSent();

    std::cout << "phase two iknp receiver in " << ms << "ms, sent " << dataSent << " bytes and received " << dataReceived << " bytes" << std::endl;
}

// Phase two sender using the IKNP OT extender.
// This phase two preprocessing implementation is benchmarked to obtain the numbers presented in the paper under IKNP.
void phase_two_iknp_send(osuCrypto::AlignedUnVector<std::array<osuCrypto::block, 2>> &Sc)
{
    osuCrypto::Timer timer;

    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());

    auto sock = coproto::asioConnect("localhost:1212", true);

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

    try
    {
        // perform random OTs and write the random OTs to Sc
        coproto::sync_wait(sender.send(Sc, prng, sock));
    }
    catch (std::exception &e)
    {
        std::cerr << e.what() << std::endl;
        coproto::sync_wait(sock.close());
    }

    coproto::sync_wait(sock.flush());

    osuCrypto::Timer::timeUnit end = timer.setTimePoint("phase 2 iknp send end");
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(baseOtEnd - baseOtStart + end - start).count();

    auto dataReceived = sock.bytesReceived();
    auto dataSent = sock.bytesSent();

    std::this_thread::sleep_for(std::chrono::seconds(1));

    std::cout << "phase two iknp sender in " << ms << "ms, sent " << dataSent << " bytes and received " << dataReceived << " bytes" << std::endl;
}

// Phase two receiver using the Silent OT extender.
// This phase two preprocessing implementation is benchmarked to obtain the numbers presented in the paper under Silent OT (n OTs and n * kappa OTs).
void phase_two_sot_receive(osuCrypto::BitVector &b, osuCrypto::AlignedUnVector<osuCrypto::block> &Rs_r)
{
    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());

    auto sock = coproto::asioConnect("localhost:1212", false);

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
    try
    {
        coproto::sync_wait(receiver.silentReceive(b, Rs_r, prng, sock, osuCrypto::OTType::Random));
    }
    catch (std::exception &e)
    {
        std::cerr << e.what() << std::endl;
        coproto::sync_wait(sock.close());
    }

    coproto::sync_wait(sock.flush());

    osuCrypto::Timer::timeUnit end = timer.setTimePoint("phase 2 silent ot receive end");
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    auto dataReceived = sock.bytesReceived();
    auto dataSent = sock.bytesSent();

    std::cout << "phase two silent ot receiver in " << ms << "ms, sent " << dataSent << " bytes and received " << dataReceived << " bytes" << std::endl;
}

// Phase two sender using the Silent OT extender.
// This phase two preprocessing implementation is benchmarked to obtain the numbers presented in the paper under Silent OT (n OTs and n * kappa OTs).
void phase_two_sot_send(osuCrypto::AlignedUnVector<std::array<osuCrypto::block, 2>> &Sc)
{
    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());

    auto sock = coproto::asioConnect("localhost:1212", true);

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
    try
    {
        coproto::sync_wait(sender.silentSend(Sc, prng, sock));
    }
    catch (std::exception &e)
    {
        std::cerr << e.what() << std::endl;
    }

    coproto::sync_wait(sock.flush());

    osuCrypto::Timer::timeUnit end = timer.setTimePoint("phase 2 silent ot send end");
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    auto dataReceived = sock.bytesReceived();
    auto dataSent = sock.bytesSent();

    std::this_thread::sleep_for(std::chrono::seconds(1));

    std::cout << "phase two silent ot sender in " << ms << "ms, sent " << dataSent << " bytes and received " << dataReceived << " bytes" << std::endl;
}

// contains examples for all preprocessing procedures.
// these procedures were used to obtain the preprocessing measures given in the paper.
// client complexity is taken as phase one sender + phase two receiver, and vice-versa for the server complexity.
void benchmark_alt_preproc()
{
    std::cout << "Benchmarking alternative preprocessing procedures..." << std::endl;
    std::cout << "Client complexity is taken as phase one sender + phase two receiver, and vice-versa for the server complexity." << std::endl;

    // data structures for "unwasteful" IKNP phase one
    osuCrypto::BitVector phase_one_iknp_b(n * kappa);
    osuCrypto::AlignedUnVector<osuCrypto::block> phase_one_iknp_Rs_r(n * kappa);
    osuCrypto::AlignedUnVector<std::array<osuCrypto::block, 2>> phase_one_iknp_Sc(n * kappa);

    std::cout << "Benchmarking for phase one of preprocessing with \"unwasteful\" IKNP..." << std::endl;
    auto phase_one_iknp_unwasteful_thread = std::thread([&]
                                                        {
       try {
          phase_one_iknp_unwasteful_receive(phase_one_iknp_b, phase_one_iknp_Rs_r);
       } catch (std::exception &e) {
          std::cerr << e.what() << std::endl;
       } });

    try
    {
        phase_one_iknp_unwasteful_send(phase_one_iknp_Sc);
    }
    catch (std::exception &e)
    {
        std::cerr << e.what() << std::endl;
    }
    phase_one_iknp_unwasteful_thread.join();

    // data structures for Naor-Pinkas phase two with IKNP
    osuCrypto::BitVector phase_two_iknp_b(lg_delta * tau);
    osuCrypto::AlignedUnVector<osuCrypto::block> phase_two_iknp_Rs_r(lg_delta * tau);
    osuCrypto::AlignedUnVector<std::array<osuCrypto::block, 2>> phase_two_iknp_Sc(lg_delta * tau);

    std::cout << "\nBenchmarking for phase two of preprocessing with IKNP/Naor-Pinkas..." << std::endl;
    auto phase_two_iknp_thread = std::thread([&]
                                             {
       try {
          phase_two_iknp_receive(phase_two_iknp_b, phase_two_iknp_Rs_r);
       } catch (std::exception &e) {
          std::cerr << e.what() << std::endl;
       } });

    try
    {
        phase_two_iknp_send(phase_two_iknp_Sc);
    }
    catch (std::exception &e)
    {
        std::cerr << e.what() << std::endl;
    }
    phase_two_iknp_thread.join();

    // data structures for phase one with Silent OT (n)
    osuCrypto::BitVector silent_ot_n_b_n(n);
    osuCrypto::AlignedUnVector<osuCrypto::block> silent_ot_n_Rs_r_n(n);
    osuCrypto::AlignedUnVector<std::array<osuCrypto::block, 2>> silent_ot_n_Sc_n(n);

    std::cout << "\n\nBenchmarking for phase one of preprocessing with Silent OT (n OTs)..." << std::endl;
    auto phase_one_sot_n_thread = std::thread([&]
                                              {
      try {
      phase_one_sot_receive(silent_ot_n_b_n, silent_ot_n_Rs_r_n);
      } catch (std::exception &e) {
      std::cerr << e.what() << std::endl;
      } });

    try
    {
        phase_one_sot_send(silent_ot_n_Sc_n);
    }
    catch (std::exception &e)
    {
        std::cerr << e.what() << std::endl;
    }
    phase_one_sot_n_thread.join();

    // extension of phase 1 OT results to n * kappa useful values
    std::cout << "Extending phase one results..." << std::endl;
    osuCrypto::Timer timer;
    osuCrypto::Timer::timeUnit startExt = timer.setTimePoint("phase 1 extension start");

    // data structures for phase one with Silent OT (n) extension
    osuCrypto::BitVector silent_ot_n_b(n * kappa);
    osuCrypto::AlignedUnVector<osuCrypto::block> silent_ot_n_Rs_r(n * kappa);
    osuCrypto::AlignedUnVector<std::array<osuCrypto::block, 2>> silent_ot_n_Sc(n * kappa);
    for (int i = 0; i < n; i++)
    {
        osuCrypto::PRNG prng_msg_0(silent_ot_n_Sc_n[i][0]);
        osuCrypto::PRNG prng_msg_1(silent_ot_n_Sc_n[i][1]);
        osuCrypto::PRNG prng_res(silent_ot_n_Rs_r_n[i]);

        for (int j = 0; j < kappa; j++)
        {
            silent_ot_n_b[j * n + i] = silent_ot_n_b_n[i];
            silent_ot_n_Sc[j * n + i][0] = prng_msg_0.get<osuCrypto::block>();
            silent_ot_n_Sc[j * n + i][1] = prng_msg_1.get<osuCrypto::block>();
            silent_ot_n_Rs_r[j * n + i] = prng_res.get<osuCrypto::block>();
        }
    }

    osuCrypto::Timer::timeUnit endExt = timer.setTimePoint("phase 1 extension end");
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(endExt - startExt).count();

    std::cout << "Extension took " << ms << "ms" << std::endl;

    // data structures for Naor-Pinkas phase two with Silent OT
    osuCrypto::BitVector phase_two_sot_b(lg_delta * tau);
    osuCrypto::AlignedUnVector<osuCrypto::block> phase_two_sot_Rs_r(lg_delta * tau);
    osuCrypto::AlignedUnVector<std::array<osuCrypto::block, 2>> phase_two_sot_Sc(lg_delta * tau);

    std::cout << "\nBenchmarking for phase two of preprocessing with Silent OT/Naor-Pinkas..." << std::endl;

    auto phase_two_sot_thread = std::thread([&]
                                            {
       try {
          phase_two_sot_receive(phase_two_sot_b, phase_two_sot_Rs_r);
       } catch (std::exception &e) {
          std::cerr << e.what() << std::endl;
       } });

    try
    {
        phase_two_sot_send(phase_two_sot_Sc);
    }
    catch (std::exception &e)
    {
        std::cerr << e.what() << std::endl;
    }
    phase_two_sot_thread.join();

    std::cout << "\n\nBenchmarking for phase one of preprocessing with Silent OT (n * kappa OTs)..." << std::endl;

    // data structures for phase one with Silent OT (n * kappa)
    osuCrypto::BitVector phase_one_sot_unwasteful_b(n * kappa);
    osuCrypto::AlignedUnVector<osuCrypto::block> phase_one_sot_unwasteful_Rs_r(n * kappa);
    osuCrypto::AlignedUnVector<std::array<osuCrypto::block, 2>> phase_one_sot_unwasteful_Sc(n * kappa);

    auto phase_one_sot_unwasteful_thread = std::thread([&]
                                                       {
      try {
      phase_one_sot_unwasteful_receive(phase_one_sot_unwasteful_b, phase_one_sot_unwasteful_Rs_r);
      } catch (std::exception &e) {
      std::cerr << e.what() << std::endl;
      } });

    try
    {
        phase_one_sot_unwasteful_send(phase_one_sot_unwasteful_Sc);
    }
    catch (std::exception &e)
    {
        std::cerr << e.what() << std::endl;
    }
    phase_one_sot_unwasteful_thread.join();

    // data structures for Naor-Pinkas phase two with Silent OT
    osuCrypto::BitVector second_phase_two_sot_b(lg_delta * tau);
    osuCrypto::AlignedUnVector<osuCrypto::block> second_phase_two_sot_Rs_r(lg_delta * tau);
    osuCrypto::AlignedUnVector<std::array<osuCrypto::block, 2>> second_phase_two_sot_Sc(lg_delta * tau);

    std::cout << "\nBenchmarking for phase two of preprocessing with Silent OT/Naor-Pinkas..." << std::endl;

    auto second_phase_two_sot_thread = std::thread([&]
                                                   {
       try {
        phase_two_sot_receive(second_phase_two_sot_b, second_phase_two_sot_Rs_r);
       } catch (std::exception &e) {
          std::cerr << e.what() << std::endl;
       } });

    try
    {
        phase_two_sot_send(second_phase_two_sot_Sc);
    }
    catch (std::exception &e)
    {
        std::cerr << e.what() << std::endl;
    }
    second_phase_two_sot_thread.join();
}

int main(int argc, char *argv[])
{
    // The following is for benchmarking purposes only.
    benchmark_alt_preproc();

    std::cout << "\n\nComputing preprocessing for online example..." << std::endl;

    // phase one data structures
    osuCrypto::BitVector b(n * tau);
    osuCrypto::AlignedUnVector<osuCrypto::block> Rs_r(n * tau);
    osuCrypto::AlignedUnVector<std::array<osuCrypto::block, 2>> Sc(n * tau);

    auto phase_one_iknp_thread = std::thread([&]
                                             {
       try {
          phase_one_iknp_receive(b, Rs_r);
       } catch (std::exception &e) {
          std::cerr << e.what() << std::endl;
       } });

    try
    {
        phase_one_iknp_send(Sc);
    }
    catch (std::exception &e)
    {
        std::cerr << e.what() << std::endl;
    }
    phase_one_iknp_thread.join();

    // phase two data structures
    std::vector<osuCrypto::u64> bpr(tau);
    osuCrypto::AlignedVector<osuCrypto::block> Rc_r(tau);
    osuCrypto::Matrix<osuCrypto::block> Ss(tau, delta);

    uint statisticalSecurityParam = 40;

    auto phase_2_thread = std::thread([&]
                                      {
      try {
      phase_two_kkrt_receive(statisticalSecurityParam, bpr, Rc_r);
      } catch (std::exception &e) {
      std::cerr << e.what() << std::endl;
      } });

    try
    {
        phase_two_kkrt_send(statisticalSecurityParam, Ss);
    }
    catch (std::exception &e)
    {
        std::cerr << e.what() << std::endl;
    }

    phase_2_thread.join();

    osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());

    // sample secret key
    osuCrypto::BitVector sk(n);
    sk.randomize(prng);
    osuCrypto::BitVector b_bar(n);
    for (int i = 0; i < n; i++)
    {
        b_bar[i] = b[i] ^ sk[i];
    }

    // parse values from OTs
    std::vector<std::array<uint, 2>> Sc_uint(n * tau);
    for (int i = 0; i < n * tau; i++)
    {
        int32_t arr0[4];
        memcpy(arr0, &Sc[i][0], sizeof(arr0));
        int32_t arr1[4];
        memcpy(arr1, &Sc[i][1], sizeof(arr1));

        Sc_uint[i][0] = (arr0[0]);
        Sc_uint[i][1] = (arr1[0]);
    }

    // State variable `ctr` depicted in Figure 4 - Request.
    uint ctr = 0;

    std::cout << "\nComputing " << num_rounds << " evaluations of the Pool OPRF..." << std::endl;

    // Communication complexity for one round of the Pool OPRF.
    // The communication complexity is computed as follows:
    // n * lg_q + lg_delta for the output values `(e_1, ..., e_n), \bar{b}'` of the `Request` phase (Fig. 4). We do not account for session-specific values.
    // delta * p for the output values `y_0, ..., y_{delta-1}` of the `BlindEval` phase (Fig. 4). Again, we ignore the session-specific values (e.g., `uid, ctr`).
    uint comm_compl = (n * lg_q + lg_delta + delta * lg_p) / 8;

    for (int round = 0; round < num_rounds; round++)
    {
        // Request (Fig. 4)
        osuCrypto::Timer timer;
        osuCrypto::Timer::timeUnit req_start = timer.setTimePoint("request start");

        // seeds for the random oracle. can be user-provided.
        int64_t t = prng.get<int64_t>();
        int64_t x = prng.get<int64_t>();

        osuCrypto::AlignedVector<uint> a(n);
        osuCrypto::AlignedVector<uint> e_0(n);
        osuCrypto::AlignedVector<uint> e_1(n);

        // need a larger type if n*(q-1) > uint::MAX
        uint c_sum = 0;

        int size = 2 * n * sizeof(osuCrypto::u8);
        osuCrypto::u8 *dest = static_cast<osuCrypto::u8 *>(malloc(size));
        osuCrypto::RandomOracle ro(size);
        ro.Update(t);
        ro.Update(x);
        ro.Final(dest);

        for (int i = 0; i < n; i++)
        {
            uint high = dest[2 * i];
            uint low = dest[2 * i + 1];
            a[i] = ((high << 8) | low) & (q - 1);
            e_0[i] = 0;

            uint c_i = (e_0[i] - (Sc_uint[(ctr * n) + i][b_bar[i]])) & (q - 1);
            e_1[i] = (a[i] + c_i + Sc_uint[(ctr * n) + i][1 - b_bar[i]]) & (q - 1);

            c_sum += c_i;
        }

        c_sum = c_sum & (q - 1);

        uint bpr_bar = ((c_sum & (delta - 1)) - bpr[ctr]) & (delta - 1);

        osuCrypto::Timer::timeUnit req_end = timer.setTimePoint("request end");

        // BlindEval (Fig. 4)

        osuCrypto::AlignedVector<std::array<uint, 2>> atil(n);

        uint atil_sum = 0;

        for (int i = 0; i < n; i++)
        {
            int32_t arr[4];
            memcpy(arr, &Rs_r[(ctr * n) + i], sizeof(arr));

            uint Rs_r_uint = arr[0];

            atil[i][0] = (e_0[i] - Rs_r_uint) & (q - 1);
            atil[i][1] = (e_1[i] - Rs_r_uint) & (q - 1);

            atil_sum += atil[i][sk[i]];
        }

        atil_sum = atil_sum & (q - 1);

        osuCrypto::AlignedVector<uint> y(delta);

        for (int i = 0; i < delta; i++)
        {
            int32_t arr[4];
            memcpy(arr, &Ss[ctr][(i - bpr_bar) & (delta - 1)], sizeof(arr));
            uint Ss_uint = arr[0];

            y[i] = ((((atil_sum - i) & (q - 1)) >> lg_delta) + Ss_uint) & (p - 1);
        }

        osuCrypto::Timer::timeUnit be_end = timer.setTimePoint("blind eval end");

        // Finalize (Fig. 4)
        int32_t arr[4];
        memcpy(arr, &Rc_r[ctr], sizeof(arr));
        uint Rc_r_uint = arr[0];

        uint y_c_sum_mod_delta = y[c_sum & (delta - 1)];

        uint y_final = (y_c_sum_mod_delta - Rc_r_uint);
        uint temp_val = ((c_sum - (c_sum & (delta - 1))) >> lg_delta);

        uint z = (y_final - temp_val) & (p - 1);

        osuCrypto::Timer::timeUnit end = timer.setTimePoint("finalize end");
        auto client_mus = std::chrono::duration_cast<std::chrono::microseconds>(end - be_end + req_end - req_start).count();
        auto server_mus = std::chrono::duration_cast<std::chrono::microseconds>(be_end - req_end).count();

        std::cout << "Result: " << z << " computed in " << client_mus << "µs for the client and " << server_mus << "µs for the server with communication complexity " << comm_compl << "B." << std::endl;

        // Sanity check
        uint eval_z = 0;
        for (int i = 0; i < n; i++)
        {
            if (sk[i])
            {
                eval_z += a[i];
            }
        }
        eval_z = ((eval_z) >> lg_delta) & (p - 1);

        // asserts that the computed value matches the expected value.
        assert(eval_z == z);
        ctr++;
        free(dest);
    }

    return 0;
}
