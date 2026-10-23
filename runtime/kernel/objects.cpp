#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <map>
#include <queue>

#include "kernel/kernel.h"

namespace kernel {

// A blocked wait. Signallers satisfy it on its behalf under the dispatcher lock (consuming the object as the wait
// would), record which object did, and wake its thread alone.
struct Waiter {
    Object* const* objs;
    size_t count;
    bool all;
    uint32_t me;
    int32_t result = -1;  // index of the satisfying object, set under the dispatcher lock
    std::condition_variable cv;
};

namespace {

std::mutex g_dispatch;

std::mutex g_handles_lock;
std::unordered_map<uint32_t, ObjectRef> g_handles;
uint32_t g_next_handle = 0x1000;

// Dispatcher table: every object bound to guest memory, by slot, kept for the life of the process. The slot sits in
// the header's WaitListHead.Flink beside a stamp in Blink, so a lookup reads the header and one table entry without a
// lock. Entries are written once, before the count that publishes them.
constexpr uint32_t kStamp = 0x4A424F4Bu;  // written into WaitListHead.Blink of objects the host tracks
constexpr uint32_t kChunkBits = 10, kChunkSize = 1u << kChunkBits, kChunks = 4096;
std::atomic<ObjectRef*> g_slots[kChunks];
std::atomic<uint32_t> g_slot_count{1};  // slot 0 is never used
std::mutex g_ptr_lock;                  // slot allocation and g_by_ptr
std::unordered_map<uint32_t, Object*> g_by_ptr;  // guest address to its current object

std::mutex g_names_lock;
std::unordered_map<std::string, std::weak_ptr<Object>> g_names;

Object* SlotObject(uint32_t slot) {
    return g_slots[slot >> kChunkBits].load(std::memory_order_relaxed)[slot & (kChunkSize - 1)].get();
}

// caller holds g_ptr_lock
uint32_t AddSlot(ObjectRef obj) {
    uint32_t slot = g_slot_count.load(std::memory_order_relaxed);
    if ((slot >> kChunkBits) >= kChunks) {
        LOGE("objects: dispatcher table full");
        std::abort();
    }
    ObjectRef* chunk = g_slots[slot >> kChunkBits].load(std::memory_order_relaxed);
    if (!chunk) {
        chunk = new ObjectRef[kChunkSize];
        g_slots[slot >> kChunkBits].store(chunk, std::memory_order_relaxed);
    }
    obj->slot = slot;
    chunk[slot & (kChunkSize - 1)] = std::move(obj);
    g_slot_count.store(slot + 1, std::memory_order_release);
    return slot;
}

// slot in WaitListHead.Flink, stamp in Blink
void Stamp(uint32_t guest, uint32_t slot) {
    W32(guest + 8, slot);
    W32(guest + 12, kStamp);
}

}  // namespace

std::mutex& DispatchLock() { return g_dispatch; }

uint32_t NewHandle(ObjectRef obj) {
    std::lock_guard<std::mutex> lock(g_handles_lock);
    uint32_t h = g_next_handle;
    g_next_handle += 4;
    g_handles[h] = std::move(obj);
    return h;
}

ObjectRef FromHandle(uint32_t handle) {
    if (handle == 0xFFFFFFFE) return CurrentRef();  // NtCurrentThread pseudo handle
    std::lock_guard<std::mutex> lock(g_handles_lock);
    auto it = g_handles.find(handle);
    return it == g_handles.end() ? nullptr : it->second;
}

bool CloseHandle(uint32_t handle) {
    std::lock_guard<std::mutex> lock(g_handles_lock);
    return g_handles.erase(handle) != 0;
}

uint32_t DuplicateHandle(uint32_t handle) {
    ObjectRef o = FromHandle(handle);
    return o ? NewHandle(o) : 0;
}

void Bind(ObjectRef obj, uint32_t guest) {
    W32(guest + 4, uint32_t(std::atomic_ref<int32_t>(obj->local).load()));  // the header holds the state from here on
    obj->guest = guest;
    std::lock_guard<std::mutex> lock(g_ptr_lock);
    g_by_ptr[guest] = obj.get();
    Stamp(guest, AddSlot(std::move(obj)));
}

// the object for a header seen for the first time or reinitialised by the guest; caller holds g_ptr_lock
static Object* Rebuild(uint32_t guest) {
    auto it = g_by_ptr.find(guest);
    Object* old = it == g_by_ptr.end() ? nullptr : it->second;
    if (old && R32(guest + 12) == kStamp && R32(guest + 8) == old->slot) return old;  // rebuilt by another thread
    uint8_t type = G<uint8_t>(guest);
    if (old && (type == 6 || old->type == ObjType::Thread)) {  // threads keep their object
        Stamp(guest, old->slot);
        return old;
    }
    ObjType t;
    bool notification = false;
    switch (type) {
        case 0: case 1: t = ObjType::Event; notification = type == 0; break;
        case 2: t = ObjType::Mutant; break;
        case 5: t = ObjType::Semaphore; break;
        case 8: case 9: t = ObjType::Timer; notification = type == 8; break;
        case 6: t = ObjType::Other; break;
        default:
            LOGW("objects: unknown dispatcher type %u at %08X", type, guest);
            if (Current()) LogGuestStack(*Current()->ctx, 64);
            t = ObjType::Event;
            notification = true;
            break;
    }
    int32_t limit = type == 5 ? int32_t(R32(guest + 0x10)) : 0;
    {
        // a reinitialised header with nobody blocked on it keeps its object, so the table grows with addresses only
        std::lock_guard<std::mutex> dl(g_dispatch);
        if (old && old->shadow && old->waiters.load(std::memory_order_relaxed) == 0) {
            old->type = t;
            old->notification = notification;
            old->limit = limit;
            old->owner.store(0, std::memory_order_relaxed);
            old->recursion = 0;
            Stamp(guest, old->slot);
            return old;
        }
    }
    auto o = std::make_shared<Object>(t);
    o->notification = notification;
    o->limit = limit;
    o->shadow = true;
    o->guest = guest;
    Object* p = o.get();
    g_by_ptr[guest] = p;
    Stamp(guest, AddSlot(std::move(o)));
    return p;
}

Object* Dispatcher(uint32_t guest) {
    if (!guest) return nullptr;
    if (R32(guest + 12) == kStamp) {
        uint32_t slot = R32(guest + 8);
        if (slot && slot < g_slot_count.load(std::memory_order_acquire)) {
            Object* o = SlotObject(slot);
            if (o->guest == guest) return o;
        }
    }
    std::lock_guard<std::mutex> lock(g_ptr_lock);
    return Rebuild(guest);
}

ObjectRef FromPointer(uint32_t guest) {
    Object* o = Dispatcher(guest);
    if (!o) return nullptr;
    return g_slots[o->slot >> kChunkBits].load(std::memory_order_relaxed)[o->slot & (kChunkSize - 1)];
}

ObjectRef FindNamed(const std::string& name) {
    std::lock_guard<std::mutex> lock(g_names_lock);
    auto it = g_names.find(name);
    return it == g_names.end() ? nullptr : it->second.lock();
}

void AddNamed(const std::string& name, ObjectRef obj) {
    std::lock_guard<std::mutex> lock(g_names_lock);
    obj->name = name;
    g_names[name] = obj;
}

// waits

static uint32_t Me(Thread* t) { return t ? t->ethread : 1; }

// Takes the object for the waiter `me` if it is signalled: an auto-reset event or timer is reset, a semaphore count
// taken, a mutant owned (or entered again by its owner). Acquire on success, so the signaller's writes are visible.
// `order` is seq_cst for the check a blocking waiter makes after it has registered, against a signaller's check of
// the waiter count.
static bool TryTake(Object& o, uint32_t me, std::memory_order order = std::memory_order_acquire) {
    auto s = o.state();
    switch (o.type) {
        case ObjType::Event:
        case ObjType::Timer:
            if (!o.notification) {
                int32_t v = s.load(order);
                while (v > 0)
                    if (s.compare_exchange_weak(v, 0, order, order)) {
                        return true;
                    }
                return false;
            }
            return s.load(order) > 0;
        case ObjType::Semaphore: {
            int32_t v = s.load(order);
            while (v > 0)
                if (s.compare_exchange_weak(v, v - 1, order, order)) {
                    return true;
                }
            return false;
        }
        case ObjType::Mutant: {
            if (o.owner.load(std::memory_order_relaxed) == me) {
                o.recursion++;
                return true;
            }
            int32_t v = s.load(order);
            while (v > 0)
                if (s.compare_exchange_weak(v, 0, order, order)) {
                    o.owner.store(me, std::memory_order_relaxed);
                    o.recursion = 1;
                    return true;
                }
            return false;
        }
        default:
            return s.load(order) > 0;
    }
}

// gives back what TryTake took, for a wait-all that could not take every object
static void Untake(Object& o) {
    auto s = o.state();
    switch (o.type) {
        case ObjType::Event:
        case ObjType::Timer:
            if (!o.notification) s.store(1, std::memory_order_release);
            break;
        case ObjType::Semaphore:
            s.fetch_add(1, std::memory_order_release);
            break;
        case ObjType::Mutant:
            if (--o.recursion == 0) {
                o.owner.store(0, std::memory_order_relaxed);
                s.store(1, std::memory_order_release);
            }
            break;
        default:
            break;
    }
}

static bool Signalled(const Object& o) { return o.state().load(std::memory_order_relaxed) > 0; }

// A wait-all takes every object or none. It runs under the dispatcher lock, which resets and pulses take too, so the
// only changes it can race with are takes by waits that do not block and sets; a take that loses such a race is given
// back.
static bool TryTakeAll(Object* const* objs, size_t n, uint32_t me, std::memory_order order) {
    for (size_t i = 0; i < n; i++)
        if (!objs[i] || (!(objs[i]->type == ObjType::Mutant && objs[i]->owner.load(std::memory_order_relaxed) == me) &&
                         objs[i]->state().load(order) <= 0))
            return false;
    for (size_t i = 0; i < n; i++) {
        bool dup = false;
        for (size_t j = 0; j < i; j++) dup |= objs[j] == objs[i];
        if (dup && objs[i]->type != ObjType::Mutant) continue;  // one object listed twice is satisfied once
        if (!TryTake(*objs[i], me, order)) {
            for (size_t j = i; j-- > 0;) {
                bool dupj = false;
                for (size_t k = 0; k < j; k++) dupj |= objs[k] == objs[j];
                if (!dupj || objs[j]->type == ObjType::Mutant) Untake(*objs[j]);
            }
            return false;
        }
    }
    return true;
}

// index of the object the wait took, -1 when none
static int32_t TryWait(Object* const* objs, size_t n, bool all, uint32_t me, std::memory_order order) {
    if (all) return TryTakeAll(objs, n, me, order) ? 0 : -1;
    for (size_t i = 0; i < n; i++)
        if (objs[i] && TryTake(*objs[i], me, order)) return int32_t(i);
    return -1;
}

// Satisfies the blocked waiters of `o` that its new state allows, in arrival order, taking the object for each:
// one for an auto-reset event or a mutant, as many as the count for a semaphore, all for a notification object.
// Caller holds the dispatcher lock.
static void SatisfyWaiters(Object& o) {
    for (Waiter* w : o.wait_list) {
        if (!Signalled(o)) break;
        if (w->result >= 0) continue;
        int32_t r = -1;
        if (w->all) {
            if (TryTakeAll(w->objs, w->count, w->me, std::memory_order_seq_cst)) r = 0;
        } else {
            for (size_t i = 0; i < w->count; i++)
                if (w->objs[i] == &o) {
                    if (TryTake(o, w->me, std::memory_order_seq_cst)) r = int32_t(i);
                    break;
                }
        }
        if (r >= 0) {
            w->result = r;
            w->cv.notify_one();
        }
    }
}

// after a state change that may satisfy a wait: the seq_cst change and this seq_cst read of the waiter count pair
// with a waiter's seq_cst count increment and re-check, so one of the two sees the other
static void WakeWaiters(Object& o) {
    if (o.waiters.load(std::memory_order_seq_cst) == 0) return;
    std::lock_guard<std::mutex> lock(g_dispatch);
    SatisfyWaiters(o);
}

void SetSignal(Object& o, int32_t v) {
    o.state().exchange(v, std::memory_order_seq_cst);
    if (v > 0) WakeWaiters(o);
}

int64_t Now100ns() {
    using namespace std::chrono;
    // 1601 to 1970 in 100 ns units
    auto t = duration_cast<nanoseconds>(system_clock::now().time_since_epoch()).count();
    return t / 100 + 116444736000000000ll;
}

int64_t ToDeadline(int64_t due) {
    using namespace std::chrono;
    int64_t now = duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count();
    if (due < 0) return now + (-due) * 100;  // negative due is relative, positive is absolute system time
    int64_t rel = due - Now100ns();
    return now + std::max<int64_t>(rel, 0) * 100;
}

void WakeAlertable(Waiter& w) { w.cv.notify_one(); }

static bool ApcPending(Thread& t) {
    std::lock_guard<std::mutex> al(t.apc_lock);
    return !t.apcs.empty();
}

static inline void SuspendCheck(Thread* t) {
    if (t && t->suspend.load(std::memory_order_relaxed) > 0) SuspendPoint();
}

// Objects are checked before APCs: a signalled object satisfies even an alertable wait with APCs queued. A blocked
// wait sleeps until a signaller satisfies it, its deadline, or (alertable) an APC is queued; it does not poll.
uint32_t Wait(Object* const* objs, size_t n, bool wait_all, int64_t timeout, bool alertable) {
    using namespace std::chrono;
    Thread* self = Current();
    SuspendCheck(self);
    uint32_t me = Me(self);
    uint32_t r;
    if (int32_t i = wait_all ? -1 : TryWait(objs, n, false, me, std::memory_order_acquire); i >= 0) {
        r = kWait0 + uint32_t(i);
    } else if (timeout == 0 && !wait_all) {
        r = kTimeout;
        if (alertable && self && ApcPending(*self)) {
            RunApcs(*self);
            r = kUserApc;
        }
    } else {
        bool infinite = timeout == INT64_MAX;
        int64_t deadline = infinite ? 0 : ToDeadline(timeout);
        Waiter w{objs, n, wait_all, me, -1, {}};
        std::unique_lock<std::mutex> lock(g_dispatch);
        for (size_t i = 0; i < n; i++)
            if (objs[i]) {
                objs[i]->wait_list.push_back(&w);
                objs[i]->waiters.fetch_add(1, std::memory_order_seq_cst);
            }
        if (alertable && self) self->alertable_wait = &w;
        for (;;) {
            if (w.result >= 0) {
                r = kWait0 + uint32_t(w.result);
                break;
            }
            if (int32_t i = TryWait(objs, n, wait_all, me, std::memory_order_seq_cst); i >= 0) {
                r = kWait0 + uint32_t(i);
                break;
            }
            if (alertable && self && ApcPending(*self)) {
                r = kUserApc;
                break;
            }
            if (infinite) {
                w.cv.wait(lock);
                continue;
            }
            int64_t now = duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count();
            if (now >= deadline) {
                r = kTimeout;
                break;
            }
            w.cv.wait_until(lock, steady_clock::time_point(duration_cast<steady_clock::duration>(nanoseconds(deadline))));
        }
        for (size_t i = 0; i < n; i++)
            if (objs[i]) {
                auto& l = objs[i]->wait_list;
                l.erase(std::find(l.begin(), l.end(), &w));
                objs[i]->waiters.fetch_sub(1, std::memory_order_relaxed);
            }
        if (alertable && self) self->alertable_wait = nullptr;
        lock.unlock();
        if (r == kUserApc) RunApcs(*self);
    }
    SuspendCheck(self);
    return r;
}

uint32_t Wait(const std::vector<ObjectRef>& objs, bool wait_all, int64_t timeout, bool alertable) {
    Object* raw[64];
    size_t n = std::min<size_t>(objs.size(), 64);  // MAXIMUM_WAIT_OBJECTS
    for (size_t i = 0; i < n; i++) raw[i] = objs[i].get();
    return Wait(raw, n, wait_all, timeout, alertable);
}

int32_t SetEvent(Object& o) {
    int32_t old = o.state().exchange(1, std::memory_order_seq_cst);
    WakeWaiters(o);
    return old;
}

int32_t ResetEvent(Object& o) {
    std::lock_guard<std::mutex> lock(g_dispatch);
    int32_t old = o.state().exchange(0, std::memory_order_relaxed);
    return old;
}

// set, satisfy the waiters blocked now, reset
int32_t PulseEvent(Object& o) {
    std::lock_guard<std::mutex> lock(g_dispatch);
    int32_t old = o.state().exchange(1, std::memory_order_seq_cst);
    SatisfyWaiters(o);
    o.state().store(0, std::memory_order_relaxed);
    return old;
}

int32_t ReleaseSemaphore(Object& o, int32_t count, uint32_t& status) {
    int32_t old = o.state().load(std::memory_order_relaxed);
    do {
        if (o.limit && old + count > o.limit) {
            status = kSemaphoreLimitExceeded;
            return old;
        }
    } while (!o.state().compare_exchange_weak(old, old + count, std::memory_order_seq_cst, std::memory_order_relaxed));
    status = kSuccess;
    WakeWaiters(o);
    return old;
}

int32_t ReleaseMutant(Object& o, uint32_t& status) {
    uint32_t me = Me(Current());
    if (o.owner.load(std::memory_order_relaxed) != me) {
        status = kMutantNotOwned;
        return o.state().load(std::memory_order_relaxed);
    }
    int32_t old = o.state().load(std::memory_order_relaxed);
    status = kSuccess;
    if (--o.recursion == 0) {
        o.owner.store(0, std::memory_order_relaxed);
        o.state().exchange(1, std::memory_order_seq_cst);
        WakeWaiters(o);
    }
    return old;
}

// timers and DPCs

namespace {

struct TimerEntry {
    int64_t deadline;
    uint64_t seq;
    ObjectRef timer;
    int32_t period_ms;
    uint32_t dpc;
    std::weak_ptr<Thread> apc_thread;
    uint32_t apc_routine, apc_context;
    bool operator>(const TimerEntry& o) const { return deadline > o.deadline; }
};

std::mutex g_timer_lock;
std::condition_variable g_timer_cv;
std::priority_queue<TimerEntry, std::vector<TimerEntry>, std::greater<TimerEntry>> g_timers;
std::unordered_map<Object*, uint64_t> g_timer_seq;  // latest arm per timer, older entries are stale
uint64_t g_seq = 1;
bool g_timer_thread = false;

std::mutex g_dpc_lock;
std::condition_variable g_dpc_cv;
std::deque<std::array<uint32_t, 3>> g_dpcs;
bool g_dpc_thread = false;

}  // namespace

void RunDpcs(X86Context& ctx) {
    for (;;) {
        std::array<uint32_t, 3> d;
        {
            std::unique_lock<std::mutex> lock(g_dpc_lock);
            g_dpc_cv.wait(lock, [] { return !g_dpcs.empty(); });
            d = g_dpcs.front();
            g_dpcs.pop_front();
        }
        uint32_t dpc = d[0];
        G<uint8_t>(dpc + 2) = 0;  // Inserted
        uint32_t routine = R32(dpc + 0x0C), context = R32(dpc + 0x10);  // KDPC.DeferredRoutine and DeferredContext
        if (routine) CallGuest(ctx, routine, {dpc, context, d[1], d[2]});
    }
}

void QueueDpc(uint32_t dpc, uint32_t arg1, uint32_t arg2) {
    std::lock_guard<std::mutex> lock(g_dpc_lock);
    W32(dpc + 0x14, arg1);  // KDPC.SystemArgument1 and 2
    W32(dpc + 0x18, arg2);
    g_dpcs.push_back({dpc, arg1, arg2});
    g_dpc_cv.notify_one();
    if (!g_dpc_thread) {
        g_dpc_thread = true;
        StartHostThread("dpc", [](X86Context& ctx) { RunDpcs(ctx); });
    }
}

static void TimerLoop() {
    using namespace std::chrono;
    PlaceHostThread("timers");
    std::unique_lock<std::mutex> lock(g_timer_lock);
    for (;;) {
        if (g_timers.empty()) {
            g_timer_cv.wait(lock);
            continue;
        }
        int64_t now = duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count();
        TimerEntry e = g_timers.top();
        if (e.deadline > now) {
            g_timer_cv.wait_for(lock, nanoseconds(e.deadline - now));
            continue;
        }
        g_timers.pop();
        auto it = g_timer_seq.find(e.timer.get());
        if (it == g_timer_seq.end() || it->second != e.seq) continue;
        SetSignal(*e.timer, 1);
        if (e.dpc) QueueDpc(e.dpc, uint32_t(Now100ns()), uint32_t(Now100ns() >> 32));
        if (auto t = e.apc_thread.lock(); t && e.apc_routine)
            QueueApc(*t, e.apc_routine, e.apc_context, uint32_t(Now100ns()), uint32_t(Now100ns() >> 32));
        if (e.period_ms > 0) {
            e.deadline += int64_t(e.period_ms) * 1000000;
            g_timers.push(e);
        } else {
            g_timer_seq.erase(e.timer.get());
        }
    }
}

void SetTimer(ObjectRef timer, int64_t due, int32_t period_ms, uint32_t dpc, std::shared_ptr<Thread> apc_thread,
              uint32_t apc_routine, uint32_t apc_context) {
    std::lock_guard<std::mutex> lock(g_timer_lock);
    if (!g_timer_thread) {
        g_timer_thread = true;
        std::thread(TimerLoop).detach();
    }
    timer->state().store(0, std::memory_order_relaxed);
    uint64_t seq = g_seq++;
    g_timer_seq[timer.get()] = seq;
    g_timers.push({ToDeadline(due), seq, timer, period_ms, dpc, apc_thread, apc_routine, apc_context});
    g_timer_cv.notify_all();
}

bool CancelTimer(Object& timer) {
    std::lock_guard<std::mutex> lock(g_timer_lock);
    return g_timer_seq.erase(&timer) != 0;
}

}  // namespace kernel
