#ifndef _etc_hpp
#define _etc_hpp

//#include <memory>
#include <jansson.h>
#include <legato.h>


// Resource management functions
// All those functions implements RAII (resource acquisition as initialization) concept
// They're using standard std::unique_ptr in their implementation
// They create small object that manages associated resource. Once the object goes out of scope,
//  the resource is released.

#if 0
template<typename P, typename D>
decltype(auto) make_unique_handle(P p, D deleter) {
	return std::unique_ptr<std::remove_pointer_t<P>, D>(p, deleter);
}

inline
decltype(auto) make_unique_handle(char *p) {
    return make_unique_handle(p, free);
}

inline
decltype(auto) json_to_str(json_t *obj, size_t flags=0) {
    return make_unique_handle(json_dumps(obj, flags));
}

inline
decltype(auto) make_unique_handle(json_t *j) {
    return make_unique_handle(j, json_decref);
}
#endif

//#include <chrono>
//#include <mutex>
#include <pthread.h>

#define USE_PERTHTREAD_CLOCK 1

inline
int64_t now_tp() {
    static std::once_flag flag;
    static bool has_perthread_clock = false;

    std::call_once(flag, [] {
        clockid_t clock_id;
        int res = pthread_getcpuclockid(pthread_self(), &clock_id);
        has_perthread_clock = (res == 0);
        if(!has_perthread_clock) {
            LE_ERROR("no per-thread clock found, err=%d", res);
        }
    });

    if(!has_perthread_clock) {
	    return std::chrono::steady_clock::now().time_since_epoch().count();
    }

    struct timespec cur_time;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &cur_time);
    int64_t res = cur_time.tv_sec * 1000000000 + cur_time.tv_nsec;
    return res;
}

inline
int64_t now_tp_abs() {
	struct timespec cur_time;

    clock_gettime(CLOCK_BOOTTIME, &cur_time);
    int64_t res = cur_time.tv_sec * 1000000000 + cur_time.tv_nsec;
    return res;    
}

#include <type_traits>

template<typename T>
class scoped_time_measurement_t {
    using time_point = decltype(now_tp());

    time_point m_tp;
    time_point m_tpabs;
    const char *m_descr;

    public:

    scoped_time_measurement_t(const char *descr): 
        m_tp(now_tp()), 
        m_tpabs(now_tp_abs()), 
        m_descr(descr)
    {
        LE_DEBUG("@-->Start %s", m_descr) ;
    }

    ~scoped_time_measurement_t() {
        auto cur = now_tp();
        auto cur_abs = now_tp_abs();
        LE_DEBUG("@-->End %s diff=%lld, diff_abs=%lld", m_descr, (cur - m_tp) / 1000, (cur_abs - m_tpabs) / 1000);
    }
};

template<>
class scoped_time_measurement_t<std::false_type> {
    public:

    scoped_time_measurement_t(const char *) {}
    ~scoped_time_measurement_t() {}
};

#define USE_TIME_MEASUREMENT 0
using scoped_time_measurement = scoped_time_measurement_t<std::bool_constant<USE_TIME_MEASUREMENT>>;

#define measure_func_time(func_call) ({ \
    scoped_time_measurement __m(#func_call); \
    func_call; \
})

#endif

