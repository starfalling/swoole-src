/*
  +----------------------------------------------------------------------+
  | Swoole                                                               |
  +----------------------------------------------------------------------+
  | This source file is subject to version 2.0 of the Apache license,    |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.apache.org/licenses/LICENSE-2.0.html                      |
  | If you did not receive a copy of the Apache2.0 license and are unable|
  | to obtain it through the world-wide-web, please send a note to       |
  | license@swoole.com so we can mail you a copy immediately.            |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  +----------------------------------------------------------------------+
*/

#include "swoole_coroutine_context.h"
#include "php_swoole_cxx.h"
#include "zend_builtin_functions.h"
#if __linux__
#include <sys/mman.h>
#endif

#ifndef SW_USE_THREAD_CONTEXT

#define MAGIC_STRING "swoole_coroutine#5652a7fb2b38be"
#define START_OFFSET (64 * 1024)

#if !defined(MAP_ANONYMOUS) && defined(MAP_ANON)
#define MAP_ANONYMOUS MAP_ANON
#endif

static zend_always_inline zval *zend_hash_find(const HashTable *ht, char *key) {
    zend_string *key_zend = zend_string_init(key, strlen(key), 0);
    zval *result = zend_hash_find(ht, key_zend);
    zend_string_release(key_zend);
    return result;
}

namespace swoole {
namespace coroutine {

Context::Context(size_t stack_size, const coroutine_func_t &fn, void *private_data)
    : fn_(fn), stack_size_(stack_size), private_data_(private_data) {
    end_ = false;
    last_swap_in_time_ = 0;
    prev_run_duration_ = 0;

#ifdef SW_CONTEXT_PROTECT_STACK_PAGE
    stack_ = (char *) ::mmap(0, stack_size_, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#else
    stack_ = (char *) sw_malloc(stack_size_);
#endif
    if (!stack_) {
        swFatalError(SW_ERROR_MALLOC_FAIL, "failed to malloc stack memory.");
        exit(254);
    }
    swTraceLog(SW_TRACE_COROUTINE, "alloc stack: size=%u, ptr=%p", stack_size_, stack_);

    void *sp = (void *) ((char *) stack_ + stack_size_);
#ifdef USE_VALGRIND
    valgrind_stack_id = VALGRIND_STACK_REGISTER(sp, stack_);
#endif

#if USE_UCONTEXT
    if (-1 == getcontext(&ctx_)) {
        swoole_throw_error(SW_ERROR_CO_GETCONTEXT_FAILED);
        sw_free(stack_);
        return;
    }
    ctx_.uc_stack.ss_sp = stack_;
    ctx_.uc_stack.ss_size = stack_size;
    ctx_.uc_link = nullptr;
    makecontext(&ctx_, (void (*)(void)) & context_func, 1, this);
#else
    ctx_ = make_fcontext(sp, stack_size_, (void (*)(intptr_t)) & context_func);
    swap_ctx_ = nullptr;
#endif

#ifdef SW_CONTEXT_DETECT_STACK_USAGE
    size_t offset = START_OFFSET;
    while (offset <= stack_size) {
        memcpy((char *) sp - offset + (sizeof(MAGIC_STRING) - 1), SW_STRL(MAGIC_STRING));
        offset *= 2;
    }
#endif

#ifdef SW_CONTEXT_PROTECT_STACK_PAGE
    mprotect(stack_, SwooleG.pagesize, PROT_NONE);
#endif
}

Context::~Context() {
    if (stack_) {
        swTraceLog(SW_TRACE_COROUTINE, "free stack: ptr=%p", stack_);
#ifdef USE_VALGRIND
        VALGRIND_STACK_DEREGISTER(valgrind_stack_id);
#endif

#ifdef SW_CONTEXT_PROTECT_STACK_PAGE
        ::munmap(stack_, stack_size_);
#else
        sw_free(stack_);
#endif
        stack_ = nullptr;
    }
}

#ifdef SW_CONTEXT_DETECT_STACK_USAGE
ssize_t Context::get_stack_usage() {
    size_t offset = START_OFFSET;
    size_t retval = START_OFFSET;

    void *sp = (void *) ((char *) stack_ + stack_size_);

    while (offset < stack_size_) {
        if (memcmp((char *) sp - offset + (sizeof(MAGIC_STRING) - 1), SW_STRL(MAGIC_STRING)) != 0) {
            retval = offset * 2;
        }
        offset *= 2;
    }

    return retval;
}
#endif

void Context::print_backtrace(zval *debug_backtrace) {
    zval current_debug_backtrace;
    if (debug_backtrace == NULL) {
        zend_fetch_debug_backtrace(&current_debug_backtrace, 0, DEBUG_BACKTRACE_IGNORE_ARGS, 0);
        debug_backtrace = &current_debug_backtrace;
    }
    zend_ulong idx;
    zend_string *key;
    zval *val;
    ZEND_HASH_FOREACH_KEY_VAL(Z_ARR_P(debug_backtrace), idx, key, val) {
        zval *line_zval = zend_hash_find(Z_ARR_P(val), "line");
        long line = 0;
        if (line_zval != NULL) {
            convert_to_long(line_zval);
            line = Z_LVAL_P(line_zval);
        }

        zval *file_zval = zend_hash_find(Z_ARR_P(val), "file");
        char *file = const_cast<char *>(file_zval == NULL ? "UNKNOWN" : ZSTR_VAL(Z_STR_P(file_zval)));

        printf("% 3d# %s(%d)\n", idx, file, line);
    }
    ZEND_HASH_FOREACH_END();
}

bool Context::swap_in() {
    if (prev_run_duration_ > 0.01) {
        printf("WARNING: 协程单次执行时间过长 %.6fs, cid=%ld\n", swoole_microtime() - last_swap_in_time_, cid_);
        printf("================== SWAP IN  ==================\n");
        print_backtrace(&last_swap_in_debug_backtrace_);
        printf("================== SWAP OUT ==================\n");
        print_backtrace(nullptr);
        prev_run_duration_ = 0;
    }
    origin_cid_ = Coroutine::get_current()->get_origin_cid();
//    printf("swap in is called, cid=%ld, origin cid=%ld\n", cid_, origin_cid_);
    last_swap_in_time_ = swoole_microtime();
    zend_fetch_debug_backtrace(&last_swap_in_debug_backtrace_, 0, DEBUG_BACKTRACE_IGNORE_ARGS, 0);
//    print_backtrace(&last_swap_in_debug_backtrace_);
#if USE_UCONTEXT
    return 0 == swapcontext(&swap_ctx_, &ctx_);
#else
    jump_fcontext(&swap_ctx_, ctx_, (intptr_t) this, true);
    return true;
#endif
}

bool Context::swap_out() {
    prev_run_duration_ = swoole_microtime() - last_swap_in_time_;
//    printf("Context::swap_out is called, cid=%d, origin cid=%ld\n", cid_, origin_cid_);
    if (prev_run_duration_ > 0.01 && end_) {
        printf("WARNING: 协程单次执行时间过长 %.6fs, cid=%ld\n", swoole_microtime() - last_swap_in_time_, cid_);
        printf("================== SWAP IN  ==================\n");
        print_backtrace(&last_swap_in_debug_backtrace_);
        printf("================== SWAP OUT ==================\n");
        print_backtrace(nullptr);
    }
    if (origin_cid_ > 0) {
        Coroutine *origin_coroutine = Coroutine::get_by_cid(origin_cid_);
        if (origin_coroutine != nullptr) {
            coroutine::Context *origin_ctx = origin_coroutine->get_ctx();
            origin_ctx->last_swap_in_time_ = swoole_microtime();
            origin_ctx->prev_run_duration_ = 0;
        }
    }

#if USE_UCONTEXT
    return 0 == swapcontext(&ctx_, &swap_ctx_);
#else
    jump_fcontext(&ctx_, swap_ctx_, (intptr_t) this, true);
    return true;
#endif
}

void Context::context_func(void *arg) {
    Context *_this = (Context *) arg;
//    printf("context_func is called, cid=%ld\n", _this->cid_);
    _this->last_swap_in_time_ = swoole_microtime();
    zend_fetch_debug_backtrace(&_this->last_swap_in_debug_backtrace_, 0, DEBUG_BACKTRACE_IGNORE_ARGS, 0);
    _this->fn_(_this->private_data_);
    _this->end_ = true;
    _this->swap_out();
}
}  // namespace coroutine
}  // namespace swoole
#endif
