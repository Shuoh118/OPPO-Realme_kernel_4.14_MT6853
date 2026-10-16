#!/bin/bash
# =============================================================================
# 7kimisu -> Linux 4.14 (MT6853) 兼容补丁
# 由 "Build Kernel for MT6853" 工作流在放置 drivers/kernelsu 后自动调用。
#
# 用法: 7kimisu-414-compat.sh <drivers/kernelsu 路径> [susfs]
#   第二个参数传 "susfs" 时，额外注入 SUSFS 集成层（需同时打
#   susfs_patch_to_4.14.patch VFS 补丁，由工作流负责）
#
# 7kimisu 内核组件面向 5.x/6.x 编写，直接放进 4.14 树会编译失败。
# 本脚本做三类处理：
#   1. 精确替换：给新版 API 调用加版本守卫或改写成 4.14 等价写法
#   2. 整体 stub：将深度依赖 5.x+ 内部结构（selinux_state.policy RCU 机制、
#      struct seccomp_filter cache 字段、selinux_hide 的 status page 机制）
#      的特性在 4.14 上置空，保证内核可编译、su 基本功能可用
#   3. 头物化：把仓库根 uapi/ 的 UAPI 头（内嵌构建只拷 kernel/，会漏掉）
#      原样落到 drivers/kernelsu/uapi/，并给 Kbuild 补 selinux 生成头的
#      查找路径与依赖
#
# 已知 4.14 限制（相对新版内核）：
#   - apply_kernelsu_rules / handle_sepolicy 不可用（sepolicy 规则注入需要
#     5.x+ 的 selinux_state.policy 机制，该 4.14.186 内核未 backport），
#     su 的 SELinux 域切换本身可用
#   - SELinux 隐身（selinux_hide）不可用
#   - seccomp filter cache 不可用
#   - LSM hook 运行期 patcher（lsm_hook）置空：4.14 的 security_hook_heads
#     是 list_head 布局，上游 patcher 只适配 5.4+ 的 hlist 布局；4.14 的
#     syscall 挂钩走 kprobes，本仓库无 lsm hook 调用方
#   - manager 的 packages.list 监听（pkg_observer）置空：4.14 的
#     fsnotify_ops 无 handle_inode_event；throne tracker 仍由 boot 事件驱动
#   - file wrapper 在 4.14 不包装 iopoll/remap_file_range/fadvise（4.14 的
#     file_operations 无这三个成员），未包装的调用直接透传
# =============================================================================
set -e

KSU_DIR="${1:-drivers/kernelsu}"
WITH_SUSFS="${2:-}"
cd "$KSU_DIR"

python3 - <<'PYEOF'
import sys

def apply_patches(path, pairs, required=True):
    try:
        with open(path, encoding='utf-8') as f:
            s = f.read()
    except FileNotFoundError:
        print(f"[414compat] ERROR: {path} not found")
        sys.exit(1)
    changed = False
    for pair in pairs:
        old, new = pair[0], pair[1]
        # unique 默认 True：锚点必须唯一，防止上游变动后静默打错补丁。
        # 短串替换（如 file->f_inode）显式传 False 允许多处命中全量替换。
        unique = pair[2] if len(pair) > 2 else True
        n = s.count(old)
        if n > 1 and unique:
            print(f"[414compat] ERROR: pattern occurs {n} times in {path} (expected 1):")
            print("----- 8< -----")
            print(old[:400])
            print("----- >8 -----")
            print("[414compat] 7kimisu 上游可能有变动，请更新本补丁脚本")
            sys.exit(1)
        if n >= 1:
            s = s.replace(old, new)
            changed = True
            print(f"[414compat] {path}: patched ({n} hit{'s' if n > 1 else ''})")
        elif required:
            print(f"[414compat] ERROR: pattern not found in {path}:")
            print("----- 8< -----")
            print(old[:400])
            print("----- >8 -----")
            sys.exit(1)
        else:
            print(f"[414compat] {path}: pattern absent, skip")
    if changed:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(s)

# ---------------------------------------------------------------------------
# 1) core/init.c: MODULE_IMPORT_NS 是 5.13+ 的宏，4.14 不存在。
#    内嵌构建（非 MODULE）不需要它，直接按版本裁掉。
# ---------------------------------------------------------------------------
apply_patches('core/init.c', [(
"""#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS("VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
#else
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif""",
"""#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 13, 0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS("VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
#else
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
#endif""",
)])

# ---------------------------------------------------------------------------
# 2) hook/arm64/patch_memory.c: p4d 层是 4.17+ 引入的，4.14 的 arm64 页表
#    只有 pgd/pud/pmd/pte 四级。给 p4d 相关代码加版本守卫。
# ---------------------------------------------------------------------------
apply_patches('hook/arm64/patch_memory.c', [
(
"""    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;""",
"""    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
    p4d_t *p4d;
#endif""",
),
(
"""    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        goto fail;
    pr_debug("p4d of 0x%lx p=0x%lx v=0x%lx", addr, (uintptr_t)p4d, (uintptr_t)p4d_val(*p4d));
#if defined(p4d_leaf)
    if (p4d_leaf(*p4d)) {
        pr_debug("Address 0x%lx maps to a P4D-level huge page\\n", addr);
        return __p4d_to_phys(*p4d) + ((addr & ~P4D_MASK));
    }
#endif

    pud = pud_offset(p4d, addr);""",
"""#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        goto fail;
    pr_debug("p4d of 0x%lx p=0x%lx v=0x%lx", addr, (uintptr_t)p4d, (uintptr_t)p4d_val(*p4d));
#if defined(p4d_leaf)
    if (p4d_leaf(*p4d)) {
        pr_debug("Address 0x%lx maps to a P4D-level huge page\\n", addr);
        return __p4d_to_phys(*p4d) + ((addr & ~P4D_MASK));
    }
#endif
    pud = pud_offset(p4d, addr);
#else
    pud = pud_offset(pgd, addr);
#endif""",
),
])

# ---------------------------------------------------------------------------
# 3) include/klog.h: __poll_t 是 4.16+ 引入的类型，4.14 用 unsigned int。
#    klog.h 被几乎所有 .c 包含，在这里统一补齐。
# ---------------------------------------------------------------------------
apply_patches('include/klog.h', [(
"""#ifndef __KSU_H_KLOG
#define __KSU_H_KLOG

#include <linux/printk.h>""",
"""#ifndef __KSU_H_KLOG
#define __KSU_H_KLOG

#include <linux/printk.h>
#include <linux/version.h>

/* Linux 4.16 引入了 __poll_t；4.14 及更早用 unsigned int */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0)
typedef unsigned int __poll_t;
#endif""",
)])

# ---------------------------------------------------------------------------
# 4) manager/throne_tracker.c: file->f_inode 是 4.19+ 的字段，
#    4.14 需要 file->f_path.dentry->d_inode。
# ---------------------------------------------------------------------------
apply_patches('manager/throne_tracker.c', [(
"file->f_inode->i_sb->s_magic",
"file->f_path.dentry->d_inode->i_sb->s_magic",
False,  # 该串在文件中出现多次，需要全部替换
)], required=False)
# 上面是整串替换；若源码写法有出入，逐个小节替换兜底
apply_patches('manager/throne_tracker.c', [(
"file->f_inode",
"file->f_path.dentry->d_inode",
False,  # 兜底短串，同样允许多处命中
)], required=False)

# ---------------------------------------------------------------------------
# 5) hook/arm64/syscall_hook.c: 4.19+ 才有 __arm64_sys_ni_syscall 包装符号，
#    4.14 只有 sys_ni_syscall。
# ---------------------------------------------------------------------------
apply_patches('hook/arm64/syscall_hook.c', [(
"""    ni_syscall = (unsigned long)ksu_resolve_symbol_for_functable_hook("__arm64_sys_ni_syscall");""",
"""#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
    ni_syscall = (unsigned long)ksu_resolve_symbol_for_functable_hook("__arm64_sys_ni_syscall");
#else
    ni_syscall = (unsigned long)ksu_resolve_symbol_for_functable_hook("sys_ni_syscall");
#endif""",
)])

# ---------------------------------------------------------------------------
# 6) selinux/selinux.c: 4.14 原版没有 selinux_cred() 宏（5.x+ 引入），
#    用 cred->security 直接访问等价。其余 selinux_state.enforcing /
#    selinux_state.disabled / avc_has_perm(&selinux_state, ...) 在该
#    4.14.186 内核已被 Android backport，原代码可直接使用。
#    （sepolicy 规则注入 selinux_state.policy 机制未被 backport，
#      rules.c 已在下方整体 stub。）
# ---------------------------------------------------------------------------
apply_patches('selinux/selinux.c', [(
"""#include "ksu.h"
""",
"""#include "ksu.h"

/* 4.14 无 selinux_cred() 宏，用 cred->security 等价替代 */
#ifndef selinux_cred
#define selinux_cred(cred) ((struct task_security_struct *)(cred)->security)
#endif
""",
)])

# ---------------------------------------------------------------------------
# 7) hook/arm64/patch_memory.c: copy_to_kernel_nofault 是 5.8+ 的 nofault
#    接口；4.14 的等价物是 probe_kernel_write——两者同为"0 成功 /
#    -EFAULT 失败"语义（4.14 mm/maccess.c: return ret ? -EFAULT : 0），
#    且同文件已有 probe_kernel_read 的使用先例。
# ---------------------------------------------------------------------------
apply_patches('hook/arm64/patch_memory.c', [(
"copy_to_kernel_nofault(",
"probe_kernel_write(",
)])

# ---------------------------------------------------------------------------
# 8) hook/arm64/patch_memory.c: Kbuild 探测 arch/arm64/include/asm/cacheflush.h
#    中的 __flush_dcache_area——4.14 该符号存在（L69），于是
#    KSU_NEW_DCACHE_FLUSH=0，编译走 #else 分支；而 __flush_icache_range
#    在 4.14 并不存在（同文件只有 flush_icache_range，L68）。
#    改用各版本都有的 flush_icache_range。
# ---------------------------------------------------------------------------
apply_patches('hook/arm64/patch_memory.c', [(
"#define ksu_flush_icache(start, end) __flush_icache_range(start, end)",
"#define ksu_flush_icache(start, end) flush_icache_range(start, end)",
)])

# ---------------------------------------------------------------------------
# 9) nofault uaccess 家族均为 5.8+ 引入，4.14 等价物（语义逐一核实）：
#      strncpy_from_user_nofault -> strncpy_from_user
#        （同样返回拷贝字节数 / -EFAULT；4.14 arm64 声明于
#         arch/arm64/include/asm/uaccess.h L349，经 linux/uaccess.h 可见）
#      copy_from_user_nofault     -> copy_from_user    （0 成功）
#      copy_to_user_nofault       -> copy_to_user      （0 成功）
#    涉及 feature/sucompat.c（x2）、runtime/ksud_integration.c（x3）、
#    sulog/event.c（x2）。hook/{riscv64,x86_64}/patch_memory.c 中也有
#    nofault 调用，但 arm64 构建不编译那两个目录，不管。
# ---------------------------------------------------------------------------
apply_patches('feature/sucompat.c', [(
"strncpy_from_user_nofault(",
"strncpy_from_user(",
False,
)])

apply_patches('runtime/ksud_integration.c', [(
"strncpy_from_user_nofault(",
"strncpy_from_user(",
), (
"copy_from_user_nofault(",
"copy_from_user(",
), (
"copy_to_user_nofault(",
"copy_to_user(",
)])

apply_patches('sulog/event.c', [(
"strncpy_from_user_nofault(",
"strncpy_from_user(",
False,
)])

# ---------------------------------------------------------------------------
# 10) infra/event_queue.c: struct_size() 是 4.18+ 的辅助宏；柔性数组成员
#     （__u8 payload[]）场景下 sizeof(*node) + len 与它完全等价
#     （struct_size 本身就是展开为 sizeof(*ptr) + size）。
# ---------------------------------------------------------------------------
apply_patches('infra/event_queue.c', [(
"node = kmalloc(struct_size(node, payload, len), gfp);",
"node = kmalloc(sizeof(*node) + len, gfp);",
)])

# ---------------------------------------------------------------------------
# 11) include/util.h: ksyscall 机制依赖 4.19+ 的 __arm64_sys_*(pt_regs *)
#     包装符号；4.14 的 arm64 SYSCALL_DEFINE 直生 sys_##name(直接参数)，
#     pt_regs 调用约定不适用。两个使用者（ksu_close_fd / ksu_sys_setns）
#     在 <4.19 时改为直调原语；sys_close / sys_setns 的声明在 4.14
#     linux/syscalls.h 中已有（L555 / L903），util.h 也已 include 该头。
#     ksyscall 宏 machinery 本身保留但不再被展开（4.14 下无编译错误）。
# ---------------------------------------------------------------------------
apply_patches('include/util.h', [(
"""#define ksu_close_fd(fd) ({ ksyscall(close, fd); })""",
"""#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0)
/* 4.14/4.17/4.18 无 __arm64_sys_* 包装符号，且 sys_ 原语为直接参数
 * 签名，直调即可 */
#define ksu_close_fd(fd) ({ sys_close(fd); })
#else
#define ksu_close_fd(fd) ({ ksyscall(close, fd); })
#endif""",
), (
"""#define ksu_sys_setns(fd, flags) ({ ksyscall(setns, fd, flags); })""",
"""#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0)
#define ksu_sys_setns(fd, flags) ({ sys_setns(fd, flags); })
#else
#define ksu_sys_setns(fd, flags) ({ ksyscall(setns, fd, flags); })
#endif""",
)])

# ---------------------------------------------------------------------------
# 12) infra/su_mount_ns.c:
#     a. ksys_unshare() 4.19 才从 SYSCALL_DEFINE1 中拆出；4.14 只有
#        sys_unshare(unsigned long)（syscalls.h L824，直接参数签名）。
#     b. path_mount() 是 5.x 引入的；4.14 唯一等价通路是
#        set_fs(KERNEL_DS) + sys_mount()（4.14 arm64：KERNEL_DS=UL(-1)，
#        __range_ok 直读 addr_limit，置 KERNEL_DS 后 access_ok 放行内核
#        指针；sys_mount 原型 syscalls.h L423）。
#     c. 补 linux/uaccess.h（set_fs/get_fs/mm_segment_t 的来源）。
# ---------------------------------------------------------------------------
apply_patches('infra/su_mount_ns.c', [(
"""extern int path_mount(const char *dev_name, struct path *path, const char *type_page, unsigned long flags,
                      void *data_page);""",
"""#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0)
extern int path_mount(const char *dev_name, struct path *path, const char *type_page, unsigned long flags,
                      void *data_page);
#endif""",
), (
"""static void ksu_mnt_ns_individual(void)
{
    long ret = ksys_unshare(CLONE_NEWNS);""",
"""#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0)
/* 4.14 无 ksys_unshare()（4.19 引入）；sys_unshare 为 SYSCALL_DEFINE1
 * 直生符号，直接调用等价 */
static long ksu_ksys_unshare(unsigned long unshare_flags)
{
    return sys_unshare(unshare_flags);
}
#define ksys_unshare ksu_ksys_unshare
#endif

static void ksu_mnt_ns_individual(void)
{
    long ret = ksys_unshare(CLONE_NEWNS);""",
), (
"""    // make root mount private
    struct path root_path;
    get_fs_root(current->fs, &root_path);
    int pm_ret = path_mount(NULL, &root_path, NULL, MS_PRIVATE | MS_REC, NULL);
    path_put(&root_path);""",
"""    // make root mount private
    struct path root_path;
    get_fs_root(current->fs, &root_path);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 5, 0)
    /* 4.14 无 path_mount()：set_fs(KERNEL_DS) + sys_mount 等价实现 */
    mm_segment_t old_fs = get_fs();
    set_fs(KERNEL_DS);
    int pm_ret = sys_mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL);
    set_fs(old_fs);
#else
    int pm_ret = path_mount(NULL, &root_path, NULL, MS_PRIVATE | MS_REC, NULL);
#endif
    path_put(&root_path);""",
), (
"""#include <linux/version.h>
#include <uapi/linux/mount.h>""",
"""#include <linux/version.h>
#include <linux/uaccess.h>
#include <uapi/linux/mount.h>""",
)])

# ---------------------------------------------------------------------------
# 13) feature/kernel_umount.c: path_umount() 同为 5.x 引入；4.14 用
#     set_fs(KERNEL_DS) + sys_umount()（原型 syscalls.h L426）。
#     需补 linux/syscalls.h 与 linux/uaccess.h。
# ---------------------------------------------------------------------------
apply_patches('feature/kernel_umount.c', [(
"""#include <linux/printk.h>
#include <linux/types.h>""",
"""#include <linux/printk.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/uaccess.h>""",
), (
"""extern int path_umount(struct path *path, int flags);

static void ksu_umount_mnt(const char *mnt, struct path *path, int flags)
{
    int err = path_umount(path, flags);
    if (err) {
        pr_info("umount %s failed: %d\\n", mnt, err);
    }
}""",
"""#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0)
extern int path_umount(struct path *path, int flags);
#endif

static void ksu_umount_mnt(const char *mnt, struct path *path, int flags)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 5, 0)
    /* 4.14 无 path_umount()：set_fs(KERNEL_DS) + sys_umount 等价实现 */
    mm_segment_t old_fs = get_fs();
    set_fs(KERNEL_DS);
    int err = sys_umount((char __user *)mnt, flags);
    set_fs(old_fs);
#else
    int err = path_umount(path, flags);
#endif
    if (err) {
        pr_info("umount %s failed: %d\\n", mnt, (int)err);
    }
}""",
)])

# ---------------------------------------------------------------------------
# 14) include/arch.h: kprobe 用的符号名随 4.19 的 arm64 syscall 包装改变。
#     4.19+ 的 SYSCALL_DEFINE 生成 __arm64_sys_##name（运行时经 kallsyms
#     查找该名字）；4.14 直生 sys_##name。只改 aarch64 分支；x86_64 /
#     riscv 分支不动（目标树只编 hook/arm64/*）。
# ---------------------------------------------------------------------------
apply_patches('include/arch.h', [(
"""#define REBOOT_SYMBOL "__arm64_sys_reboot"
#define SYS_READ_SYMBOL "__arm64_sys_read"
#define SYS_EXECVE_SYMBOL "__arm64_sys_execve"
// https://cs.android.com/android/kernel/superproject/+/common-android-mainline:common/scripts/syscalltbl.sh;l=57;drc=9142be9e6443fd641ca37f820efe00d9cd890eb1
// https://cs.android.com/android/kernel/superproject/+/common-android-mainline:common/scripts/syscall.tbl;l=104;drc=b36d4b6aa88ef039647228b98c59a875e92f8c8e
#define SYS_FSTAT_SYMBOL "__arm64_sys_newfstat\"""",
"""/* 4.19+ arm64 的 SYSCALL_DEFINE 生成 __arm64_sys_##name 包装符号；
 * 4.14 及更早直生 sys_##name（kprobe 运行时经 kallsyms 查找，名字必须匹配） */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
#define REBOOT_SYMBOL "__arm64_sys_reboot"
#define SYS_READ_SYMBOL "__arm64_sys_read"
#define SYS_EXECVE_SYMBOL "__arm64_sys_execve"
// https://cs.android.com/android/kernel/superproject/+/common-android-mainline:common/scripts/syscalltbl.sh;l=57;drc=9142be9e6443fd641ca37f820efe00d9cd890eb1
// https://cs.android.com/android/kernel/superproject/+/common-android-mainline:common/scripts/syscall.tbl;l=104;drc=b36d4b6aa88ef039647228b98c59a875e92f8c8e
#define SYS_FSTAT_SYMBOL "__arm64_sys_newfstat"
#else
#define REBOOT_SYMBOL "sys_reboot"
#define SYS_READ_SYMBOL "sys_read"
#define SYS_EXECVE_SYMBOL "sys_execve"
#define SYS_FSTAT_SYMBOL "sys_newfstat"
#endif""",
)])

# ---------------------------------------------------------------------------
# 15) supercall/supercall.c: reboot kprobe handler 的解包语义随 4.19 的
#     syscall 包装改变而变：
#       4.19+：kprobe 挂 __arm64_sys_reboot(const struct pt_regs *)，
#               regs->regs[0] 是用户态 pt_regs 指针，须 PT_REAL_REGS 解包；
#       4.14 ：kprobe 挂 sys_reboot(magic1, magic2, cmd, arg)，
#               regs->regs[0..3] 直接就是四个参数——若仍解包会把
#               magic1 当指针解引用，直接踩内存崩溃。
# ---------------------------------------------------------------------------
apply_patches('supercall/supercall.c', [(
"""static int reboot_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs *real_regs = PT_REAL_REGS(regs);""",
"""static int reboot_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
    /* 4.19+：regs[0] 是用户态 pt_regs 指针，需要解包 */
    struct pt_regs *real_regs = PT_REAL_REGS(regs);
#else
    /* 4.14：regs->regs[0..3] 即 reboot 的四个参数，不能再解包 */
    struct pt_regs *real_regs = regs;
#endif""",
)])

# ---------------------------------------------------------------------------
# 16) include/klog.h + infra/symbol_resolver.c: 两件兜底（klog.h 被几乎所有
#     .c 包含，是统一放置点）：
#     a. __nocfi：clang CFI 属性宏，5.x+ 才有；4.14 无 CFI，置空即可。
#        symbol_resolver.c 用到 __nocfi 但不含 klog.h，为其补 include。
#     b. TWA_RESUME：5.5+ 才作为 enum task_work_notify_mode 成员引入
#        （已核实 4.14~5.4 均为 task_work_add(..., bool)）；
#        4.14 的 true 即 TWA_RESUME 语义。三个使用点
#        （pkg_observer.c / allowlist.c / supercall.c）均包含 klog.h，
#        且都先于 klog.h 包含 task_work.h，不会破坏枚举声明。
# ---------------------------------------------------------------------------
apply_patches('include/klog.h', [(
"""#ifdef pr_fmt
#undef pr_fmt
#define pr_fmt(fmt) "KernelSU: " fmt
#endif

#endif""",
"""#ifdef pr_fmt
#undef pr_fmt
#define pr_fmt(fmt) "KernelSU: " fmt
#endif

/* 4.14 无 CFI 属性宏（随 clang CFI 在 5.x 引入），置空即可 */
#ifndef __nocfi
#define __nocfi
#endif

/* TWA_RESUME 5.5+ 才引入；4.14 的 task_work_add 第三参数是 bool，
 * true 即 TWA_RESUME 的语义 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 5, 0)
#define TWA_RESUME true
#endif

#endif""",
)])

apply_patches('infra/symbol_resolver.c', [(
"""#include "infra/symbol_resolver.h"
""",
"""#include "infra/symbol_resolver.h"
#include "klog.h" // 4.14: 本文件用到 __nocfi，兜底宏在 klog.h
""",
)])

# ---------------------------------------------------------------------------
# 17) Kbuild: selinux 的 flask.h 是该树构建期生成的头（genheaders 生成到
#     $(objtree)/security/selinux/，源码树里没有）。KSU 的 selinux.c 与
#     infra/file_wrapper.c 经 objsec.h -> "flask.h" 引用它，而 KSU 的
#     ccflags 只有 srctree 路径，找不到生成头。
#     - 补 -I$(objtree)/security/selinux
#     - 给所有 KSU 对象显式加上对 flask.h 的依赖：并行内核构建里
#       drivers/kernelsu 可能抢在 security/selinux 生成 flask.h 之前
#       编译，偶发 file not found（树内 selinux Makefile L19 同款写法）
#     （CONFIG_SECURITY_SELINUX=n 时该文件永远不存在——那种配置下 KSU
#       本来也编译不过，属预期失败。）
# ---------------------------------------------------------------------------
apply_patches('Kbuild', [(
"""ccflags-y += -I$(KSU_KERNEL_DIR) -I$(KSU_KERNEL_DIR)/include""",
"""ccflags-y += -I$(KSU_KERNEL_DIR) -I$(KSU_KERNEL_DIR)/include
# 4.14: selinux 的 flask.h 是构建期生成头，位于 $(objtree)/security/selinux/
ccflags-y += -I$(objtree)/security/selinux""",
), (
"""# Keep a new line here!! Because someone may append config""",
"""# Keep a new line here!! Because someone may append config

# 4.14: 所有 KSU 对象依赖 selinux 的生成头 flask.h（见上方 -I 注释），
# 避免并行构建时抢在 security/selinux 生成它之前编译
$(kernelsu-objs): $(objtree)/security/selinux/flask.h""",
)])

# ---------------------------------------------------------------------------
# 19) feature/sucompat.c: linux/pgtable.h 是 4.16+ 才出现的通用头，4.14
#     没有这个文件（编译直接 fatal error: file not found）。已核实本文件
#     对 pgtable 零使用（无 pgd/p4d/pud/pmd/pte/pgprot 任何引用），删除。
# ---------------------------------------------------------------------------
apply_patches('feature/sucompat.c', [(
"""#include <linux/mm.h>
#include <linux/pgtable.h>
""",
"""#include <linux/mm.h>
""",
)])

# ---------------------------------------------------------------------------
# 20) sulog/event.c: linux/minmax.h 是 5.1+ 才从 kernel.h 拆出来的，
#     4.14 的 min/max 宏还在 kernel.h。删掉 minmax.h include，改为
#     <5.1 时补 kernel.h（插入点在 version.h 之后，保证 LINUX_VERSION_CODE
#     在该处可用）。
# ---------------------------------------------------------------------------
apply_patches('sulog/event.c', [
(
"""#include <linux/minmax.h>
""",
"""/* 4.14 compat: 无 linux/minmax.h（5.1+），min/max 宏改由下方 kernel.h 提供 */
""",
),
(
"""#include <linux/version.h>
""",
"""#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
#include <linux/kernel.h> /* 4.14: 无 linux/minmax.h，min/max 宏在 kernel.h */
#endif
""",
)])

# ---------------------------------------------------------------------------
# 21) infra/su_mount_ns.c: uapi/linux/mount.h 是 5.0+ 才从 fs.h 拆出的
#     UAPI 头，4.14 没有。本文件只用 MS_PRIVATE/MS_REC，在 4.14 的
#     uapi/linux/fs.h（已核实 L123/L129）。改为 <5.0 时包含 fs.h。
#     （version.h 在本文件先于该 include，LINUX_VERSION_CODE 可用。）
# ---------------------------------------------------------------------------
apply_patches('infra/su_mount_ns.c', [(
"""#include <uapi/linux/mount.h>
""",
"""#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
#include <uapi/linux/fs.h> /* 4.14: MS_* 在 uapi/linux/fs.h，无 uapi/linux/mount.h */
#else
#include <uapi/linux/mount.h>
#endif
""",
)])

# ---------------------------------------------------------------------------
# 22) hook/syscall_hook.h: syscall_fn_t 的 typedef 只覆盖了 x86_64
#     （sys_call_ptr_t）和 riscv（pt_regs 直取），aarch64 落在分支之外、
#     类型未定义——hook/arm64/syscall_hook.c 及所有包含本头的 .c 全挂。
#     4.19+ 的 arm64 与 riscv 同为 pt_regs 派发语义，把 #elif defined(__riscv)
#     放宽为 #else 即可覆盖 aarch64（x86_64 分支不受影响）。
# ---------------------------------------------------------------------------
apply_patches('hook/syscall_hook.h', [(
"""#elif defined(__riscv)
""",
"""#else /* aarch64 等其余架构：与 riscv 同为 pt_regs 派发（4.19+ arm64 同款语义） */
""",
)])

# ---------------------------------------------------------------------------
# 23) policy/app_profile.c: struct seccomp.filter_count 是 5.9+ 才加入的
#     （已核实 4.14~5.8 的 struct seccomp 只有 mode/filter 两个字段）。
#     给 disable seccomp 时的清零语句加版本守卫。
# ---------------------------------------------------------------------------
apply_patches('policy/app_profile.c', [(
"""    atomic_set(&current->seccomp.filter_count, 0);
""",
"""#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
    atomic_set(&current->seccomp.filter_count, 0);
#endif
""",
)])

# ---------------------------------------------------------------------------
# 24) include/klog.h: fallthrough 属性宏 4.15+ 才在 compiler-gcc.h 定义，
#     4.14 没有。allowlist.c 的 profile 版本迁移 switch 用到它（全仓唯一
#     使用点），且 allowlist.c 已包含 klog.h，在这里兜底为空语句。
# ---------------------------------------------------------------------------
apply_patches('include/klog.h', [(
"""#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 5, 0)
#define TWA_RESUME true
#endif

#endif""",
"""#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 5, 0)
#define TWA_RESUME true
#endif

/* fallthrough 属性宏 4.15+ 引入（compiler-gcc.h）；4.14 无。
 * policy/allowlist.c 的 switch 版本迁移用到，展开为空语句 */
#ifndef fallthrough
#define fallthrough do {} while (0)
#endif

#endif""",
)])

# ---------------------------------------------------------------------------
# 25) supercall/dispatch.c: do_set_init_pgrp() 用到 tasklist_lock 与
#     init_task，二者在 4.14 声明于 linux/sched/task.h（新版分散在
#     sched.h 等处），dispatch.c 未包含该头。补 include。
# ---------------------------------------------------------------------------
apply_patches('supercall/dispatch.c', [(
"""#include <linux/thread_info.h>
""",
"""#include <linux/thread_info.h>
#include <linux/sched/task.h> /* 4.14: tasklist_lock / init_task 声明在此 */
""",
)])

# ---------------------------------------------------------------------------
# 26) hook/lsm_hook.c: 整套运行期 LSM hook patcher 建立在 5.4+ 的
#     security_hook_heads hlist 布局上（head 是 struct hlist_head、
#     security_hook_list 内嵌 hlist_node，靠 head->first / list.pprev 完成
#     "只改头指针"的无锁插入）。4.14 的 security_hook_heads 是
#     struct list_head 布局（双链、节点带 prev 指针），插入链首必须改写旧首
#     节点的 prev——RCU 遍历下这不安全；且已核实本仓库没有任何
#     ksu_register_lsm_hook() 调用方（4.14 的 syscall 挂钩走 kprobes，
#     LSM hook 链接是 5.x+ BPF LSM 的特性）。
#     => 4.14 退化为保留导出符号的空实现：链接期不缺符号、运行期零风险。
# ---------------------------------------------------------------------------
apply_patches('hook/lsm_hook.c', [
(
"""#include <linux/compiler.h>
""",
"""#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
#include <linux/compiler.h>
""",
),
(
"""    for (i = count - 1; i >= 0; i--)
        ksu_lsm_unhook(hooks[i]);
}
""",
"""    for (i = count - 1; i >= 0; i--)
        ksu_lsm_unhook(hooks[i]);
}

#else /* 4.14: security_hook_heads 为 list_head 布局，hlist 版 patcher 不适用 */
#include <linux/init.h>
#include "hook/lsm_hook.h"
#include "klog.h"

int ksu_lsm_hook(struct ksu_lsm_hook *hook)
{
    return 0;
}

void ksu_lsm_unhook(struct ksu_lsm_hook *hook)
{
}

int ksu_register_lsm_hook(struct ksu_lsm_hook *hook)
{
    return 0;
}

void ksu_unregister_lsm_hook(struct ksu_lsm_hook *hook)
{
}

void __init ksu_lsm_hook_init(void)
{
    pr_info("lsm_hook: init (4.14 no-op)\\n");
}

void __exit ksu_lsm_hook_exit(void)
{
}
#endif
""",
)])

# ---------------------------------------------------------------------------
# 27) manager/pkg_observer.c: fsnotify_ops.handle_inode_event 是 5.10+ 才
#     加入的成员（已核实 4.14/4.19/5.4 的 fsnotify_ops 只有 handle_event，
#     且 4.14 连 fsnotify_add_inode_mark 都没有、mark API 签名也不同），
#     4.14 的 fsnotify 与上游这套 packages.list 监听写法不兼容。
#     => 4.14 退化为空实现：throne tracker 仍由 boot_event / init 的
#        track_throne() 驱动，仅失去运行期 packages.list 变更监听。
# ---------------------------------------------------------------------------
apply_patches('manager/pkg_observer.c', [
(
"""// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
""",
"""// SPDX-License-Identifier: GPL-2.0
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
#include <linux/module.h>
""",
),
(
"""void __exit ksu_observer_exit(void)
{
    unwatch_one_dir(&g_watch);
    fsnotify_put_group(g);
    pr_info("observer exit done\\n");
}""",
"""void __exit ksu_observer_exit(void)
{
    unwatch_one_dir(&g_watch);
    fsnotify_put_group(g);
    pr_info("observer exit done\\n");
}

#else /* 4.14: fsnotify_ops 无 handle_inode_event，API 不兼容，退化为空实现 */
#include <linux/init.h>
#include <linux/module.h>
#include "klog.h"

int ksu_observer_init(void)
{
    pr_info("observer: 4.14 no-op\\n");
    return 0;
}

void __exit ksu_observer_exit(void)
{
}
#endif
""",
)])

# ---------------------------------------------------------------------------
# 28) infra/file_wrapper.c: 4.14 的 struct file_operations 没有
#     iopoll / remap_file_range / fadvise / mmap_supported_flags 四个成员
#     （已逐字段核对 4.14.186 树：只有 llseek..dedupe_file_range，其中
#     clone_file_range/dedupe_file_range 是 remap_file_range 的前身；
#     上游引入版本：fadvise/mmap_supported_flags 4.19、remap_file_range
#     5.0、iopoll 5.1）。把对应 wrapper 函数与 fops 赋值整段裁掉——少包
#     几个方法不影响正确性（未包装的调用直接透传给 orig）。
# ---------------------------------------------------------------------------
apply_patches('infra/file_wrapper.c', [
# --- a. iopoll（5.1+）：函数整段（6.1 的 icb 变体与 <6.1 的 spin 变体）---
(
"""#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
static int ksu_wrapper_iopoll(struct kiocb *kiocb, struct io_comp_batch *icb, unsigned int v)
""",
"""#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
static int ksu_wrapper_iopoll(struct kiocb *kiocb, struct io_comp_batch *icb, unsigned int v)
""",
),
(
"""    kiocb->ki_filp = orig;
    return orig->f_op->iopoll(kiocb, spin);
}
#endif
""",
"""    kiocb->ki_filp = orig;
    return orig->f_op->iopoll(kiocb, spin);
}
#endif
#endif /* 4.14: file_operations 无 iopoll */
""",
),
(
"""    p->ops.iopoll = fp->f_op->iopoll ? ksu_wrapper_iopoll : NULL;
""",
"""#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
    p->ops.iopoll = fp->f_op->iopoll ? ksu_wrapper_iopoll : NULL;
#endif
""",
),
# --- b. remap_file_range（5.0+）：函数整段裁掉，REMAP_FILE_DEDUP 随之裁掉 ---
(
"""static loff_t ksu_wrapper_remap_file_range(struct file *file_in, loff_t pos_in, struct file *file_out, loff_t pos_out,
""",
"""#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
static loff_t ksu_wrapper_remap_file_range(struct file *file_in, loff_t pos_in, struct file *file_out, loff_t pos_out,
""",
),
# --- c. fadvise（4.19+）：函数整段（上面 remap 的守卫在 d 步关闭）---
(
"""static int ksu_wrapper_fadvise(struct file *fp, loff_t off1, loff_t off2, int flags)
{
    struct ksu_file_wrapper *data = fp->private_data;
    struct file *orig = data->orig;
    if (orig->f_op->fadvise) {
        return orig->f_op->fadvise(orig, off1, off2, flags);
    }
    return -EINVAL;
}
""",
"""#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
static int ksu_wrapper_fadvise(struct file *fp, loff_t off1, loff_t off2, int flags)
{
    struct ksu_file_wrapper *data = fp->private_data;
    struct file *orig = data->orig;
    if (orig->f_op->fadvise) {
        return orig->f_op->fadvise(orig, off1, off2, flags);
    }
    return -EINVAL;
}
#endif /* 4.14: file_operations 无 fadvise */
""",
),
# --- d. 关闭 remap 守卫 + fops 赋值处的版本守卫 ---
(
"""static void ksu_release_file_wrapper(struct ksu_file_wrapper *data);
""",
"""#endif /* 4.14: 无 remap_file_range / REMAP_FILE_DEDUP */

static void ksu_release_file_wrapper(struct ksu_file_wrapper *data);
""",
),
(
"""    p->ops.remap_file_range = fp->f_op->remap_file_range ? ksu_wrapper_remap_file_range : NULL;
""",
"""#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
    p->ops.remap_file_range = fp->f_op->remap_file_range ? ksu_wrapper_remap_file_range : NULL;
#endif
""",
),
(
"""    p->ops.fadvise = fp->f_op->fadvise ? ksu_wrapper_fadvise : NULL;
""",
"""#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
    p->ops.fadvise = fp->f_op->fadvise ? ksu_wrapper_fadvise : NULL;
#endif
""",
),
(
"""#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
    p->ops.fop_flags = fp->f_op->fop_flags;
#else
    p->ops.mmap_supported_flags = fp->f_op->mmap_supported_flags;
#endif
""",
"""#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
    p->ops.fop_flags = fp->f_op->fop_flags;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
    p->ops.mmap_supported_flags = fp->f_op->mmap_supported_flags;
#endif
""",
)])

# ---------------------------------------------------------------------------
# 29) infra/event_queue.c/.h: 两处 4.14 缺失——
#     a. EPOLLIN/EPOLLHUP/EPOLLRDNORM 定义在 linux/eventpoll.h（4.14 有
#        该头，但 event_queue.c 只包含了 poll.h）；
#     b. __poll_t 是 4.16+ 才在 poll.h 定义的 typedef，兜底在 klog.h
#        （见组 3），而 event_queue.c 与 event_queue.h（L58 函数声明）都
#        不包含 klog.h。两处都补上。
# ---------------------------------------------------------------------------
apply_patches('infra/event_queue.c', [(
"""#include <linux/wait.h>

#include "infra/event_queue.h"
""",
"""#include <linux/wait.h>
#include <linux/eventpoll.h> /* 4.14: EPOLLIN/EPOLLHUP/EPOLLRDNORM 在此 */

#include "infra/event_queue.h"
#include "klog.h" /* 4.14: __poll_t 兜底在 klog.h */
""",
)])

apply_patches('infra/event_queue.h', [(
"""#include <linux/wait.h>
""",
"""#include <linux/wait.h>
#include "klog.h" /* 4.14: __poll_t 兜底在 klog.h */
""",
)])

# ---------------------------------------------------------------------------
# 30) policy/app_profile.c: seccomp_filter_release() 5.9 才引入（v5.8 无、
#     v5.9 有）；4.14 只有 put_seccomp_filter()——两者签名相同
#     （void f(struct task_struct *)），语义都是释放 tsk->seccomp.filter 上
#     的引用（disable_seccomp() 里 fake 是 current 的拷贝，filter 指针在
#     NULL 化 current 之前已拷入 fake）。pristine 的前向声明正好是单一锚点，
#     用 #define 改名，调用点 seccomp_filter_release(fake) 无需改动。
# ---------------------------------------------------------------------------
apply_patches('policy/app_profile.c', [(
"""void seccomp_filter_release(struct task_struct *tsk);
""",
"""#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
void seccomp_filter_release(struct task_struct *tsk);
#else
// 4.14 无 seccomp_filter_release()（5.9 引入）；put_seccomp_filter() 签名相同
// （include/linux/seccomp.h:83），语义一致：释放 tsk->seccomp.filter 的引用
#define seccomp_filter_release put_seccomp_filter
#endif
""",
)])

# ---------------------------------------------------------------------------
# 31) policy/allowlist.c: 两个 4.14 缺口（均只在链接期暴露——gnu89 下隐式
#     声明只是 warning，单目标编译发现不了）——
#     a. put_task_struct() 在 4.14 是 include/linux/sched/task.h 里的
#        static inline（L101），而 allowlist.c 未包含该头（sched.h 不含它），
#        调用处退化为未定义符号；
#     b. strscpy_pad() 5.2 才引入（v5.1 无、v5.2 有），4.14 只有 strscpy()。
#        唯一调用点 migrate_profile() 忽略返回值，按 lib/string.c 语义
#        （strscpy + dest 剩余空间补 NUL）等价实现即可。
# ---------------------------------------------------------------------------
apply_patches('policy/allowlist.c', [(
"""#include <linux/hashtable.h>
#include <linux/kref.h>
""",
"""#include <linux/hashtable.h>
#include <linux/kref.h>
#include <linux/sched/task.h> /* 4.14: put_task_struct() 在此（static inline） */
#include <linux/string.h> /* 4.14: strscpy()/memset() 声明 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)
// 4.14 无 strscpy_pad()（5.2 引入）；按 lib/string.c 语义等价实现：
// strscpy() 拷贝并保证 NUL 结尾，再把 dest 剩余空间补零。
static inline ssize_t ksu_strscpy_pad(char *dest, const char *src, size_t count)
{
    ssize_t written = strscpy(dest, src, count);

    if (written < 0 || written == count - 1)
        return written;
    memset(dest + written + 1, 0, count - written - 1);
    return written;
}
#define strscpy_pad ksu_strscpy_pad
#endif
""",
)])

# ---------------------------------------------------------------------------
# 32) infra/file_wrapper.c: 三个 4.14 缺口，都在 < 5.16 的自实现分支里——
#     a. selinux_inode() 5.1 引入（v5.0 无）；4.14 的 objsec.h（Kbuild 的
#        -I$(srctree)/security/selinux/include 提供）只给出
#        struct inode_security_struct，访问器就是 inode->i_security 直接取值；
#     b. security_inode_init_security_anon() 5.12 引入（v5.11 无，5.2~5.11
#        主线同样没有，一并跳过）。wrapper inode 的 SID 随后会在
#        ksu_install_file_wrapper() 里覆写为 ksu_file_sid；且 4.14 的
#        alloc_anon_inode()→new_inode_pseudo()→security_inode_alloc 已给
#        i_security 分配好初始标签，跳过安全初始化不影响功能；
#     c. alloc_file_pseudo() 4.19 引入（v4.18 无）。按 v5.4 fs/file_table.c
#        的 alloc_file_pseudo() 等价实现，唯一差异：4.14 的 alloc_file()
#        第二参是 fmode_t，需调用方自行 OPEN_FMODE()。引用计数模型
#        （4.14 fs/dcache.c:577 d_kill→dentry_unlink_inode→iput）：
#        成功路径上 alloc_anon_inode() 那份引用在 fput→dput→iput 时归还，
#        inode 随之释放；失败路径先 ihold 再 path_put，让 path_put 里的
#        iput 消耗这次额外引用，调用方 err_iput 对自己那份引用的 iput
#        不受影响（与上游同一手法）。
# ---------------------------------------------------------------------------
apply_patches('infra/file_wrapper.c', [(
"""#include "objsec.h"
""",
"""#include "objsec.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
// 4.14 无 selinux_inode()（5.1 引入）；struct inode_security_struct 已由
// objsec.h 给出，直接取 inode->i_security
#define selinux_inode(inode) ((struct inode_security_struct *)(inode)->i_security)
#endif
""",
), (
"""// Borrow kernel's anon_inode_mnt, so that we don't need to mount one by ourselves.
static struct vfsmount *anon_inode_mnt __read_mostly;
""",
"""// Borrow kernel's anon_inode_mnt, so that we don't need to mount one by ourselves.
static struct vfsmount *anon_inode_mnt __read_mostly;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0)
// 4.14 无 alloc_file_pseudo()（4.19 引入）。等价实现照抄 v5.4
// fs/file_table.c 的 alloc_file_pseudo()，唯一差异：4.14 的 alloc_file()
// 第二参是 fmode_t，需调用方自行 OPEN_FMODE()。
static struct file *ksu_alloc_file_pseudo_414(struct inode *inode, struct vfsmount *mnt,
                                              const char *name, int flags,
                                              const struct file_operations *fops)
{
    static const struct dentry_operations anon_ops = { .d_dname = simple_dname };
    struct qstr qname = QSTR_INIT(name, strlen(name));
    struct path path;
    struct file *file;

    path.dentry = d_alloc_pseudo(mnt->mnt_sb, &qname);
    if (!path.dentry)
        return ERR_PTR(-ENOMEM);
    if (!mnt->mnt_sb->s_d_op)
        d_set_d_op(path.dentry, &anon_ops);
    path.mnt = mntget(mnt);
    d_instantiate(path.dentry, inode);
    file = alloc_file(&path, OPEN_FMODE(flags), fops);
    if (IS_ERR(file)) {
        ihold(inode);
        path_put(&path);
    }
    return file;
}
#define alloc_file_pseudo ksu_alloc_file_pseudo_414
#endif
""",
), (
"""    struct inode *inode;
    const struct qstr qname = QSTR_INIT(name, strlen(name));
    int error;
""",
"""    struct inode *inode;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
    const struct qstr qname = QSTR_INIT(name, strlen(name));
    int error;
#endif
""",
), (
"""    error = security_inode_init_security_anon(inode, &qname, context_inode);
    if (error) {
        iput(inode);
        return ERR_PTR(error);
    }
    return inode;
""",
"""#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
    error = security_inode_init_security_anon(inode, &qname, context_inode);
    if (error) {
        iput(inode);
        return ERR_PTR(error);
    }
#endif
    return inode;
""",
)])

# ---------------------------------------------------------------------------
# 33) hook/arm64/patch_memory.c: __pte_to_phys() 4.16 才引入（v4.15 无、
#     v4.16 有）；4.14 只有 pte_pfn() = (pte_val(pte) & PHYS_MASK) >>
#     PAGE_SHIFT。phys_from_virt() 的用法是 __pte_to_phys(*pte) +
#     (addr & ~PAGE_MASK)，即"页框物理基址 + 页内偏移"；pte_pfn(*pte)
#     << PAGE_SHIFT 正是页框物理基址，两者等价。（同一函数里的
#     __pmd_to_phys 分支被 #if defined(pmd_leaf) 永久排除——pmd_leaf 是
#     函数不是宏，无需处理。）
# ---------------------------------------------------------------------------
apply_patches('hook/arm64/patch_memory.c', [(
"""    return __pte_to_phys(*pte) + ((addr & ~PAGE_MASK));
""",
"""#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 16, 0)
    return __pte_to_phys(*pte) + ((addr & ~PAGE_MASK));
#else
    // 4.14 无 __pte_to_phys()（4.16 引入）；pte_pfn() 即 pte_val & PHYS_MASK
    // 后右移 PAGE_SHIFT，左移回来就是页框物理基址，与上游宏语义一致
    return (pte_pfn(*pte) << PAGE_SHIFT) + (addr & ~PAGE_MASK);
#endif
""",
)])

print("[414compat] source patches done")
PYEOF

# -----------------------------------------------------------------------------
# 18) uapi/ 头物化：7kimisu 仓库把 UAPI 头放在仓库根的 uapi/（与 kernel/ 平级），
#     而内嵌构建只拷 kernel/ -> drivers/kernelsu，代码里的
#     #include "uapi/xxx.h" 将无处解析。Kbuild 已有 -I$(KSU_KERNEL_DIR)，
#     把这 6 个头原样落到 drivers/kernelsu/uapi/ 即可。
#     UAPI 是与用户态管理器之间的稳定契约，随本脚本一起钉版本；
#     若构建流程已自行拷入 uapi/（版本更新鲜），保留不覆盖。
# -----------------------------------------------------------------------------
if [ ! -d uapi ]; then
    mkdir -p uapi

    cat > uapi/app_profile.h <<'EOF'
#ifndef __KSU_UAPI_APP_PROFILE_H
#define __KSU_UAPI_APP_PROFILE_H

#include <linux/types.h>

#define KSU_APP_PROFILE_VER 4
#define KSU_MAX_PACKAGE_NAME 256
/* NGROUPS_MAX for Linux is 65535 generally, but we only supports 32 groups. */
#define KSU_MAX_GROUPS 32
#define KSU_SELINUX_DOMAIN 64

#define FLAG_KSU_NO_NEW_PRIVS (1ULL << 0)

struct root_profile {
    __s32 uid;
    __s32 gid;

    __u32 groups_count;
    __s32 groups[KSU_MAX_GROUPS];

    /* kernel_cap_t is u32[2] for capabilities v3 */
    struct {
        __u64 effective;
        __u64 permitted;
        __u64 inheritable;
    } capabilities;

    char selinux_domain[KSU_SELINUX_DOMAIN];

    __s32 namespaces;

    __u64 flags;
};

struct non_root_profile {
    bool umount_modules;
};

struct app_profile {
    /*
     * It may be utilized for backward compatibility, although we have never
     * explicitly made any promises regarding this.
     */
    __u32 version;

    /* this is usually the package of the app, but can be other value for special apps */
    char key[KSU_MAX_PACKAGE_NAME];
    __s32 curr_uid;
    bool allow_su;

    union {
        struct {
            bool use_default;
            char template_name[KSU_MAX_PACKAGE_NAME];

            struct root_profile profile;
        } rp_config;

        struct {
            bool use_default;

            struct non_root_profile profile;
        } nrp_config;
    };
};

#endif
EOF

    cat > uapi/feature.h <<'EOF'
#ifndef __KSU_UAPI_FEATURE_H
#define __KSU_UAPI_FEATURE_H

enum ksu_feature_id {
    KSU_FEATURE_SU_COMPAT = 0,
    KSU_FEATURE_KERNEL_UMOUNT = 1,
    KSU_FEATURE_SULOG = 2,
    KSU_FEATURE_ADB_ROOT = 3,
    KSU_FEATURE_SELINUX_HIDE = 4,
    // 5 was webview_zygote_umount (v3.3.0), keep it unused so stale configs don't apply
    KSU_FEATURE_SHELL_SU_ADB_ONLY = 6,

    KSU_FEATURE_MAX
};

#endif
EOF

    cat > uapi/selinux.h <<'EOF'
#ifndef __KSU_UAPI_SELINUX_H
#define __KSU_UAPI_SELINUX_H

#include <linux/types.h>

static const __u32 KSU_SEPOLICY_CMD_NORMAL_PERM = 1;
static const __u32 KSU_SEPOLICY_CMD_XPERM = 2;
static const __u32 KSU_SEPOLICY_CMD_TYPE_STATE = 3;
static const __u32 KSU_SEPOLICY_CMD_TYPE = 4;
static const __u32 KSU_SEPOLICY_CMD_TYPE_ATTR = 5;
static const __u32 KSU_SEPOLICY_CMD_ATTR = 6;
static const __u32 KSU_SEPOLICY_CMD_TYPE_TRANSITION = 7;
static const __u32 KSU_SEPOLICY_CMD_TYPE_CHANGE = 8;
static const __u32 KSU_SEPOLICY_CMD_GENFSCON = 9;

static const __u32 KSU_SEPOLICY_SUBCMD_NORMAL_PERM_ALLOW = 1;
static const __u32 KSU_SEPOLICY_SUBCMD_NORMAL_PERM_DENY = 2;
static const __u32 KSU_SEPOLICY_SUBCMD_NORMAL_PERM_AUDITALLOW = 3;
static const __u32 KSU_SEPOLICY_SUBCMD_NORMAL_PERM_DONTAUDIT = 4;

static const __u32 KSU_SEPOLICY_SUBCMD_XPERM_ALLOW = 1;
static const __u32 KSU_SEPOLICY_SUBCMD_XPERM_AUDITALLOW = 2;
static const __u32 KSU_SEPOLICY_SUBCMD_XPERM_DONTAUDIT = 3;

static const __u32 KSU_SEPOLICY_SUBCMD_TYPE_STATE_PERMISSIVE = 1;
static const __u32 KSU_SEPOLICY_SUBCMD_TYPE_STATE_ENFORCE = 2;

static const __u32 KSU_SEPOLICY_SUBCMD_TYPE_CHANGE_CHANGE = 1;
static const __u32 KSU_SEPOLICY_SUBCMD_TYPE_CHANGE_MEMBER = 2;

#endif
EOF

    cat > uapi/sulog.h <<'EOF'
#ifndef __KSU_UAPI_SULOG_H
#define __KSU_UAPI_SULOG_H

#include <linux/sched.h>
#include <linux/types.h>

#define KSU_SULOG_EVENT_VERSION 1
#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

enum ksu_sulog_event_type {
    KSU_SULOG_EVENT_ROOT_EXECVE = 1,
    KSU_SULOG_EVENT_SUCOMPAT = 2,
    KSU_SULOG_EVENT_IOCTL_GRANT_ROOT = 3,
};

struct ksu_sulog_event {
    __u16 version;
    __u16 event_type;
    __s32 retval;
    __u32 pid;
    __u32 tgid;
    __u32 ppid;
    __u32 uid;
    __u32 euid;
    char comm[TASK_COMM_LEN];
    __u32 filename_len;
    __u32 argv_len;
} __packed;

#endif
EOF

    cat > uapi/supercall.h <<'EOF'
#ifndef __KSU_UAPI_SUPERCALL_H
#define __KSU_UAPI_SUPERCALL_H

#include <linux/ioctl.h>
#include <linux/types.h>

#include "uapi/app_profile.h"

// 2: allowlist v4 root profile flags
// 3: scoped su-session driver fd
// 4: add KSU_GET_INFO_FLAG_BUNDLED
// 5: add EVENT_SERVICES with a start/skip result; 7kimisu: add stealth get/set
static const __u32 KERNEL_SU_UAPI_VERSION = 5;

/* Magic numbers for reboot hook to install fd */
static const __u32 KSU_INSTALL_MAGIC1 = 0xDEADBEEF;
static const __u32 KSU_INSTALL_MAGIC2 = 0xCAFEBABE;

struct ksu_become_daemon_cmd {
    __u8 token[65]; /* Input: daemon token (null-terminated) */
};

static const __u32 EVENT_POST_FS_DATA = 1;
static const __u32 EVENT_BOOT_COMPLETED = 2;
static const __u32 EVENT_MODULE_MOUNTED = 3;
static const __u32 EVENT_SERVICES = 4;

static const __u32 KSU_GET_INFO_FLAG_LKM = (1U << 0);
static const __u32 KSU_GET_INFO_FLAG_MANAGER = (1U << 1);
static const __u32 KSU_GET_INFO_FLAG_LATE_LOAD = (1U << 2);
static const __u32 KSU_GET_INFO_FLAG_PR_BUILD = (1U << 3);
static const __u32 KSU_GET_INFO_FLAG_BUNDLED = (1U << 4);

struct ksu_get_info_cmd {
    __u32 version; /* Output: KERNEL_SU_VERSION */
    __u32 flags; /* Output: KSU_GET_INFO_FLAG_* bits */
    __u32 features; /* Output: max feature ID supported */
    __u32 uapi_version; /* Output: KERNEL_SU_UAPI_VERSION */
};

struct ksu_get_info_legacy_cmd {
    __u32 version; /* Output: KERNEL_SU_VERSION */
    __u32 flags; /* Output: KSU_GET_INFO_FLAG_* bits */
    __u32 features; /* Output: max feature ID supported */
};

struct ksu_report_event_cmd {
    __u32 event; /* Input: EVENT_POST_FS_DATA, EVENT_BOOT_COMPLETED, etc. */
};

struct ksu_set_sepolicy_cmd {
    __u64 data_len; /* Input: bytes of serialized command payload */
    __aligned_u64 data; /* Input: pointer to serialized payload */
};

struct ksu_sepolicy_cmd_hdr {
    __u32 cmd; /* Input: command type, CMD_* */
    __u32 subcmd; /* Input: command subtype */
};
/*
 * After each ksu_sepolicy_cmd_hdr, command arguments are encoded sequentially as:
 * [u32 len][len bytes][\0], where len excludes the trailing '\0'.
 * len == 0 represents ALL.
 * Argument count is derived from cmd:
 * KSU_SEPOLICY_CMD_NORMAL_PERM=4, KSU_SEPOLICY_CMD_XPERM=5,
 * KSU_SEPOLICY_CMD_TYPE_STATE=1, KSU_SEPOLICY_CMD_TYPE=2,
 * KSU_SEPOLICY_CMD_TYPE_ATTR=2, KSU_SEPOLICY_CMD_ATTR=1,
 * KSU_SEPOLICY_CMD_TYPE_TRANSITION=5, KSU_SEPOLICY_CMD_TYPE_CHANGE=4,
 * KSU_SEPOLICY_CMD_GENFSCON=3.
 */

struct ksu_check_safemode_cmd {
    __u8 in_safe_mode; /* Output: true if in safe mode, false otherwise */
};

/* deprecated */
struct ksu_get_allow_list_cmd {
    __u32 uids[128]; /* Output: array of allowed/denied UIDs */
    __u32 count; /* Output: number of UIDs in array */
    __u8 allow; /* Input: true for allow list, false for deny list */
};

struct ksu_new_get_allow_list_cmd {
    __u16 count; /* Input / Output: number of UIDs in array */
    __u16 total_count; /* Output: total number of UIDs in requested list */
    __u32 uids[0]; /* Output: array of allowed/denied UIDs */
};

struct ksu_uid_granted_root_cmd {
    __u32 uid; /* Input: target UID to check */
    __u8 granted; /* Output: true if granted, false otherwise */
};

struct ksu_uid_should_umount_cmd {
    __u32 uid; /* Input: target UID to check */
    __u8 should_umount; /* Output: true if should umount, false otherwise */
};

struct ksu_get_manager_appid_cmd {
    __u32 appid; /* Output: manager app id */
};

struct ksu_get_app_profile_cmd {
    struct app_profile profile; /* Input/Output: app profile structure */
};

struct ksu_set_app_profile_cmd {
    struct app_profile profile; /* Input: app profile structure */
};

struct ksu_get_feature_cmd {
    __u32 feature_id; /* Input: feature ID (enum ksu_feature_id) */
    __u64 value; /* Output: feature value/state */
    __u8 supported; /* Output: KSU_FEATURE_FLAG_* bits, 0 if feature is not supported */
};

#define KSU_FEATURE_FLAG_SUPPORTED (1 << 0)
/* Value is forced by boot config (force_feature param), SET_FEATURE is refused */
#define KSU_FEATURE_FLAG_FORCED (1 << 1)

struct ksu_set_feature_cmd {
    __u32 feature_id; /* Input: feature ID (enum ksu_feature_id) */
    __u64 value; /* Input: feature value/state to set */
};

struct ksu_get_wrapper_fd_cmd {
    __u32 fd; /* Input: userspace fd */
    __u32 flags; /* Input: flags of userspace fd */
};

struct ksu_manage_mark_cmd {
    __u32 operation; /* Input: KSU_MARK_* */
    __s32 pid; /* Input: target pid (0 for all processes) */
    __u32 result; /* Output: for get operation - mark status or reg_count */
};

static const __u32 KSU_MARK_GET = 1;
static const __u32 KSU_MARK_MARK = 2;
static const __u32 KSU_MARK_UNMARK = 3;
static const __u32 KSU_MARK_REFRESH = 4;

struct ksu_nuke_ext4_sysfs_cmd {
    __aligned_u64 arg; /* Input: mnt pointer */
};

struct ksu_add_try_umount_cmd {
    __aligned_u64 arg; /* char ptr, this is the mountpoint */
    __u32 flags; /* this is the flag we use for it */
    __u8 mode; /* denotes what to do with it 0:wipe_list 1:add_to_list 2:delete_entry */
};

struct ksu_get_sulog_fd_cmd {
    __u32 flags; /* Input: reserved for future use, must be 0 */
};

static const __u8 KSU_UMOUNT_WIPE = 0; /* ignore everything and wipe list */
static const __u8 KSU_UMOUNT_ADD = 1; /* add entry (path + flags) */
static const __u8 KSU_UMOUNT_DEL = 2; /* delete entry, strcmp */

/* IOCTL command definitions */
static const __u32 KSU_IOCTL_GRANT_ROOT = _IOC(_IOC_NONE, 'K', 1, 0);
static const __u32 KSU_IOCTL_GET_INFO = _IOR('K', 2, struct ksu_get_info_cmd);
/* deprecated */
static const __u32 KSU_IOCTL_GET_INFO_LEGACY = _IOC(_IOC_READ, 'K', 2, 0);
static const __u32 KSU_IOCTL_REPORT_EVENT = _IOC(_IOC_WRITE, 'K', 3, 0);
static const __u32 KSU_IOCTL_SET_SEPOLICY = _IOC(_IOC_READ | _IOC_WRITE, 'K', 4, 0);
static const __u32 KSU_IOCTL_CHECK_SAFEMODE = _IOC(_IOC_READ, 'K', 5, 0);
/* deprecated */
static const __u32 KSU_IOCTL_GET_ALLOW_LIST = _IOC(_IOC_READ | _IOC_WRITE, 'K', 6, 0);
/* deprecated */
static const __u32 KSU_IOCTL_GET_DENY_LIST = _IOC(_IOC_READ | _IOC_WRITE, 'K', 7, 0);
static const __u32 KSU_IOCTL_NEW_GET_ALLOW_LIST = _IOWR('K', 6, struct ksu_new_get_allow_list_cmd);
static const __u32 KSU_IOCTL_NEW_GET_DENY_LIST = _IOWR('K', 7, struct ksu_new_get_allow_list_cmd);
static const __u32 KSU_IOCTL_UID_GRANTED_ROOT = _IOC(_IOC_READ | _IOC_WRITE, 'K', 8, 0);
static const __u32 KSU_IOCTL_UID_SHOULD_UMOUNT = _IOC(_IOC_READ | _IOC_WRITE, 'K', 9, 0);
static const __u32 KSU_IOCTL_GET_MANAGER_APPID = _IOC(_IOC_READ, 'K', 10, 0);
static const __u32 KSU_IOCTL_GET_APP_PROFILE = _IOC(_IOC_READ | _IOC_WRITE, 'K', 11, 0);
static const __u32 KSU_IOCTL_SET_APP_PROFILE = _IOC(_IOC_WRITE, 'K', 12, 0);
static const __u32 KSU_IOCTL_GET_FEATURE = _IOC(_IOC_READ | _IOC_WRITE, 'K', 13, 0);
static const __u32 KSU_IOCTL_SET_FEATURE = _IOC(_IOC_WRITE, 'K', 14, 0);
static const __u32 KSU_IOCTL_GET_WRAPPER_FD = _IOC(_IOC_WRITE, 'K', 15, 0);
static const __u32 KSU_IOCTL_MANAGE_MARK = _IOC(_IOC_READ | _IOC_WRITE, 'K', 16, 0);
static const __u32 KSU_IOCTL_NUKE_EXT4_SYSFS = _IOC(_IOC_WRITE, 'K', 17, 0);
static const __u32 KSU_IOCTL_ADD_TRY_UMOUNT = _IOC(_IOC_WRITE, 'K', 18, 0);
static const __u32 KSU_IOCTL_SET_INIT_PGRP = _IO('K', 19);
static const __u32 KSU_IOCTL_GET_SULOG_FD = _IOW('K', 20, struct ksu_get_sulog_fd_cmd);
static const __u32 KSU_IOCTL_DISABLE_ESCAPE_TO_ROOT = _IO('K', 21);


/* App lock (superkey): kernel-enforced password gate for privileged operations */
struct ksu_app_lock_state_cmd {
    __u8 configured; /* Output: whether a lock is configured */
    __u8 authed; /* Output: whether already authenticated this boot */
};

struct ksu_app_lock_auth_cmd {
    __u8 hash[32]; /* Input: SHA-256(password) */
};

struct ksu_app_lock_set_cmd {
    __u8 hash[32]; /* Input: new SHA-256(password) */
    __u8 disable; /* Input: 1 to disable the lock */
    __u8 state; /* Output: 1 if a lock is configured after the operation */
};

static const __u32 KSU_IOCTL_APP_LOCK_STATE = _IOR('K', 22, struct ksu_app_lock_state_cmd);
static const __u32 KSU_IOCTL_APP_LOCK_AUTH = _IOW('K', 23, struct ksu_app_lock_auth_cmd);
static const __u32 KSU_IOCTL_APP_LOCK_SET = _IOWR('K', 24, struct ksu_app_lock_set_cmd);

/*
 * 隐身模式:开启后 GET_INFO 不再上报 MANAGER 标志,管理器整个界面伪装成"未安装"。
 * 内核真实权限不变,因此只有真正的管理器(签名匹配)能读写该开关。
 */
struct ksu_stealth_cmd {
    __u8 enabled; /* Input for SET, Output for GET */
};

static const __u32 KSU_IOCTL_STEALTH_GET = _IOR('K', 25, struct ksu_stealth_cmd);
static const __u32 KSU_IOCTL_STEALTH_SET = _IOW('K', 26, struct ksu_stealth_cmd);

/*
 * 断代闸门（2026-09-20）
 *
 *   认主是内核扫包**自动**完成的（kernel/manager/throne_tracker.c）：
 *   内核在 /data/app 里扫到「签名匹配」的 base.apk 就把它设成管理器。
 *   闸门加在**那一步**：除签名外，APK 还必须带 `assets/ksu_manager_gen<N>`
 *   条目（N >= kernel/Kbuild 的 KSU_MANAGER_MIN_GEN）。老版本 APK 的包里
 *   没有这个条目，物理上满足不了 → 永远不会被认主。
 *
 *   老 APK 同样**不认识下面这两条新命令**，所以它连"关隐身"都做不到
 *   （STEALTH_GET/SET 的权限仍是 only_manager，它没被认主 → -EPERM）；
 *   而**新版管理器**即使因为别的原因没被认主，也能用新命令关掉隐身。
 *
 * ⚠️ 这里**故意不动 KERNEL_SU_UAPI_VERSION**（仍是 5）：
 *   ksud 的 ensure_uapi_version_matched() 要求 kernel_uapi >= ksud_uapi，
 *   一旦把常量抬到 6，"新 APK + 老内核"会被判 "UAPI too old" → 模块挂载 /
 *   开机流程全废（违反「老内核 + 任意版本行为不变」）。
 *   新增 ioctl 天生向后兼容（老内核对未知 cmd 返回 -ENOTTY），不需要抬版本号。
 */
struct ksu_stealth_gen_cmd {
    __u32 manager_gen; /* Input: 管理器世代号; Output(GET): 内核要求的世代号下限 */
    __u8 enabled; /* Input for SET, Output for GET */
    __u8 _pad[3];
};

static const __u32 KSU_IOCTL_STEALTH_GET_G = _IOR('K', 27, struct ksu_stealth_gen_cmd);
static const __u32 KSU_IOCTL_STEALTH_SET_G = _IOW('K', 28, struct ksu_stealth_gen_cmd);

#endif
EOF

    cat > uapi/ksu.h <<'EOF'
#ifndef __KSU_UAPI_KSU_H
#define __KSU_UAPI_KSU_H

#include "uapi/supercall.h"
#include "uapi/app_profile.h"
#include "uapi/feature.h"
#include "uapi/selinux.h"
#include "uapi/sulog.h"

#endif // __KSU_UAPI_KSU_H
EOF

    echo "[414compat] uapi headers written (pinned snapshot)"
else
    echo "[414compat] uapi/ already present, keeping existing copy"
fi

# -----------------------------------------------------------------------------
# 30) 整体 stub：以下特性深度依赖 5.x+ 内核内部结构，4.14 无可移植实现。
#    - selinux/rules.c   : selinux_state.policy RCU 换策略机制（5.x+）
#    - selinux/sepolicy.c: 新版 policydb 内部结构（5.x+）
#    - feature/selinux_hide.c: selinux status page 机制（5.x+）
#    - infra/seccomp_cache.c : struct seccomp_filter 的 cache 字段（4.18+）
#    保留函数签名，置空实现；Kbuild 中移除 sepolicy.o。
# -----------------------------------------------------------------------------

cat > selinux/rules.c <<'EOF'
/* 4.14 compat stub: sepolicy 规则注入依赖 5.x+ 的 selinux_state.policy 机制 */
#include "selinux.h"
#include <linux/kernel.h>
#include <linux/version.h>

void apply_kernelsu_rules(void)
{
    pr_info("apply_kernelsu_rules: sepolicy injection is not supported on this kernel\n");
}

int handle_sepolicy(void __user *user_data, u64 data_len)
{
    return -EOPNOTSUPP;
}
EOF

cat > feature/selinux_hide.c <<'EOF'
/* 4.14 compat stub: selinux_hide 依赖 5.x+ 的 selinux status page 机制 */
#include "selinux_hide.h"
#include <linux/version.h>

void ksu_selinux_hide_init(void)
{
}

void ksu_selinux_hide_exit(void)
{
}

void ksu_selinux_hide_drop_backup_if_unused(void)
{
}

void ksu_selinux_hide_handle_second_stage(void)
{
}

void ksu_selinux_hide_handle_post_fs_data(void)
{
}
EOF

cat > infra/seccomp_cache.c <<'EOF'
/* 4.14 compat stub: struct seccomp_filter 无 cache 字段（4.18+ 才有） */
#include "infra/seccomp_cache.h"
#include <linux/version.h>

void ksu_seccomp_clear_cache(struct seccomp_filter *filter, int nr)
{
}

void ksu_seccomp_allow_cache(struct seccomp_filter *filter, int nr)
{
}
EOF

# sepolicy.c 不再被引用，从 Kbuild 移除
sed -i '/selinux\/sepolicy\.o/d' Kbuild

echo "[414compat] stubs written, all done"

# =============================================================================
# 31) SUSFS 集成层（仅当第二个参数为 "susfs" 时执行）
#
# susfs_patch_to_4.14.patch 只提供 VFS 层（fs/susfs.c），其功能全部包在
# #ifdef CONFIG_KSU_SUSFS_* 内，且 extern 三个 KernelSU 侧符号：
#     susfs_is_current_ksu_domain / setup_selinux / ksu_cred
# 后两者 7kimisu 已有，这里补齐 KSU 侧这一层：
#   a. susfs_ksu.c：定义 susfs_is_current_ksu_domain + 默认隐藏路径
#      （复刻 susfs_add_sus_path 的内核态逻辑，绕开 copy_from_user，
#       因为 7kimisu 管理器没有 SUSFS 界面，路径清单由内核侧硬编码）
#   b. Kconfig：CONFIG_KSU_SUSFS 及 9 个子选项（susfs.c 的 ifdef 依赖它们；
#      含 HIDE_KSU_SUSFS_SYMBOLS，对应补丁里 kallsyms.c 的隐藏段）
#   c. Kbuild：编入 susfs_ksu.o
#   d. ksud_integration.c：extern 声明 + second_stage 时应用默认路径
#      （此时 /data 已挂载），并补调 susfs_init()
# =============================================================================
if [ "$WITH_SUSFS" = "susfs" ]; then

cat > susfs_ksu.c <<'CEOF'
/* ============================================================================
 * 7kimisu <-> SUSFS 集成层（4.14 适配）
 *
 * SUSFS 的 VFS 部分由 susfs_patch_to_4.14.patch 提供（fs/susfs.c），
 * 它 extern 三个 KernelSU 侧符号：
 *     susfs_is_current_ksu_domain / setup_selinux / ksu_cred
 * 后两者 7kimisu 已有，本文件补上第一个，并提供：
 *   1. 默认隐藏路径清单（second_stage 时 /data 已挂载，内核侧直接添加，
 *      不依赖管理器 App 的 SUSFS 界面——7kimisu 管理器没有该界面）
 *   2. 挂载隐藏开关（static_branch_enable）
 *
 * 注意：susfs_add_sus_path() 等官方入口用 copy_from_user 收用户态指针，
 * 本文件不复用它们，而是复刻其内核态核心逻辑。
 * ===========================================================================
 */
#include <linux/susfs.h>
#include <linux/version.h>
#include <linux/path.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/kernel.h>

#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "selinux/selinux.h"

/* fs/susfs.c 中 DEFINE_STATIC_KEY_FALSE 定义的开关（susfs 补丁提供） */
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
extern struct static_key_false susfs_is_hide_sus_mnts_for_non_su_procs_enabled;
#endif

/* --------------------------------------------------------------------------
 * susfs.c extern 的符号：判断当前进程是否处于 ksu 域
 * 7kimisu 的 selinux.c 已实现 is_ksu_domain()，直接包一层
 * -------------------------------------------------------------------------- */
bool susfs_is_current_ksu_domain(void)
{
    return is_ksu_domain();
}

#ifdef CONFIG_KSU_SUSFS_SUS_PATH
/* --------------------------------------------------------------------------
 * 默认隐藏路径清单
 *
 * susfs 的 sus_path 是对 inode 打 AS_FLAGS_SUS_PATH 标记，命中后
 * stat/readdir/open 都看不到该路径。这里在 second_stage（/data 挂载后）
 * 把 7kimisu 自己的数据目录全部标记掉。
 *
 * 路径不存在时 kern_path 失败，静默跳过即可。
 * -------------------------------------------------------------------------- */
static const char *ksu_susfs_default_sus_paths[] = {
    "/data/adb/sevenk",
    "/data/adb/sevenk/lib",
    "/data/adb/sevenk/modules",
    "/data/adb/sevenk/stealth",
    "/data/adb/sevenk/.allowlist",
    "/data/adb/ksud",
    "/metadata/ksu",
};

static void ksu_susfs_add_sus_path(const char *pathname)
{
    struct path path;
    struct inode *inode;
    int err;

    if (!pathname || !*pathname)
        return;

    err = kern_path(pathname, LOOKUP_FOLLOW, &path);
    if (err) {
        pr_debug("susfs: skip '%s', err=%d\n", pathname, err);
        return;
    }

    inode = d_backing_inode(path.dentry);
    if (inode && inode->i_mapping) {
        set_bit(AS_FLAGS_SUS_PATH, &inode->i_state);
        pr_info("susfs: sus_path added: '%s'\n", pathname);
    }
    path_put(&path);
}
#endif /* CONFIG_KSU_SUSFS_SUS_PATH */

/* --------------------------------------------------------------------------
 * second_stage 入口：init 挂载 /data 后由 ksud_integration.c 调用
 * -------------------------------------------------------------------------- */
void ksu_susfs_handle_second_stage(void)
{
#ifdef CONFIG_KSU_SUSFS
    int i;

    /* susfs.c 的初始化（INIT_WORK susfs_extra_works）。
     * VFS 补丁只定义不调用——它假定 KSU 侧集成会调，这里补上 */
    susfs_init();

#ifdef CONFIG_KSU_SUSFS_SUS_PATH
    for (i = 0; i < ARRAY_SIZE(ksu_susfs_default_sus_paths); i++)
        ksu_susfs_add_sus_path(ksu_susfs_default_sus_paths[i]);
#endif

#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
    /* 对非 su 进程隐藏 KSU 挂载（/proc/mounts、mountinfo） */
    static_branch_enable(&susfs_is_hide_sus_mnts_for_non_su_procs_enabled);
    pr_info("susfs: hide_sus_mnts_for_non_su_procs enabled\n");
#endif

    pr_info("susfs: defaults applied (SUSFS v2.2.0)\n");
#endif /* CONFIG_KSU_SUSFS */
}
CEOF

python3 - <<'PYEOF2'
import sys

def patch(path, pairs, required=True):
    try:
        with open(path, encoding='utf-8') as f:
            s = f.read()
    except FileNotFoundError:
        print(f"[414compat-susfs] ERROR: {path} not found")
        sys.exit(1)
    changed = False
    for pair in pairs:
        old, new = pair[0], pair[1]
        unique = pair[2] if len(pair) > 2 else True
        n = s.count(old)
        if n > 1 and unique:
            print(f"[414compat-susfs] ERROR: pattern occurs {n} times in {path} (expected 1):")
            print(old[:300])
            sys.exit(1)
        if n >= 1:
            s = s.replace(old, new)
            changed = True
            print(f"[414compat-susfs] {path}: patched ({n} hit{'s' if n > 1 else ''})")
        elif required:
            print(f"[414compat-susfs] ERROR: pattern not found in {path}:")
            print(old[:300])
            sys.exit(1)
        else:
            print(f"[414compat-susfs] {path}: pattern absent, skip")
    if changed:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(s)

# c1) Kconfig: 在 endmenu 前追加 SUSFS 选项（susfs.c 的 ifdef 依赖它们）
patch('Kconfig', [(
"""endmenu""",
"""config KSU_SUSFS
	bool "SUSFS support for KernelSU (VFS layer from susfs patch)"
	depends on KSU
	default y
	help
	  Enable SUSFS integration. Requires the susfs VFS patch
	  (susfs_patch_to_4.14.patch) applied to the kernel tree.

config KSU_SUSFS_SUS_PATH
	bool "Hide susfs paths from stat/readdir/open"
	depends on KSU_SUSFS
	default y

config KSU_SUSFS_SUS_MOUNT
	bool "Hide sus mounts for non-su processes"
	depends on KSU_SUSFS
	default y

config KSU_SUSFS_SUS_KSTAT
	bool "Spoof kstat for sus paths"
	depends on KSU_SUSFS
	default n

config KSU_SUSFS_SPOOF_UNAME
	bool "Spoof uname"
	depends on KSU_SUSFS
	default n

config KSU_SUSFS_ENABLE_LOG
	bool "Enable susfs logging"
	depends on KSU_SUSFS
	default n

config KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
	bool "Spoof /proc/cmdline"
	depends on KSU_SUSFS
	default n

config KSU_SUSFS_OPEN_REDIRECT
	bool "Open path redirection"
	depends on KSU_SUSFS
	default n

config KSU_SUSFS_SUS_MAP
	bool "Hide susfs paths from /proc/self/maps"
	depends on KSU_SUSFS
	default n

config KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS
	bool "Hide ksu_/susfs_ symbols from /proc/kallsyms"
	depends on KSU_SUSFS
	default y
	help
	  Hide KernelSU and susfs symbols from /proc/kallsyms.
	  Requires the kallsyms.c hunk from the susfs patch.

endmenu""",
)])

# c2) Kbuild: 编入 susfs_ksu.o
patch('Kbuild', [(
"kernelsu-objs := core/init.o",
"kernelsu-objs := core/init.o\nkernelsu-objs += susfs_ksu.o",
)])

# c3) ksud_integration.c: extern 声明 + second_stage 时应用 susfs 默认路径
patch('runtime/ksud_integration.c', [(
"""#include "hook/syscall_event_bridge.h"

// clang-format off""",
"""#include "hook/syscall_event_bridge.h"

void ksu_susfs_handle_second_stage(void);

// clang-format off""",
), (
"""            ksu_selinux_hide_handle_second_stage();""",
"""            ksu_selinux_hide_handle_second_stage();
            ksu_susfs_handle_second_stage();""",
)])

print("[414compat-susfs] integration done")
PYEOF2

echo "[414compat] SUSFS integration injected"
else
echo "[414compat] SUSFS integration skipped (no 'susfs' arg)"
fi
