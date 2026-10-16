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
# 本脚本做四类处理：
#   1. 精确替换：给新版 API 调用加版本守卫或改写成 4.14 等价写法
#   2. 整体移植：将深度依赖 5.x+ 内部结构的特性（SELinux sepolicy 规则
#      注入、SELinux 隐藏）替换为 BakaSU 的 4.14 兼容实现（组 30），
#      依赖 MTK 4.14.186 已 backport 的 selinux_ss（内含 status_page /
#      policy_rwlock）与带 selinux_state 参数的 security_* API
#   3. 整体 stub：仅对 4.14 确无等价路径的特性置空（seccomp filter
#      cache 等），保证内核可编译、su 基本功能可用
#   4. 头物化：把仓库根 uapi/ 的 UAPI 头（内嵌构建只拷 kernel/，会漏掉）
#      原样落到 drivers/kernelsu/uapi/，并给 Kbuild 补 selinux 生成头的
#      查找路径与依赖
#
# 已知 4.14 限制（相对新版内核）：
#   - apply_kernelsu_rules / handle_sepolicy 与 SELinux 隐身（selinux_hide）
#     均已恢复：组 30 移植 BakaSU 4.14 兼容实现，su 提权的 sepolicy 规则
#     注入与 /sys/fs/selinux 查询伪装可用（经两种模式全内核构建验证）
#   - seccomp filter cache 不可用（4.18+ 的 struct seccomp_filter 才有
#     cache 字段，与 upstream 4.14 行为一致）
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
#    （sepolicy 规则注入不需要 selinux_state.policy 机制：组 30 移植的
#      rules.c 走 selinux_state.ss->policydb + selinuxfs mutex 路径。）
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
# 30) SELinux sepolicy 规则注入 + SELinux 隐藏（BakaSU 4.14 兼容实现）
#
# 原 7kimisu 的 rules.c / sepolicy.c / selinux_hide.c 是 5.x-only 设计：
#   - struct selinux_policy              （5.3+）
#   - selinux_state.policy / policy_mutex（5.10+）
#   - selinux_state.status_lock/status_page（4.16+；MTK 4.14.186 的
#     struct selinux_ss 自带这两个字段，走 ss->* 即可）
#   - sidtab_entry / sidtab_sid2str_*     （5.1+）
#   - hashtab_key_params                  （5.9+）
#   - symtab_search / sym_name            （5.9+）
#   - policydb_filenametr_search          （5.x）
# 4.14 全部缺失，曾整体 stub，导致 apply_kernelsu_rules（su 提权的 sepolicy
# 规则注入）与 selinux_hide（/sys/fs/selinux 查询伪装）双双失效。
#
# 现移植 BakaSU（tiann/KernelSU 下游，官方声明兼容 4.2-6.18）的同名实现，
# 其 compat 体系为源码树扫描式（tools/kernel_compat.mk 用 grep 检测内核
# 能力生成 -DKSU_COMPAT_*），在 MTK 4.14.186 上自动走：
#   KSU_COMPAT_HAS_SELINUX_STATE   -> selinux_state.ss->policydb
#   KSU_COMPAT_SIDTAB_AS_REFERENCE -> sidtab 指针语义
#   legacy sel_mutex/policy_rwlock -> selinuxfs_mount->mnt_sb->s_fs_info
#   lsm list 4.2+ 路径             -> list_for_each_entry 遍历 hook_heads
#   status 访问                    -> selinux_state.ss->status_lock/status_page
# 文件清单（均来自 BakaSU main，GPL-2.0）：
#   compat/kernel_compat.{c,h}、tools/kernel_compat.mk、
#   selinux/sepolicy.{c,h}、selinux/rules.c、feature/selinux_hide.{c,h}
#   （另需 include/ksu.h 的 backup 变量条件声明与 selinux/selinux.h 的
#     KSU_COMPAT_USE_SELINUX_STATE 宏，见下方 PYKSU/PYSEL）
# infra/seccomp_cache.c 仍保留 stub（struct seccomp_filter 无 cache 字段，
# 4.18+ 才有，与 upstream 行为一致）。
# -----------------------------------------------------------------------------

mkdir -p compat tools
cat > compat/kernel_compat.h <<'KCEOF'
#ifndef __KSU_H_KERNEL_COMPAT
#define __KSU_H_KERNEL_COMPAT

#include <linux/namei.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <linux/version.h>
#include <linux/fdtable.h>
#include "ss/policydb.h"
#include <linux/key.h>
#include <linux/ptrace.h>
#include <linux/syscalls.h>
#include "arch.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
#if defined(__aarch64__)
#define KSU_SYS_PREFIX(name) __arm64_sys_##name
#elif defined(__x86_64__)
#define KSU_SYS_PREFIX(name) __x64_sys_##name
#elif defined(__riscv)
#define KSU_SYS_PREFIX(name) __riscv_sys_##name
#elif defined(__arm__)
#define KSU_SYS_PREFIX(name) sys_##name
#else // wire up your arch here.
static_assert(1 == 0, "Unsupported architecture!");
#define KSU_SYS_PREFIX(name) sys_##name
#endif

/**
 * ksyscall: call syscalls from kernelspace
 * - tries to copy unistd's syscall()
 *
 * usage: ksyscall(close, fd);
 */
#define __ksyscall(name, a, b, c, d, e, f)                                                                             \
    ({                                                                                                                 \
        extern long KSU_SYS_PREFIX(name)(const struct pt_regs *);                                                      \
        struct pt_regs __ksu_regs = { 0 };                                                                             \
        PT_REGS_PARM1(&__ksu_regs) = (unsigned long)(a);                                                               \
        PT_REGS_PARM2(&__ksu_regs) = (unsigned long)(b);                                                               \
        PT_REGS_PARM3(&__ksu_regs) = (unsigned long)(c);                                                               \
        PT_REGS_SYSCALL_PARM4(&__ksu_regs) = (unsigned long)(d);                                                       \
        PT_REGS_PARM5(&__ksu_regs) = (unsigned long)(e);                                                               \
        PT_REGS_PARM6(&__ksu_regs) = (unsigned long)(f);                                                               \
        (long)KSU_SYS_PREFIX(name)(&__ksu_regs);                                                                       \
    })

// https://elixir.bootlin.com/musl/v1.2.6/source/src/internal/syscall.h#L45
#define ksyscall_0(name) __ksyscall(name, 0, 0, 0, 0, 0, 0)
#define ksyscall_1(name, a) __ksyscall(name, a, 0, 0, 0, 0, 0)
#define ksyscall_2(name, a, b) __ksyscall(name, a, b, 0, 0, 0, 0)
#define ksyscall_3(name, a, b, c) __ksyscall(name, a, b, c, 0, 0, 0)
#define ksyscall_4(name, a, b, c, d) __ksyscall(name, a, b, c, d, 0, 0)
#define ksyscall_5(name, a, b, c, d, e) __ksyscall(name, a, b, c, d, e, 0)
#define ksyscall_6(name, a, b, c, d, e, f) __ksyscall(name, a, b, c, d, e, f)

#else
#define KSU_SYS_PREFIX(name) sys_##name

#define ksyscall_0(name)                                                                                               \
    ({                                                                                                                 \
        extern typeof(KSU_SYS_PREFIX(name)) KSU_SYS_PREFIX(name);                                                      \
        (long)KSU_SYS_PREFIX(name)();                                                                                  \
    })

#define ksyscall_1(name, a)                                                                                            \
    ({                                                                                                                 \
        extern typeof(KSU_SYS_PREFIX(name)) KSU_SYS_PREFIX(name);                                                      \
        (long)KSU_SYS_PREFIX(name)(a);                                                                                 \
    })

#define ksyscall_2(name, a, b)                                                                                         \
    ({                                                                                                                 \
        extern typeof(KSU_SYS_PREFIX(name)) KSU_SYS_PREFIX(name);                                                      \
        (long)KSU_SYS_PREFIX(name)(a, b);                                                                              \
    })

#define ksyscall_3(name, a, b, c)                                                                                      \
    ({                                                                                                                 \
        extern typeof(KSU_SYS_PREFIX(name)) KSU_SYS_PREFIX(name);                                                      \
        (long)KSU_SYS_PREFIX(name)(a, b, c);                                                                           \
    })

#define ksyscall_4(name, a, b, c, d)                                                                                   \
    ({                                                                                                                 \
        extern typeof(KSU_SYS_PREFIX(name)) KSU_SYS_PREFIX(name);                                                      \
        (long)KSU_SYS_PREFIX(name)(a, b, c, d);                                                                        \
    })

#define ksyscall_5(name, a, b, c, d, e)                                                                                \
    ({                                                                                                                 \
        extern typeof(KSU_SYS_PREFIX(name)) KSU_SYS_PREFIX(name);                                                      \
        (long)KSU_SYS_PREFIX(name)(a, b, c, d, e);                                                                     \
    })

#define ksyscall_6(name, a, b, c, d, e, f)                                                                             \
    ({                                                                                                                 \
        extern typeof(KSU_SYS_PREFIX(name)) KSU_SYS_PREFIX(name);                                                      \
        (long)KSU_SYS_PREFIX(name)(a, b, c, d, e, f);                                                                  \
    })
#endif

#define __ksyscall_arg_n(_1, _2, _3, _4, _5, _6, _7, N, ...) N
#define __ksyscall_count_args(...) __ksyscall_arg_n(__VA_ARGS__, 6, 5, 4, 3, 2, 1, 0)
#define __ksyscall_concat(a, b) a##b
#define __ksyscall_exp(func, arg) __ksyscall_concat(func, arg)
#define ksyscall(...) __ksyscall_exp(ksyscall_, __ksyscall_count_args(__VA_ARGS__))(__VA_ARGS__)

#define ksu_close_fd(fd) ({ ksyscall(close, fd); })
#define ksu_sys_setns(fd, flags) ({ ksyscall(setns, fd, flags); })
#define ksu_sys_umount(mnt, flags) ({ ksyscall(umount, (char __user *)mnt, flags); })

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0)
#define ksys_unshare(flags) ({ ksyscall(unshare, flags); })
#endif

/*
 * Leagcy Huawei Hisi Devices info Start
 * For EMUI 9,9.1.0(Or HarmonyOS2 Based EMUI 9.1.0),10 Devices
 * Adapt to Huawei HISI kernel without affecting other kernels ,
 * Huawei Hisi Kernel EBITMAP Enable or Disable Flag ,
 * From ss/ebitmap.h
 */
#if ((LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)) && (LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0))) ||            \
    ((LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)) && (LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0)))
#if defined(HISI_SELINUX_EBITMAP_RO) && !defined(KSU_COMPAT_IS_HISI_HM2)
#define KSU_COMPAT_IS_HISI_LEGACY 1
#endif
#endif

/* 
* For EMUI 10+ or HarmonyOS2 Based EMUI10+ Devices
*/
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)) && (LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0))
#if defined(KSU_COMPAT_IS_HISI_HM2)
#define KSU_COMPAT_IS_HISI_LEGACY_HM2 1
#endif
#endif

/*
* Leagcy Huawei Hisi Devices info End
*/

// Checks for UH, KDP and RKP
#ifdef SAMSUNG_UH_DRIVER_EXIST
#if defined(CONFIG_UH) || defined(CONFIG_KDP) || defined(CONFIG_RKP)
#error                                                                                                                 \
    "CONFIG_UH, CONFIG_KDP and CONFIG_RKP is enabled! Please disable or remove it before compile a kernel with KernelSU!"
#endif
#endif

extern long ksu_strncpy_from_user_nofault(char *dst, const void __user *unsafe_addr, long count);

extern ssize_t ksu_kernel_read_compat(struct file *p, void *buf, size_t count, loff_t *pos);
extern ssize_t ksu_kernel_write_compat(struct file *p, const void *buf, size_t count, loff_t *pos);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
#define ksu_access_ok(addr, size) access_ok(addr, size)
#else
#define ksu_access_ok(addr, size) access_ok(VERIFY_READ, addr, size)
#endif

// https://elixir.bootlin.com/linux/v5.3-rc1/source/kernel/signal.c#L1613
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
#define __force_sig(sig) force_sig(sig)
#else
#define __force_sig(sig) force_sig(sig, current)
#endif

// Linux >= 5.7
// task_work_add (struct, struct, enum)
// Linux pre-5.7
// task_work_add (struct, struct, bool)
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
#ifndef TWA_RESUME
#define TWA_RESUME true
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0) && !defined(KSU_UL_HAS_FILE_INODE)
static inline struct inode *file_inode(struct file *f)
{
    return f->f_path.dentry->d_inode;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0) && !defined(KSU_OPTIONAL_SELINUX_INODE)
static inline struct inode_security_struct *selinux_inode(const struct inode *inode)
{
    return inode->i_security;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0) && !defined(KSU_OPTIONAL_SELINUX_CRED)
static inline struct task_security_struct *selinux_cred(const struct cred *cred)
{
    return cred->security;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
extern void *ksu_compat_kvrealloc(const void *p, size_t oldsize, size_t newsize, gfp_t flags);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0)
__weak void groups_sort(struct group_info *group_info)
{
    return;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 5, 0) && !defined(KSU_HAS_INODE_LOCK_UNLOCK)
// https://github.com/torvalds/linux/commit/5955102c9984fa081b2d570cfac75c97eecf8f3b
// for setuid_hooks only
// it will remove when we impl dynamic-manager feature init out of replaceable ksud
static inline void inode_lock(struct inode *inode)
{
    mutex_lock(&inode->i_mutex);
}

static inline void inode_unlock(struct inode *inode)
{
    mutex_unlock(&inode->i_mutex);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0)
#define ksu_get_uid_t(x) *(unsigned int *)&(x)
#else
#define ksu_get_uid_t(x) (x.val)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 0)
__weak char *bin2hex(char *dst, const void *src, size_t count)
{
    const unsigned char *_src = src;
    while (count--)
        dst = pack_hex_byte(dst, *_src++);
    return dst;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0)
// https://github.com/torvalds/linux/commit/89a0714106aac7309c7dfa0f004b39e1e89d2942
// app_profile require U16_MAX, define here
#define U16_MAX ((u16)~0U)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0) && !defined(KSU_HAS_ITERATE_DIR)
struct dir_context {
    const filldir_t actor;
    loff_t pos;
};

static int iterate_dir(struct file *file, struct dir_context *ctx)
{
    return vfs_readdir(file, ctx->actor, ctx);
}
#endif // KSU_HAS_ITERATE_DIR

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 8, 0)
__weak long vfs_truncate(struct path *path, loff_t length)
{
    struct inode *inode;
    long error;

    inode = path->dentry->d_inode;

    /* For directories it's -EISDIR, for other non-regulars - -EINVAL */
    if (S_ISDIR(inode->i_mode))
        return -EISDIR;
    if (!S_ISREG(inode->i_mode))
        return -EINVAL;

    error = mnt_want_write(path->mnt);
    if (error)
        goto out;

    error = inode_permission(inode, MAY_WRITE);
    if (error)
        goto mnt_drop_write_and_out;

    error = -EPERM;
    if (IS_APPEND(inode))
        goto mnt_drop_write_and_out;

    error = get_write_access(inode);
    if (error)
        goto mnt_drop_write_and_out;

    /*
	 * Make sure that there are no leases.  get_write_access() protects
	 * against the truncate racing with a lease-granting setlease().
	 */
    error = break_lease(inode, O_WRONLY);
    if (error)
        goto put_write_and_out;

    error = locks_verify_truncate(inode, NULL, length);
    if (!error)
        error = security_path_truncate(path);
    if (!error)
        error = do_truncate(path->dentry, length, 0, NULL);

put_write_and_out:
    put_write_access(inode);
mnt_drop_write_and_out:
    mnt_drop_write(path->mnt);
out:
    return error;
}
#endif

// linux kernel https://github.com/torvalds/linux/commit/7e040726850a106587485c21bdacc0bfc8a0cbed
// kanged from xxksu lmao
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0) && !defined(EPOLLIN)
#define EPOLLIN 0x00000001
#define EPOLLPRI 0x00000002
#define EPOLLOUT 0x00000004
#define EPOLLERR 0x00000008
#define EPOLLHUP 0x00000010
#define EPOLLRDNORM 0x00000040
#define EPOLLRDBAND 0x00000080
#define EPOLLWRNORM 0x00000100
#define EPOLLWRBAND 0x00000200
#define EPOLLMSG 0x00000400
#define EPOLLRDHUP 0x00002000
#endif

#ifndef READ_ONCE
#define READ_ONCE(x) (*(const volatile typeof(x) *)&(x))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0)
#define task_ppid_nr(a) (pid_t) sys_getppid()
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 17, 0)
static inline u64 ksu_ktime_get_ns(void)
{
    return ktime_to_ns(ktime_get());
}
#define ktime_get_ns ksu_ktime_get_ns
#endif

// WARNING: no overflow safety!
#ifndef struct_size
#define struct_size(p, member, n) (sizeof(*(p)) + (n) * sizeof(*(p)->member))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
#ifndef ALIGN_DOWN
#define ALIGN_DOWN(x, a) __ALIGN_KERNEL((x) - ((a) - 1), (a))
#endif
#endif

#ifndef untagged_addr
#define untagged_addr(addr) (addr)
#endif

#ifndef in_compat_syscall
#define in_compat_syscall() is_compat_task()
#endif

extern void ksu_run_in_init_if_possible(void (*callback)(void *), void *data);

extern struct key *init_session_keyring;
extern void setup_ksu_cred_session_keyring(void);

static inline struct key *ksu_get_session_keyring(const struct cred *cred)
{
// https://github.com/torvalds/linux/commit/3a50597de8635cd05133bd12c95681c82fe7b878
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
    return rcu_dereference(cred->session_keyring);
#else
    return rcu_dereference(current->cred->tgcred->session_keyring);
#endif
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0) || defined(KSU_HAS_MODERN_STATIC_KEY_INTERFACE)
#define KSU_COMPAT_USE_STATIC_KEY
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
__weak long copy_from_kernel_nofault(void *dst, const void *src, size_t size)
{
    // https://elixir.bootlin.com/linux/v5.2.21/source/mm/maccess.c#L27
    long ret;
    mm_segment_t old_fs = get_fs();

    set_fs(KERNEL_DS);
    pagefault_disable();
    ret = __copy_from_user_inatomic(dst, (__force const void __user *)src, size);
    pagefault_enable();
    set_fs(old_fs);

    return ret ? -EFAULT : 0;
}
#endif

#ifndef __nocfi
#define __nocfi
#endif

// https://github.com/torvalds/linux/commit/294f69e662d1570703e9b56e95be37a9fd3afba5
// f**k old compiler, thx for your notices, but better don't notice next time
#ifndef __GCC4_has_attribute___fallthrough__
#define __GCC4_has_attribute___fallthrough__ 0
#endif

#ifndef __has_attribute
#define __has_attribute(x) __GCC4_has_attribute_##x
#endif
/*
 * Add the pseudo keyword 'fallthrough' so case statement blocks
 * must end with any of these keywords:
 *   break;
 *   fallthrough;
 *   continue;
 *   goto <label>;
 *   return [expression];
 *
 *  gcc: https://gcc.gnu.org/onlinedocs/gcc/Statement-Attributes.html#Statement-Attributes
 */
#if __has_attribute(__fallthrough__)
#define fallthrough __attribute__((__fallthrough__))
#else
#define fallthrough                                                                                                    \
    do {                                                                                                               \
    } while (0) /* fallthrough */
#endif

#ifdef KSU_COMPAT_SYM_NAME_NOT_FOUND

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0) && !defined(KSU_COMPAT_HAS_MODERN_POLICYDB)
#include <linux/flex_array.h>
#endif

static inline char *sym_name(struct policydb *p, unsigned int sym_num, unsigned int element_nr)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0) || defined(KSU_COMPAT_HAS_MODERN_POLICYDB)
    return p->sym_val_to_name[sym_num][element_nr];
#else
    struct flex_array *fa = p->sym_val_to_name[sym_num];

    return flex_array_get_ptr(fa, element_nr);
#endif
}
#endif

static inline struct file *ksu_filp_open_nonotify(const char *path, int flags)
{
    struct path p;
    struct file *f;
    int ret;
    ret = kern_path(path, (flags & O_NOFOLLOW) ? 0 : LOOKUP_FOLLOW, &p);
    if (ret) {
        return ERR_PTR(ret);
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 14, 0)
    f = dentry_open_nonotify(&p, flags, current_cred());
    // https://github.com/torvalds/linux/commit/765927b2d508712d320c8934db963bbe14c3fcec
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 6, 0) || defined(KSU_COMPAT_HAS_MODERN_DENTRY_OPEN)
    f = dentry_open(&p, flags | __FMODE_NONOTIFY, current_cred());
#else
    // clang-format off

    // Old dentry_open consumes dentry / mnt!
    // We have 2 choice
    // 1. path_get or dget and mntget before call dentry_open
    // 2. don't path_put when it happen
    //
    // I choose #2, because it can optimize 1 dentry / mnt get and put
    // Because stupid compiler's dead code warning, we can't directly return f when this case end
    // define DENTRY_OPEN_COSUME_CONTEXT and ifdef for path_put to let them shut up
    #define DENTRY_OPEN_CONSUME_CONTEXT
    // clang-format on
    f = dentry_open(p.dentry, p.mnt, flags | __FMODE_NONOTIFY, current_cred());
    // return f;
#endif

#ifndef DENTRY_OPEN_CONSUME_CONTEXT
    path_put(&p);
#endif
    return f;
}

#endif
KCEOF
cat > compat/kernel_compat.c <<'KCEOF'
#include <linux/version.h>
#include <linux/fs.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/task.h>
#else
#include <linux/sched.h>
#endif
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/errno.h>

#include "klog.h" // IWYU pragma: keep
#include "kernel_compat.h"
#include "ksu.h"

ssize_t ksu_kernel_read_compat(struct file *p, void *buf, size_t count, loff_t *pos)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0) || defined(KSU_OPTIONAL_KERNEL_READ)
    return kernel_read(p, buf, count, pos);
#else // https://elixir.bootlin.com/linux/v4.14.336/source/fs/read_write.c#L418
    mm_segment_t old_fs;
    old_fs = get_fs();
    set_fs(get_ds());
    ssize_t result = vfs_read(p, (void __user *)buf, count, pos);
    set_fs(old_fs);
    return result;
#endif
}

ssize_t ksu_kernel_write_compat(struct file *p, const void *buf, size_t count, loff_t *pos)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0) || defined(KSU_OPTIONAL_KERNEL_WRITE)
    return kernel_write(p, buf, count, pos);
#else // https://elixir.bootlin.com/linux/v4.14.336/source/fs/read_write.c#L512
    mm_segment_t old_fs;
    old_fs = get_fs();
    set_fs(get_ds());
    ssize_t res = vfs_write(p, (__force const char __user *)buf, count, pos);
    set_fs(old_fs);
    return res;
#endif
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0) || defined(KSU_OPTIONAL_STRNCPY)
long ksu_strncpy_from_user_nofault(char *dst, const void __user *unsafe_addr, long count)
{
    return strncpy_from_user_nofault(dst, unsafe_addr, count);
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
long ksu_strncpy_from_user_nofault(char *dst, const void __user *unsafe_addr, long count)
{
    return strncpy_from_unsafe_user(dst, unsafe_addr, count);
}
#else
// Copied from: https://elixir.bootlin.com/linux/v4.9.337/source/mm/maccess.c#L201
long ksu_strncpy_from_user_nofault(char *dst, const void __user *unsafe_addr, long count)
{
    mm_segment_t old_fs = get_fs();
    long ret;

    if (unlikely(count <= 0))
        return 0;

    set_fs(USER_DS);
    pagefault_disable();
    ret = strncpy_from_user(dst, unsafe_addr, count);
    pagefault_enable();
    set_fs(old_fs);

    if (ret >= count) {
        ret = count;
        dst[ret - 1] = '\0';
    } else if (ret > 0) {
        ret++;
    }

    return ret;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
__weak int path_mount(const char *dev_name, struct path *path, const char *type_page, unsigned long flags,
                      void *data_page)
{
    // 384 is enough
    char buf[384] = { 0 };
    mm_segment_t old_fs;
    long ret;

    // -1 on the size as implicit null termination
    // as we zero init the thing
    char *realpath = d_path(path, buf, sizeof(buf) - 1);
    if (!(realpath && realpath != buf))
        return -ENOENT;

    old_fs = get_fs();
    set_fs(KERNEL_DS);
    ret = do_mount(dev_name, (const char __user *)realpath, type_page, flags, data_page);
    set_fs(old_fs);
    return ret;
}
#endif

static void *__kvmalloc(size_t size, gfp_t flags)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
    // https://elixir.bootlin.com/linux/v4.4.302/source/security/apparmor/lib.c#L79
    void *buffer = NULL;

    if (size == 0)
        return NULL;

    /* do not attempt kmalloc if we need more than 16 pages at once */
    if (size <= (16 * PAGE_SIZE))
        buffer = kmalloc(size, flags | GFP_NOIO | __GFP_NOWARN);
    if (!buffer) {
        if (flags & __GFP_ZERO)
            buffer = vzalloc(size);
        else
            buffer = vmalloc(size);
    }
    return buffer;
#else
    return kvmalloc(size, flags);
#endif
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
// https://elixir.bootlin.com/linux/v5.10.247/source/mm/util.c#L664
void *ksu_compat_kvrealloc(const void *p, size_t oldsize, size_t newsize, gfp_t flags)
{
    void *newp;

    if (oldsize >= newsize)
        return (void *)p;
    newp = __kvmalloc(newsize, flags);
    if (!newp)
        return NULL;
    memcpy(newp, p, oldsize);
    kvfree(p);
    return newp;
}
#endif

// https://github.com/torvalds/linux/commit/e73f8959af0439d114847eab5a8a5ce48f1217c4
// this feature include in 3.5, but from my test, we no need that for 3.5-
// directly call is enough
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
#include <linux/task_work.h>
struct ksu_task_work_struct {
    struct callback_head cb;
    void (*callback)(void *);
    void *data;
};

static void ksu_task_work_dispatcher(struct callback_head *cb)
{
    struct ksu_task_work_struct *tw = container_of(cb, struct ksu_task_work_struct, cb);
    tw->callback(tw->data);
    kfree(tw);
}
#endif

void ksu_run_in_init_if_possible(void (*callback)(void *), void *data)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
    struct task_struct *tsk;

    tsk = get_pid_task(find_vpid(1), PIDTYPE_PID);
    if (!tsk) {
        pr_err("ksu run in init find init task err\n");
        return;
    }

    // GFP_ATOMIC here, i don't want think the caller is in atomic context or not
    struct ksu_task_work_struct *tw = kzalloc(sizeof(struct ksu_task_work_struct), GFP_ATOMIC);
    if (!tw) {
        pr_err("ksu run in init alloc tw err\n");
        goto put_task;
    }

    tw->callback = callback;
    tw->data = data;
    tw->cb.func = ksu_task_work_dispatcher;

    if (task_work_add(tsk, &tw->cb, TWA_RESUME)) {
        kfree(tw);
        pr_warn("ksu run in init add task_work failed\n");
    }

put_task:
    put_task_struct(tsk);
#else
    callback(data);
#endif
}

struct key *init_session_keyring = NULL;
extern int install_session_keyring_to_cred(struct cred *, struct key *);

void setup_ksu_cred_session_keyring(void)
{
    if (ksu_get_session_keyring(ksu_cred)) {
        // if we have session_keyring, skip
        return;
    }

    if (init_session_keyring == NULL) {
        // if init_session_keyring is null, skip
        return;
    }

    install_session_keyring_to_cred(ksu_cred, init_session_keyring);

    pr_info("kernel_compat: %s: install init_session_keyring to ksu_cred\n", __func__);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
__weak int path_umount(struct path *path, int flags)
{
    char buf[256];
    int ret = -ENOENT;

    char *usermnt = d_path(path, buf, sizeof(buf) - 1);
    if (IS_ERR(usermnt) || usermnt == buf)
        goto out;

    mm_segment_t old_fs = get_fs();
    set_fs(KERNEL_DS);
    ret = ksu_sys_umount((char __user *)usermnt, flags);
    set_fs(old_fs);

out: // release ref here! user_path_at increases it then only cleans for itself
    path_put(path);
    return ret;
}
#endif // < 5.9
KCEOF
cat > tools/kernel_compat.mk <<'KCEOF'
# SELinux drivers check
ifeq ($(shell grep -q "current_sid(void)" $(srctree)/security/selinux/include/objsec.h; echo $$?),0)
$(info -- 7kimisu/compat: current_sid found)
ccflags-y += -DKSU_COMPAT_HAS_CURRENT_SID
endif
ifeq ($(shell grep -q "struct selinux_state " $(srctree)/security/selinux/include/security.h; echo $$?),0)
$(info -- 7kimisu/compat: selinux_state found)
ccflags-y += -DKSU_COMPAT_HAS_SELINUX_STATE
endif

# Handle optional backports
ifeq ($(shell grep -q "strncpy_from_user_nofault" $(srctree)/include/linux/uaccess.h; echo $$?),0)
$(info -- 7kimisu/compat: strncpy found)
ccflags-y += -DKSU_OPTIONAL_STRNCPY
endif

ifeq ($(shell grep -q "ssize_t kernel_read" $(srctree)/fs/read_write.c; echo $$?),0)
$(info -- 7kimisu/compat: kernel_read found)
ccflags-y += -DKSU_OPTIONAL_KERNEL_READ
endif

ifeq ($(shell grep "ssize_t kernel_write" $(srctree)/fs/read_write.c | grep -q "const void" ; echo $$?),0)
$(info -- 7kimisu/compat: kernel_write found)
ccflags-y += -DKSU_OPTIONAL_KERNEL_WRITE
endif

ifeq ($(shell grep -q "inode_security_struct\s\+\*selinux_inode" $(srctree)/security/selinux/include/objsec.h; echo $$?),0)
$(info -- 7kimisu/compat: selinux_inode found)
ccflags-y += -DKSU_OPTIONAL_SELINUX_INODE
endif

ifeq ($(shell grep -q "task_security_struct\s\+\*selinux_cred" $(srctree)/security/selinux/include/objsec.h; echo $$?),0)
$(info -- 7kimisu/compat: selinux_cred found)
ccflags-y += -DKSU_OPTIONAL_SELINUX_CRED
endif

# seccomp_types.h was added in 6.7
ifeq ($(shell grep -q "atomic_t\s\+filter_count" $(srctree)/include/linux/seccomp.h $(srctree)/include/linux/seccomp_types.h 2>/dev/null; echo $$?),0)
$(info -- 7kimisu/compat: seccomp_filter_count found)
ccflags-y += -DKSU_OPTIONAL_SECCOMP_FILTER_CNT
endif

# some old kernels backport this, so check whether put_seccomp_filter still exists
ifneq ($(shell grep -wq "put_seccomp_filter" $(srctree)/kernel/seccomp.c $(srctree)/include/linux/seccomp.h; echo $$?),0)
$(info -- 7kimisu/compat: put_seccomp_filter found)
ccflags-y += -DKSU_OPTIONAL_SECCOMP_FILTER_RELEASE
endif

# https://github.com/torvalds/linux/commit/215b674b84dd052098fe6389e32a5afaff8b4d56
# 5.12-
ifeq ($(shell grep -q "security_inode_init_security_anon" $(srctree)/include/linux/security.h; echo $$?),0)
$(info -- 7kimisu/compat: security_inode_init_security_anon found)
ccflags-y += -DKSU_OPTIONAL_HAS_INIT_SEC_ANON
endif

# https://github.com/torvalds/linux/commit/e7e832ce6fa769f800cd7eaebdb0459ad31e0416
# 5.12-
ifeq ($(shell grep -q "anon_inode_getfd_secure" $(srctree)/fs/anon_inodes.c; echo $$?),0)
$(info -- 7kimisu/compat: anon_inode_getfd_secure found)
ccflags-y += -DKSU_HAS_GETFD_SECURE
endif

# https://github.com/torvalds/linux/commit/4f0b9194bc119a9850a99e5e824808e2f468c348
# 6.8-
ifeq ($(shell grep -q "anon_inode_create_getfd" $(srctree)/fs/anon_inodes.c; echo $$?),0)
$(info -- 7kimisu/compat: anon_inode_create_getfd found)
ccflags-y += -DKSU_HAS_ANON_INODE_CREATE_FD
endif

ifeq ($(shell grep -q "static inline struct inode \*file_inode" $(srctree)/include/linux/fs.h; echo $$?),0)
$(info -- 7kimisu/compat: file_inode() found)
ccflags-y += -DKSU_UL_HAS_FILE_INODE
endif

ifneq ($(shell grep -q __flush_dcache_area $(srctree)/arch/arm64/include/asm/cacheflush.h 2>/dev/null; echo $$?),0)
$(info -- 7kimisu/compat: __flush_dcache_area not found)
ccflags-y += -DKSU_FLUSH_DCACHE_AREA_NOT_FOUND
endif

# Checks Samsung
ifeq ($(shell grep -q "CONFIG_KDP_CRED" $(srctree)/kernel/cred.c; echo $$?),0)
$(info -- 7kimisu/compat/samsung: CONFIG_KDP_CRED found)
ccflags-y += -DSAMSUNG_UH_DRIVER_EXIST
endif

ifeq ($(shell grep -q "SEC_SELINUX_PORTING_COMMON" $(srctree)/security/selinux/avc.c; echo $$?),0)
$(info -- 7kimisu/compat/samsung: SEC_SELINUX_PORTING_COMMON found)
ccflags-y += -DSAMSUNG_SELINUX_PORTING
endif

## For Huawei EMUI10+ check  
# Scan Kernel Tree to find CONFIG_HKIP_SELINUX_PROT in ebitmap.h
ifeq ($(shell grep -q "CONFIG_HKIP_SELINUX_PROT" $(srctree)/security/selinux/ss/ebitmap.h 2>/dev/null; echo $$?),0)
$(info -- 7kimisu: CONFIG_HKIP_SELINUX_PROT found!)
ccflags-y += -DKSU_COMPAT_IS_HISI_HM2
endif

# policy mutex
# kernel 5.10+
ifeq ($(shell grep -q "policy_mutex" $(srctree)/security/selinux/include/security.h; echo $$?),0)
$(info -- 7kimisu/compat: policy_mutex found)
ccflags-y += -DKSU_COMPAT_HAS_POLICY_MUTEX
endif

# Function ns_get_path check
# for kernel 3.19-
# https://github.com/torvalds/linux/commit/e149ed2b805fefdccf7ccdfc19eca22fdd4514ac
ifeq ($(shell grep -q "ns_get_path" $(srctree)/fs/nsfs.c 2>/dev/null; echo $$?),0)
$(info -- 7kimisu/compat: ns_get_path found)
ccflags-y += -DKSU_COMPAT_HAS_NS_GET_PATH
endif

# Modern dentry_open check
# add . to skip (, avoid build failed
# for kernel 3.6-
ifeq ($(shell grep -q "dentry_open.const struct path" $(srctree)/include/linux/fs.h; echo $$?),0)
$(info -- 7kimisu/compat: modern dentry_open found)
ccflags-y += -DKSU_COMPAT_HAS_MODERN_DENTRY_OPEN
endif

# UL, look for "ext4_unregister_sysfs" on fs/ext4
ifeq ($(shell grep -q "^extern void ext4_unregister_sysfs" $(srctree)/fs/ext4/ext4.h 2>/dev/null; echo $$?),0)
$(info -- 7kimisu/compat: ext4_unregister_sysfs found)
ccflags-y += -DKSU_HAS_MODERN_EXT4
endif

# UL, look for read_iter on f_op struct
ifeq ($(shell grep -q "read_iter" $(srctree)/include/linux/fs.h 2>/dev/null; echo $$?),0)
$(info -- 7kimisu/compat: f_op->read_iter found)
ccflags-y += -DKSU_HAS_FOP_READ_ITER
endif

# UL, look for iterate_dir on fs/readdir.c
ifeq ($(shell grep -q "^int iterate_dir" $(srctree)/fs/readdir.c 2>/dev/null; echo $$?),0)
$(info -- 7kimisu/compat: iterate_dir found)
ccflags-y += -DKSU_HAS_ITERATE_DIR
endif

# UL, look for modern alloc_uid on include/linux/sched.h
ifeq ($(shell grep -q "alloc_uid.kuid_t" $(srctree)/include/linux/sched.c 2>/dev/null; echo $$?),0)
$(info -- 7kimisu/compat: modern alloc_Uid found)
ccflags-y += -DKSU_HAS_MODERN_ALLOC_UID
endif

# UL(4.3-), look for modern static_key interface
# https://github.com/torvalds/linux/commit/11276d5306b8e5b438a36bbff855fe792d7eaa61
ifeq ($(shell grep -q "DEFINE_STATIC_KEY_TRUE" $(srctree)/include/linux/jump_label.h 2>/dev/null; echo $$?),0)
$(info -- 7kimisu/compat: modern static_key_interface found)
ccflags-y += -DKSU_HAS_MODERN_STATIC_KEY_INTERFACE
endif

# UL(4.0-), d_inode may not found
# https://github.com/torvalds/linux/commit/155e35d4daa804582f75acaa2c74ec797a89c615
ifeq ($(shell grep -q "static inline struct inode..d_inode" $(srctree)/include/linux/dcache.h 2>/dev/null; echo $$?),0)
$(info -- 7kimisu/compat: d_inode found)
ccflags-y += -DKSU_HAS_D_INODE
endif

# https://github.com/torvalds/linux/commit/5955102c9984fa081b2d570cfac75c97eecf8f3b
# for setuid_hooks only
# it will remove when we impl dynamic-manager feature init out of replaceable ksud
ifeq ($(shell grep -q "inode_lock.struct inode" $(srctree)/include/linux/fs.h 2>/dev/null; echo $$?),0)
$(info -- 7kimisu/compat: inode_lock found)
ccflags-y += -DKSU_HAS_INODE_LOCK_UNLOCK
endif

# for kernel version below 3.7, uapi/asm-generic/errno.h maybe not found
ifneq ($(wildcard $(srctree)/include/uapi/asm-generic/errno.h),)
$(info -- 7kimisu/compat: modern errno file found)
ccflags-y += -I$(objtree)/security/selinux -include $(srctree)/include/uapi/asm-generic/errno.h
else
ccflags-y += -I$(objtree)/security/selinux -include $(srctree)/include/asm-generic/errno.h
endif

# for kernel version below 5.10, include/linux/minmax.h maybe not found
# https://github.com/torvalds/linux/commit/b296a6d53339a79082c1d2c1761e948e8b3def69
ifneq ($(wildcard $(srctree)/include/linux/minmax.h),)
$(info -- 7kimisu/compat: minmax.h found)
ccflags-y += -DKSU_COMPAT_HAS_MINMAX_H
endif

# for kernel version below 4.18, include/linux/overflow.h maybe not found
# https://github.com/torvalds/linux/commit/f0907827a8a9152aedac2833ed1b674a7b2a44f2
ifneq ($(wildcard $(srctree)/include/linux/overflow.h),)
$(info -- 7kimisu/compat: overflow.h found)
ccflags-y += -DKSU_COMPAT_HAS_OVERFLOW_H
endif

# for kernel version below 3.14, linux/proc_ns.h maybe not found
# https://github.com/torvalds/linux/commit/0bb80f240520c4148b623161e7856858c021696d
ifneq ($(wildcard $(srctree)/include/linux/proc_ns.h),)
$(info -- 7kimisu/compat: modern proc ns header file found)
ccflags-y += -DKSU_HAS_MODERN_PROC_NS
endif

# Android SPEC Changes
# https://android-review.googlesource.com/c/kernel/common/+/3009995
ifeq ($(shell grep -q "POLICYDB_CONFIG_ANDROID_NETLINK_ROUTE" $(srctree)/security/selinux/ss/policydb.h; echo $$?),0)
$(info -- 7kimisu/compat: android spec POLICYDB_CONFIG_ANDROID_NETLINK_ROUTE found!!)
ccflags-y += -DKSU_COMPAT_HAS_POLICYDB_CONFIG_ANDROID_NETLINK_ROUTE
endif

ifeq ($(shell grep -q "POLICYDB_CONFIG_ANDROID_NETLINK_GETNEIGH" $(srctree)/security/selinux/ss/policydb.h; echo $$?),0)
$(info -- 7kimisu/compat: android spec POLICYDB_CONFIG_ANDROID_NETLINK_GETNEIGH found!!)
ccflags-y += -DKSU_COMPAT_HAS_POLICYDB_CONFIG_ANDROID_NETLINK_GETNEIGH
endif

# https://github.com/torvalds/linux/commit/acdf52d97f824019888422842757013b37441dd1
ifneq ($(shell grep -q "flex_array" $(srctree)/security/selinux/ss/policydb.h; echo $$?),0)
$(info -- 7kimisu/compat: found modern selinux policydb)
ccflags-y += -DKSU_COMPAT_HAS_MODERN_POLICYDB
endif

ifeq ($(shell grep -q "struct sidtab .sidtab" $(srctree)/security/selinux/ss/services.h; echo $$?),0)
$(info -- 7kimisu/compat: found sidtab as reference)
ccflags-y += -DKSU_COMPAT_SIDTAB_AS_REFERENCE
endif

ifeq ($(shell grep -q "hlist_head" $(srctree)/include/linux/lsm_hooks.h 2>/dev/null; echo $$?),0)
$(info -- 7kimisu/compat: found hlist in security_hook_list)
ccflags-y += -DKSU_COMPAT_HLIST_FOR_SECURITY_HOOK_LIST
endif

ifeq ($(shell grep -F -q "int (*setprocattr)(const char *name, void *value, size_t size);" $(srctree)/include/linux/lsm_hooks.h 2>/dev/null; echo $$?),0)
$(info -- 7kimisu/compat: found new setprocattr prototype)
ccflags-y += -DKSU_COMPAT_SETPROCATTR_USE_NEW_PROTOTYPE
endif

ifeq ($(shell grep -F -q "char *lsm_names" $(srctree)/security/security.c; echo $$?),0)
$(info -- 7kimisu/compat: found required provide lsm name)
ccflags-y += -DKSU_COMPAT_REQUIRE_PROVIDE_LSM_NAME
endif

# https://github.com/torvalds/linux/commit/4b36cb773a8153417a080f8025d522322f915aea
ifeq ($(shell grep -q "struct mutex status_lock" $(srctree)/security/selinux/include/security.h; echo $$?),0)
$(info -- 7kimisu/compat: found selinux status variables in selinux_state)
ccflags-y += -DKSU_COMPAT_SELINUX_STATUS_VAR_IN_SELINUX_STATE
endif

ifeq ($(shell grep -q "struct selinux_policy" $(srctree)/security/selinux/ss/services.h; echo $$?),0)
$(info -- 7kimisu/compat: found selinux_policy struct)
ccflags-y += -DKSU_COMPAT_HAS_SELINUX_POLICY_STRUCT
endif

# https://github.com/torvalds/linux/commit/03414a49ad5f3c56988c36d2070e402ffa17feaf
ifeq ($(shell grep -q "struct hashtab table" $(srctree)/security/selinux/ss/symtab.h; echo $$?),0)
$(info -- 7kimisu/compat: found hashtabs is a struct instead of pointer)
ccflags-y += -DKSU_COMPAT_HAS_NON_POINTER_SYMTAB_STRUCT
endif

# https://github.com/torvalds/linux/commit/237389e3015e0f4ceac7cf00c70a59746150561d
ifeq ($(shell grep -q "symtab_search" $(srctree)/security/selinux/ss/symtab.h; echo $$?),0)
$(info -- 7kimisu/compat: found symtab_search function)
ccflags-y += -DKSU_COMPAT_HAS_SYMTAB_SEARCH
endif

# https://github.com/torvalds/linux/commit/24def7bb92c19337cee26d506f87dc4eeeba7a19
ifeq ($(shell grep -q "hashtab_key_params" $(srctree)/security/selinux/ss/hashtab.h; echo $$?),0)
$(info -- 7kimisu/compat: found hashtab_key_params function)
ccflags-y += -DKSU_COMPAT_HAS_HASHTAB_KEY_PARAMS
endif

# https://github.com/torvalds/linux/commit/c3a276111ea2572399281988b3129683e2a6b60b
ifeq ($(shell grep -q "filename_trans_key" $(srctree)/security/selinux/ss/policydb.h; echo $$?),0)
$(info -- 7kimisu/compat: found filename_trans_key function)
ccflags-y += -DKSU_COMPAT_HAS_FILENAME_TRANS_KEY
endif

# https://github.com/torvalds/linux/commit/e20b043a6902ecb61c2c84355c3bae5149f391db
# https://github.com/torvalds/linux/commit/b1d9e6b0646d0e5ee5d9050bd236b6c65d66faef
ifeq ($(shell grep -q "security_add_hooks" $(srctree)/include/linux/lsm_hooks.h 2>/dev/null; echo $$?),0)
$(info -- 7kimisu/compat: found security_add_hooks)
ccflags-y += -DKSU_COMPAT_HAS_LIST_OF_LSM_HOOKS
endif

# for HUAWEI kernel
# huawei rename type_attr_map_arry -> type_attr_map
# https://github.com/xixiaobei-bei/Huawei_MHA_EMUI9.0_ReSukiSU/blob/master/security/selinux/ss/policydb.h#L293
ifneq ($(shell grep -q "type_attr_map_array" $(srctree)/security/selinux/ss/policydb.h; echo $$?),0)
$(info -- 7kimisu/compat: type_attr_map_array not found)
ccflags-y += -DKSU_COMPAT_TYPE_ATTR_MAP_ARRAY_NOT_FOUND
endif

# for HUAWEI kernel
# huawei removed sym_name func
# https://github.com/xixiaobei-bei/Huawei_MHA_EMUI9.0_ReSukiSU/blob/master/security/selinux/ss/policydb.h
ifneq ($(shell grep -q "sym_name" $(srctree)/security/selinux/ss/policydb.h; echo $$?),0)
$(info -- 7kimisu/compat: sym_name not found)
ccflags-y += -DKSU_COMPAT_SYM_NAME_NOT_FOUND
endif

# for kernel version below 3.8, include/uapi/linux/module.h maybe not found
# https://github.com/torvalds/linux/commit/2f3238aebedb243804f58d62d57244edec4149b2
ifneq ($(wildcard $(srctree)/uapi/include/linux/module.h),)
$(info -- 7kimisu/compat: module.h found)
ccflags-y += -DKSU_COMPAT_HAS_UAPI_MODULE_H
endif

# optional hook
ifneq ($(shell grep -q "ksu_handle_post_execve" $(srctree)/fs/exec.c; echo $$?),0)
$(info -- 7kimisu/compat: ksu_handle_post_execve hook not found)
ccflags-y += -DKSU_COMPAT_NO_POST_EXECVE_HOOK
endif

# https://github.com/torvalds/linux/commit/a721f7b8c3548e943e514a957f2a37f4763b9888
ifeq ($(shell grep -q -F "void security_bprm_committed_creds(const struct linux_binprm *bprm)" $(srctree)/security/security.c; echo $$?),0)
$(info -- 7kimisu/compat: constify bprm parameter in security_bprm_committed_creds found)
ccflags-y += -DKSU_COMPAT_CONSTIFY_BPRM_PARAMETER_IN_SECURITY_BPRM_COMMITTED_CREDS
endif

# https://github.com/torvalds/linux/commit/8c0637e950d68933a67f7438f779d79b049b5e5c
ifeq ($(shell grep -q -F "key_need_perm" $(srctree)/include/linux/key.h; echo $$?),0)
$(info -- 7kimisu/compat: key need perm as enum found)
ccflags-y += -DKSU_COMPAT_KEY_NEED_PERM_AS_ENUM
endif

# https://github.com/torvalds/linux/commit/765927b2d508712d320c8934db963bbe14c3fcec
ifeq ($(shell grep -q "struct file .dentry_open.const struct path .path, int flags," $(srctree)/fs/open.c; echo $$?),0)
$(info -- 7kimisu/compat: modern dentry_open found)
ccflags-y += -DKSU_COMPAT_HAS_MODERN_DENTRY_OPEN
endif
KCEOF
cat > selinux/sepolicy.h <<'KCEOF'
#ifndef __KSU_H_SEPOLICY
#define __KSU_H_SEPOLICY

#include <linux/types.h>

#include "ss/policydb.h"

int ksu_dup_policydb(struct policydb *old_db, struct policydb *new_db);
void ksu_destroy_policydb(struct policydb *db);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) || defined(KSU_COMPAT_HAS_POLICY_MUTEX)
struct selinux_policy *ksu_dup_sepolicy(struct selinux_policy *old_pol);

void ksu_destroy_sepolicy(struct selinux_policy *orig);
#endif

// Operation on types
bool ksu_type(struct policydb *db, const char *name, const char *attr);
bool ksu_attribute(struct policydb *db, const char *name);
bool ksu_permissive(struct policydb *db, const char *type);
bool ksu_enforce(struct policydb *db, const char *type);
bool ksu_typeattribute(struct policydb *db, const char *type, const char *attr);
bool ksu_exists(struct policydb *db, const char *type);

// Access vector rules
bool ksu_allow(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *perm);
bool ksu_deny(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *perm);
bool ksu_auditallow(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *perm);
bool ksu_dontaudit(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *perm);

// Extended permissions access vector rules
bool ksu_allowxperm(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *range);
bool ksu_auditallowxperm(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *range);
bool ksu_dontauditxperm(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *range);

// Type rules
bool ksu_type_transition(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *def,
                         const char *obj);
bool ksu_type_change(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *def);
bool ksu_type_member(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *def);

// File system labeling
bool ksu_genfscon(struct policydb *db, const char *fs_name, const char *path, const char *ctx);

#endif
KCEOF
cat > selinux/sepolicy.c <<'KCEOF'
#include <linux/gfp.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/mutex.h>

#include "ss/constraint.h"
#include "ss/ebitmap.h"
#include "ss/hashtab.h"
#include "ss/policydb.h"
#include "ss/services.h"

#include "selinux.h"
#include "sepolicy.h"
#include "klog.h" // IWYU pragma: keep
#include "ss/symtab.h"
#include "compat/kernel_compat.h" // Add check Huawei Device

#define KSU_SUPPORT_ADD_TYPE

//////////////////////////////////////////////////////
// Declaration
//////////////////////////////////////////////////////

static struct avtab_node *get_avtab_node(struct policydb *db, struct avtab_key *key,
                                         struct avtab_extended_perms *xperms);

static bool is_redundant_avtab_node(struct avtab_node *node);

static bool remove_avtab_node(struct policydb *db, struct avtab_node *node);

static bool add_rule(struct policydb *db, const char *s, const char *t, const char *c, const char *p, int effect,
                     bool invert);

static bool add_rule_raw(struct policydb *db, struct type_datum *src, struct type_datum *tgt, struct class_datum *cls,
                         struct perm_datum *perm, int effect, bool invert);

static void add_xperm_rule_raw(struct policydb *db, struct type_datum *src, struct type_datum *tgt,
                               struct class_datum *cls, uint16_t low, uint16_t high, int effect, bool invert);
static bool add_xperm_rule(struct policydb *db, const char *s, const char *t, const char *c, const char *range,
                           int effect, bool invert);

static bool add_type_rule(struct policydb *db, const char *s, const char *t, const char *c, const char *d, int effect);

static bool add_filename_trans(struct policydb *db, const char *s, const char *t, const char *c, const char *d,
                               const char *o);

static bool add_genfscon(struct policydb *db, const char *fs_name, const char *path, const char *context);

static bool add_type(struct policydb *db, const char *type_name, bool attr);

static bool set_type_state(struct policydb *db, const char *type_name, bool permissive);

static void add_typeattribute_raw(struct policydb *db, struct type_datum *type, struct type_datum *attr);

static bool add_typeattribute(struct policydb *db, const char *type, const char *attr);

//////////////////////////////////////////////////////
// Implementation
//////////////////////////////////////////////////////

// Invert is adding rules for auditdeny; in other cases, invert is removing
// rules
#define strip_av(effect, invert) ((effect == AVTAB_AUDITDENY) == !invert)

#define ksu_hash_for_each(node_ptr, n_slot, cur)                                                                       \
    int i;                                                                                                             \
    for (i = 0; i < n_slot; ++i)                                                                                       \
        for (cur = node_ptr[i]; cur; cur = cur->next)

// htable is a struct instead of pointer above 5.8.0:
// https://elixir.bootlin.com/linux/v5.8-rc1/source/security/selinux/ss/symtab.h
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0) || defined(KSU_COMPAT_HAS_NON_POINTER_SYMTAB_STRUCT)
#define ksu_hashtab_for_each(htab, cur) ksu_hash_for_each(htab.htable, htab.size, cur)
#else
#define ksu_hashtab_for_each(htab, cur) ksu_hash_for_each(htab->htable, htab->size, cur)
#endif

// symtab_search is introduced on 5.9.0:
// https://elixir.bootlin.com/linux/v5.9-rc1/source/security/selinux/ss/symtab.h
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0) && !defined(KSU_COMPAT_HAS_SYMTAB_SEARCH)
#define symtab_search(s, name) hashtab_search((s)->table, name)
#define symtab_insert(s, name, datum) hashtab_insert((s)->table, name, datum)
#endif

#define avtab_for_each(avtab, cur) ksu_hash_for_each(avtab.htable, avtab.nslot, cur)

static struct avtab_node *get_avtab_node(struct policydb *db, struct avtab_key *key,
                                         struct avtab_extended_perms *xperms)
{
    struct avtab_node *node;

    /* AVTAB_XPERMS entries are not necessarily unique */
    if (key->specified & AVTAB_XPERMS) {
        bool match = false;
        node = avtab_search_node(&db->te_avtab, key);
        while (node) {
            if ((node->datum.u.xperms->specified == xperms->specified) &&
                (node->datum.u.xperms->driver == xperms->driver)) {
                match = true;
                break;
            }
            node = avtab_search_node_next(node, key->specified);
        }
        if (!match)
            node = NULL;
    } else {
        node = avtab_search_node(&db->te_avtab, key);
    }

    if (!node) {
        struct avtab_datum avdatum = {};
        /*
	 * AUDITDENY, aka DONTAUDIT, are &= assigned, versus |= for
	 * others. Initialize the data accordingly.
	 */
        if (key->specified & AVTAB_XPERMS) {
            avdatum.u.xperms = xperms;
        } else {
            avdatum.u.data = key->specified == AVTAB_AUDITDENY ? ~0U : 0U;
        }
        /* this is used to get the node - insertion is actually unique */
        node = avtab_insert_nonunique(&db->te_avtab, key, &avdatum);
        if (!node)
            return NULL;

        // extra size: add_type() can grow policy without updating db->len
        int grow_size = sizeof(struct avtab_key);
        grow_size += sizeof(struct avtab_datum);
        if (key->specified & AVTAB_XPERMS) {
            grow_size += sizeof(avdatum.u.xperms->specified) + sizeof(avdatum.u.xperms->driver) +
                         sizeof(avdatum.u.xperms->perms.p);
        }
        db->len += grow_size;
    }

    return node;
}

static bool is_redundant_avtab_node(struct avtab_node *node)
{
    if (node->key.specified & AVTAB_XPERMS)
        return node->datum.u.xperms == NULL;
    if (!(node->key.specified & AVTAB_AV))
        return false;
    if (node->key.specified & AVTAB_AUDITDENY)
        return node->datum.u.data == ~0U;
    return node->datum.u.data == 0U;
}

static bool remove_avtab_node(struct policydb *db, struct avtab_node *node)
{
    int i;
    int ret;
    // https://github.com/torvalds/linux/blob/v6.1/security/selinux/ss/avtab.c#L619
    int shrink_size = sizeof(node->key.source_type) + sizeof(node->key.target_type) + sizeof(node->key.target_class) +
                      sizeof(node->key.specified);
    struct avtab removed = {};
    struct avtab_node *n;
    struct avtab_node *prev;

    ret = avtab_alloc(&removed, 1);
    if (ret < 0)
        return false;

    for (i = 0; i < db->te_avtab.nslot; i++) {
        prev = NULL;
        // https://github.com/torvalds/linux/commit/acdf52d97f824019888422842757013b37441dd1   <- 5.1
        // https://github.com/torvalds/linux/commit/ba39db6e0519aa8362dbda6523ceb69349a18dc3   <- 4.1
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0) || LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0) ||                   \
    defined(KSU_COMPAT_HAS_MODERN_POLICYDB)
        for (n = db->te_avtab.htable[i]; n; prev = n, n = n->next) {
            if (n != node)
                continue;

            if (prev)
                prev->next = n->next;
            else
                db->te_avtab.htable[i] = n->next;

            if (db->te_avtab.nel > 0)
                db->te_avtab.nel--;

            if (n->key.specified & AVTAB_XPERMS)
                // specified and driver are u8, perms.p holds 8 u32s
                shrink_size += sizeof(n->datum.u.xperms->specified) + sizeof(n->datum.u.xperms->driver) +
                               sizeof(n->datum.u.xperms->perms.p);
            else
                // data is u32
                shrink_size += sizeof(n->datum.u.data);
            n->next = NULL;
            removed.htable[0] = n;
            removed.nel = 1;
            avtab_destroy(&removed);
            if (db->len >= shrink_size)
                db->len -= shrink_size;
            return true;
        }
#else
        for (n = flex_array_get_ptr(db->te_avtab.htable, i); n; prev = n, n = n->next) {
            if (n != node)
                continue;

            if (prev) {
                prev->next = n->next;
            } else {
                flex_array_put_ptr(db->te_avtab.htable, i, n->next, GFP_KERNEL | __GFP_ZERO);
            }

            if (db->te_avtab.nel > 0)
                db->te_avtab.nel--;

            if ((n->key.specified & AVTAB_XPERMS) && n->datum.u.xperms) {
                shrink_size += sizeof(u8) + sizeof(u8) + sizeof(u32) * ARRAY_SIZE(n->datum.u.xperms->perms.p);
            }
            n->next = NULL;

            flex_array_put_ptr(removed.htable, 0, n, GFP_KERNEL | __GFP_ZERO);

            removed.nel = 1;
            avtab_destroy(&removed);
            if (db->len >= shrink_size)
                db->len -= shrink_size;
            return true;
        }
#endif
    }

    avtab_destroy(&removed);
    return false;
}

static bool add_rule(struct policydb *db, const char *s, const char *t, const char *c, const char *p, int effect,
                     bool invert)
{
    struct type_datum *src = NULL, *tgt = NULL;
    struct class_datum *cls = NULL;
    struct perm_datum *perm = NULL;

    if (s) {
        src = symtab_search(&db->p_types, s);
        if (src == NULL) {
            pr_info("source type %s does not exist\n", s);
            return false;
        }
    }

    if (t) {
        tgt = symtab_search(&db->p_types, t);
        if (tgt == NULL) {
            pr_info("target type %s does not exist\n", t);
            return false;
        }
    }

    if (c) {
        cls = symtab_search(&db->p_classes, c);
        if (cls == NULL) {
            pr_info("class %s does not exist\n", c);
            return false;
        }
    }

    if (p) {
        if (c == NULL) {
            pr_info("No class is specified, cannot add perm [%s] \n", p);
            return false;
        }

        perm = symtab_search(&cls->permissions, p);
        if (perm == NULL && cls->comdatum != NULL) {
            perm = symtab_search(&cls->comdatum->permissions, p);
        }
        if (perm == NULL) {
            pr_info("perm %s does not exist in class %s\n", p, c);
            return false;
        }
    }
    return add_rule_raw(db, src, tgt, cls, perm, effect, invert);
}

static bool add_rule_raw(struct policydb *db, struct type_datum *src, struct type_datum *tgt, struct class_datum *cls,
                         struct perm_datum *perm, int effect, bool invert)
{
    bool success = true;

    if (src == NULL) {
        struct hashtab_node *node;
        if (strip_av(effect, invert)) {
            ksu_hashtab_for_each(db->p_types.table, node)
            {
                success &= add_rule_raw(db, (struct type_datum *)node->datum, tgt, cls, perm, effect, invert);
            };
        } else {
            ksu_hashtab_for_each(db->p_types.table, node)
            {
                struct type_datum *type = (struct type_datum *)(node->datum);
                if (type->attribute) {
                    success &= add_rule_raw(db, type, tgt, cls, perm, effect, invert);
                }
            };
        }
    } else if (tgt == NULL) {
        struct hashtab_node *node;
        if (strip_av(effect, invert)) {
            ksu_hashtab_for_each(db->p_types.table, node)
            {
                success &= add_rule_raw(db, src, (struct type_datum *)node->datum, cls, perm, effect, invert);
            };
        } else {
            ksu_hashtab_for_each(db->p_types.table, node)
            {
                struct type_datum *type = (struct type_datum *)(node->datum);
                if (type->attribute) {
                    success &= add_rule_raw(db, src, type, cls, perm, effect, invert);
                }
            };
        }
    } else if (cls == NULL) {
        struct hashtab_node *node;
        ksu_hashtab_for_each(db->p_classes.table, node)
        {
            success &= add_rule_raw(db, src, tgt, (struct class_datum *)node->datum, perm, effect, invert);
        }
    } else {
        struct avtab_key key;
        struct avtab_node *node;

        key.source_type = src->value;
        key.target_type = tgt->value;
        key.target_class = cls->value;
        key.specified = effect;

        if (invert && effect != AVTAB_AUDITDENY) {
            node = avtab_search_node(&db->te_avtab, &key);
            if (!node)
                return true;
        } else {
            node = get_avtab_node(db, &key, NULL);
            if (!node)
                return false;
        }

        if (invert) {
            if (perm)
                node->datum.u.data &= ~(1U << (perm->value - 1));
            else
                node->datum.u.data = 0U;
        } else {
            if (perm)
                node->datum.u.data |= 1U << (perm->value - 1);
            else
                node->datum.u.data = ~0U;
        }
        if (is_redundant_avtab_node(node))
            return remove_avtab_node(db, node);
    }

    return success;
}

#define ioctl_driver(x) (x >> 8 & 0xFF)
#define ioctl_func(x) (x & 0xFF)

#define xperm_test(x, p) (1 & (p[x >> 5] >> (x & 0x1f)))
#define xperm_set(x, p) (p[x >> 5] |= (1 << (x & 0x1f)))
#define xperm_clear(x, p) (p[x >> 5] &= ~(1 << (x & 0x1f)))

static void add_xperm_rule_raw(struct policydb *db, struct type_datum *src, struct type_datum *tgt,
                               struct class_datum *cls, uint16_t low, uint16_t high, int effect, bool invert)
{
    if (src == NULL) {
        struct hashtab_node *node;
        ksu_hashtab_for_each(db->p_types.table, node)
        {
            struct type_datum *type = (struct type_datum *)(node->datum);
            if (type->attribute) {
                add_xperm_rule_raw(db, type, tgt, cls, low, high, effect, invert);
            }
        };
    } else if (tgt == NULL) {
        struct hashtab_node *node;
        ksu_hashtab_for_each(db->p_types.table, node)
        {
            struct type_datum *type = (struct type_datum *)(node->datum);
            if (type->attribute) {
                add_xperm_rule_raw(db, src, type, cls, low, high, effect, invert);
            }
        };
    } else if (cls == NULL) {
        struct hashtab_node *node;
        ksu_hashtab_for_each(db->p_classes.table, node)
        {
            add_xperm_rule_raw(db, src, tgt, (struct class_datum *)(node->datum), low, high, effect, invert);
        };
    } else {
        struct avtab_key key;
        key.source_type = src->value;
        key.target_type = tgt->value;
        key.target_class = cls->value;
        key.specified = effect;

        struct avtab_datum *datum;
        struct avtab_node *node;
        struct avtab_extended_perms xperms;

        memset(&xperms, 0, sizeof(xperms));
        if (ioctl_driver(low) != ioctl_driver(high)) {
            xperms.specified = AVTAB_XPERMS_IOCTLDRIVER;
            xperms.driver = 0;
        } else {
            xperms.specified = AVTAB_XPERMS_IOCTLFUNCTION;
            xperms.driver = ioctl_driver(low);
        }
        int i;
        if (xperms.specified == AVTAB_XPERMS_IOCTLDRIVER) {
            for (i = ioctl_driver(low); i <= ioctl_driver(high); ++i) {
                if (invert)
                    xperm_clear(i, xperms.perms.p);
                else
                    xperm_set(i, xperms.perms.p);
            }
        } else {
            for (i = ioctl_func(low); i <= ioctl_func(high); ++i) {
                if (invert)
                    xperm_clear(i, xperms.perms.p);
                else
                    xperm_set(i, xperms.perms.p);
            }
        }

        node = get_avtab_node(db, &key, &xperms);
        if (!node) {
            pr_warn("add_xperm_rule_raw cannot found node!\n");
            return;
        }
        datum = &node->datum;

        // Allow updating permission bits of existing xperms
        for (i = 0; i < ARRAY_SIZE(xperms.perms.p); i++)
            datum->u.xperms->perms.p[i] |= xperms.perms.p[i];
    }
}

static bool add_xperm_rule(struct policydb *db, const char *s, const char *t, const char *c, const char *range,
                           int effect, bool invert)
{
    struct type_datum *src = NULL, *tgt = NULL;
    struct class_datum *cls = NULL;

    if (s) {
        src = symtab_search(&db->p_types, s);
        if (src == NULL) {
            pr_info("source type %s does not exist\n", s);
            return false;
        }
    }

    if (t) {
        tgt = symtab_search(&db->p_types, t);
        if (tgt == NULL) {
            pr_info("target type %s does not exist\n", t);
            return false;
        }
    }

    if (c) {
        cls = symtab_search(&db->p_classes, c);
        if (cls == NULL) {
            pr_info("class %s does not exist\n", c);
            return false;
        }
    }

    u16 low, high;

    if (range) {
        if (strchr(range, '-')) {
            sscanf(range, "%hx-%hx", &low, &high);
        } else {
            sscanf(range, "%hx", &low);
            high = low;
        }
    } else {
        low = 0;
        high = 0xFFFF;
    }

    add_xperm_rule_raw(db, src, tgt, cls, low, high, effect, invert);
    return true;
}

static bool add_type_rule(struct policydb *db, const char *s, const char *t, const char *c, const char *d, int effect)
{
    struct type_datum *src, *tgt, *def;
    struct class_datum *cls;

    src = symtab_search(&db->p_types, s);
    if (src == NULL) {
        pr_info("source type %s does not exist\n", s);
        return false;
    }
    tgt = symtab_search(&db->p_types, t);
    if (tgt == NULL) {
        pr_info("target type %s does not exist\n", t);
        return false;
    }
    cls = symtab_search(&db->p_classes, c);
    if (cls == NULL) {
        pr_info("class %s does not exist\n", c);
        return false;
    }
    def = symtab_search(&db->p_types, d);
    if (def == NULL) {
        pr_info("default type %s does not exist\n", d);
        return false;
    }

    struct avtab_key key;
    key.source_type = src->value;
    key.target_type = tgt->value;
    key.target_class = cls->value;
    key.specified = effect;

    struct avtab_node *node = get_avtab_node(db, &key, NULL);
    if (!node)
        return false;
    node->datum.u.data = def->value;

    return true;
}

// 5.9.0 : static inline int hashtab_insert(struct hashtab *h, void *key, void
// *datum, struct hashtab_key_params key_params) 5.8.0: int
// hashtab_insert(struct hashtab *h, void *k, void *d);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0) || defined(KSU_COMPAT_HAS_HASHTAB_KEY_PARAMS)
static u32 filenametr_hash(const void *k)
{
    const struct filename_trans_key *ft = k;
    unsigned long hash;
    unsigned int byte_num;
    unsigned char focus;

    hash = ft->ttype ^ ft->tclass;

    byte_num = 0;
    while ((focus = ft->name[byte_num++]))
        hash = partial_name_hash(focus, hash);
    return hash;
}

static int filenametr_cmp(const void *k1, const void *k2)
{
    const struct filename_trans_key *ft1 = k1;
    const struct filename_trans_key *ft2 = k2;
    int v;

    v = ft1->ttype - ft2->ttype;
    if (v)
        return v;

    v = ft1->tclass - ft2->tclass;
    if (v)
        return v;

    return strcmp(ft1->name, ft2->name);
}

static const struct hashtab_key_params filenametr_key_params = {
    .hash = filenametr_hash,
    .cmp = filenametr_cmp,
};
#endif

static bool add_filename_trans(struct policydb *db, const char *s, const char *t, const char *c, const char *d,
                               const char *o)
{
    struct type_datum *src, *tgt, *def;
    struct class_datum *cls;

    src = symtab_search(&db->p_types, s);
    if (src == NULL) {
        pr_warn("source type %s does not exist\n", s);
        return false;
    }
    tgt = symtab_search(&db->p_types, t);
    if (tgt == NULL) {
        pr_warn("target type %s does not exist\n", t);
        return false;
    }
    cls = symtab_search(&db->p_classes, c);
    if (cls == NULL) {
        pr_warn("class %s does not exist\n", c);
        return false;
    }
    def = symtab_search(&db->p_types, d);
    if (def == NULL) {
        pr_warn("default type %s does not exist\n", d);
        return false;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0) || defined(KSU_COMPAT_HAS_FILENAME_TRANS_KEY)
    struct filename_trans_key key;
    key.ttype = tgt->value;
    key.tclass = cls->value;
    key.name = (char *)o;

    struct filename_trans_datum *last = NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0) || defined(KSU_COMPAT_HAS_HASHTAB_KEY_PARAMS)
    struct filename_trans_datum *trans = policydb_filenametr_search(db, &key);
#else
    struct filename_trans_datum *trans = hashtab_search(&db->filename_trans, &key);
#endif
    while (trans) {
        if (ebitmap_get_bit(&trans->stypes, src->value - 1)) {
            // Duplicate, overwrite existing data and return
            trans->otype = def->value;
            return true;
        }
        if (trans->otype == def->value)
            break;
        last = trans;
        trans = trans->next;
    }

    if (trans == NULL) {
        trans = (struct filename_trans_datum *)kcalloc(1, sizeof(*trans), GFP_KERNEL);
        if (!trans) {
            pr_err("add_filename_trans: Failed to alloc datum\n");
            return false;
        }
        struct filename_trans_key *new_key = (struct filename_trans_key *)kzalloc(sizeof(*new_key), GFP_KERNEL);
        if (!new_key) {
            pr_err("add_filename_trans: Failed to alloc new_key\n");
            kfree(trans);
            return false;
        }
        *new_key = key;
        new_key->name = kstrdup(key.name, GFP_KERNEL);
        if (!new_key->name) {
            pr_err("add_filename_trans: Failed to dup name\n");
            kfree(new_key);
            kfree(trans);
            return false;
        }
        trans->next = last;
        trans->otype = def->value;
        hashtab_insert(&db->filename_trans, new_key, trans, filenametr_key_params);
    }

    db->compat_filename_trans_count++;
    return ebitmap_set_bit(&trans->stypes, src->value - 1, 1) == 0;
#else // < 5.7.0, has no filename_trans_key, but struct filename_trans

    struct filename_trans key;
    key.ttype = tgt->value;
    key.tclass = cls->value;
    key.name = (char *)o;

    struct filename_trans_datum *trans = hashtab_search(db->filename_trans, &key);

    if (trans == NULL) {
        trans = (struct filename_trans_datum *)kcalloc(sizeof(*trans), 1, GFP_KERNEL);
        if (!trans) {
            pr_err("add_filename_trans: Failed to alloc datum\n");
            return false;
        }
        struct filename_trans *new_key = (struct filename_trans *)kzalloc(sizeof(*new_key), GFP_KERNEL);
        if (!new_key) {
            pr_err("add_filename_trans: Failed to alloc new_key\n");
            return false;
        }
        *new_key = key;
        new_key->name = kstrdup(key.name, GFP_KERNEL);
        trans->otype = def->value;
        hashtab_insert(db->filename_trans, new_key, trans);
    }

    return ebitmap_set_bit(&db->filename_trans_ttypes, src->value - 1, 1) == 0;
#endif
}

static bool add_genfscon(struct policydb *db, const char *fs_name, const char *path, const char *context)
{
    return false;
}

// https://github.com/torvalds/linux/commit/590b9d576caec6b4c46bba49ed36223a399c3fc5#diff-cc9aa90e094e6e0f47bd7300db4f33cf4366b98b55d8753744f31eb69c691016R844-R845
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#define ksu_kvrealloc(p, new_size, _old_size) kvrealloc(p, new_size, GFP_KERNEL)
#else
#define ksu_kvrealloc(p, new_size, old_size) ksu_compat_kvrealloc(p, old_size, new_size, GFP_KERNEL)
#endif

static bool add_type(struct policydb *db, const char *type_name, bool attr)
{
#ifdef KSU_SUPPORT_ADD_TYPE
    struct type_datum *type = symtab_search(&db->p_types, type_name);
    if (type) {
        pr_warn("Type %s already exists\n", type_name);
        return true;
    }

    u32 value = ++db->p_types.nprim;
    type = (struct type_datum *)kzalloc(sizeof(struct type_datum), GFP_KERNEL);
    if (!type) {
        pr_err("add_type: alloc type_datum failed.\n");
        return false;
    }

    type->primary = 1;
    type->value = value;
    type->attribute = attr;

    char *key = kstrdup(type_name, GFP_KERNEL);
    if (!key) {
        pr_err("add_type: alloc key failed.\n");
        return false;
    }

    if (symtab_insert(&db->p_types, key, type)) {
        pr_err("add_type: insert symtab failed.\n");
        return false;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0) ||                                                                   \
    (defined(KSU_COMPAT_HAS_MODERN_POLICYDB) && !defined(KSU_COMPAT_TYPE_ATTR_MAP_ARRAY_NOT_FOUND))
    struct ebitmap *new_type_attr_map_array =
        ksu_kvrealloc(db->type_attr_map_array, value * sizeof(struct ebitmap), (value - 1) * sizeof(struct ebitmap));

    if (!new_type_attr_map_array) {
        pr_err("add_type: alloc type_attr_map_array failed\n");
        return false;
    }

    struct type_datum **new_type_val_to_struct = ksu_kvrealloc(
        db->type_val_to_struct, sizeof(*db->type_val_to_struct) * value, sizeof(*db->type_val_to_struct) * (value - 1));

    if (!new_type_val_to_struct) {
        pr_err("add_type: alloc type_val_to_struct failed\n");
        return false;
    }

    char **new_val_to_name_types =
        ksu_kvrealloc(db->sym_val_to_name[SYM_TYPES], sizeof(char *) * value, sizeof(char *) * (value - 1));
    if (!new_val_to_name_types) {
        pr_err("add_type: alloc val_to_name failed\n");
        return false;
    }

    db->type_attr_map_array = new_type_attr_map_array;
    ebitmap_init(&db->type_attr_map_array[value - 1]);
    ebitmap_set_bit(&db->type_attr_map_array[value - 1], value - 1, 1);

    db->type_val_to_struct = new_type_val_to_struct;
    db->type_val_to_struct[value - 1] = type;

    db->sym_val_to_name[SYM_TYPES] = new_val_to_name_types;
    db->sym_val_to_name[SYM_TYPES][value - 1] = key;

    int i;
    for (i = 0; i < db->p_roles.nprim; ++i) {
        ebitmap_set_bit(&db->role_val_to_struct[i]->types, value - 1, 1);
    }

    return true;

    // safe? because only huawei do this fucking things
#elif defined(KSU_COMPAT_TYPE_ATTR_MAP_ARRAY_NOT_FOUND)
    /*
   * Huawei use type_attr_map and type_val_to_struct.
   * And use ebitmap not flex_array.
   */
    size_t new_size = sizeof(struct ebitmap) * db->p_types.nprim;
    struct ebitmap *new_type_attr_map = (krealloc(db->type_attr_map, new_size, GFP_KERNEL));

    struct type_datum **new_type_val_to_struct =
        krealloc(db->type_val_to_struct, sizeof(*db->type_val_to_struct) * db->p_types.nprim, GFP_KERNEL);

    if (!new_type_attr_map) {
        pr_err("add_type: alloc type_attr_map failed\n");
        return false;
    }

    if (!new_type_val_to_struct) {
        pr_err("add_type: alloc type_val_to_struct failed\n");
        return false;
    }

    char **new_val_to_name_types =
        krealloc(db->sym_val_to_name[SYM_TYPES], sizeof(char *) * db->symtab[SYM_TYPES].nprim, GFP_KERNEL);
    if (!new_val_to_name_types) {
        pr_err("add_type: alloc val_to_name failed\n");
        return false;
    }

    db->type_attr_map = new_type_attr_map;
#ifdef HISI_SELINUX_EBITMAP_RO
    ebitmap_init(&db->type_attr_map[value - 1], HISI_SELINUX_EBITMAP_RO);
#else
    ebitmap_init(&db->type_attr_map[value - 1], HKIP_SELINUX_EBITMAP_RO);
#endif
    ebitmap_set_bit(&db->type_attr_map[value - 1], value - 1, 1);

    db->type_val_to_struct = new_type_val_to_struct;
    db->type_val_to_struct[value - 1] = type;

    db->sym_val_to_name[SYM_TYPES] = new_val_to_name_types;
    db->sym_val_to_name[SYM_TYPES][value - 1] = key;

    int i;
    for (i = 0; i < db->p_roles.nprim; ++i) {
        ebitmap_set_bit(&db->role_val_to_struct[i]->types, value - 1, 1);
    }

    return true;
#else
    // flex_array is not extensible, we need to create a new bigger one instead
    struct flex_array *new_type_attr_map_array =
        flex_array_alloc(sizeof(struct ebitmap), db->p_types.nprim, GFP_KERNEL | __GFP_ZERO);

    struct flex_array *new_type_val_to_struct =
        flex_array_alloc(sizeof(struct type_datum *), db->p_types.nprim, GFP_KERNEL | __GFP_ZERO);

    struct flex_array *new_val_to_name_types =
        flex_array_alloc(sizeof(char *), db->symtab[SYM_TYPES].nprim, GFP_KERNEL | __GFP_ZERO);

    if (!new_type_attr_map_array) {
        pr_err("add_type: alloc type_attr_map_array failed\n");
        return false;
    }

    if (!new_type_val_to_struct) {
        pr_err("add_type: alloc type_val_to_struct failed\n");
        return false;
    }

    if (!new_val_to_name_types) {
        pr_err("add_type: alloc val_to_name failed\n");
        return false;
    }

    // preallocate so we don't have to worry about the put ever failing
    if (flex_array_prealloc(new_type_attr_map_array, 0, db->p_types.nprim, GFP_KERNEL | __GFP_ZERO)) {
        pr_err("add_type: prealloc type_attr_map_array failed\n");
        return false;
    }

    if (flex_array_prealloc(new_type_val_to_struct, 0, db->p_types.nprim, GFP_KERNEL | __GFP_ZERO)) {
        pr_err("add_type: prealloc type_val_to_struct_array failed\n");
        return false;
    }

    if (flex_array_prealloc(new_val_to_name_types, 0, db->symtab[SYM_TYPES].nprim, GFP_KERNEL | __GFP_ZERO)) {
        pr_err("add_type: prealloc val_to_name_types failed\n");
        return false;
    }

    int j;
    void *old_elem;
    // copy the old data or pointers to new flex arrays
    for (j = 0; j < db->type_attr_map_array->total_nr_elements; j++) {
        old_elem = flex_array_get(db->type_attr_map_array, j);
        if (old_elem)
            flex_array_put(new_type_attr_map_array, j, old_elem, GFP_KERNEL | __GFP_ZERO);
    }

    for (j = 0; j < db->type_val_to_struct_array->total_nr_elements; j++) {
        old_elem = flex_array_get_ptr(db->type_val_to_struct_array, j);
        if (old_elem)
            flex_array_put_ptr(new_type_val_to_struct, j, old_elem, GFP_KERNEL | __GFP_ZERO);
    }

    for (j = 0; j < db->symtab[SYM_TYPES].nprim; j++) {
        old_elem = flex_array_get_ptr(db->sym_val_to_name[SYM_TYPES], j);
        if (old_elem)
            flex_array_put_ptr(new_val_to_name_types, j, old_elem, GFP_KERNEL | __GFP_ZERO);
    }

    // store the pointer of old flex arrays first, when assigning new ones we
    // should free it
    struct flex_array *old_fa;

    old_fa = db->type_attr_map_array;
    db->type_attr_map_array = new_type_attr_map_array;
    if (old_fa) {
        flex_array_free(old_fa);
    }

// Huawei's EMUI 10+ / HM2 HKIP is closed, use the original flex_array_get and HISI_SELINUX_EBITMAP_RO(false)
#if defined(KSU_COMPAT_IS_HISI_LEGACY_HM2)
    ebitmap_init(flex_array_get(db->type_attr_map_array, value - 1), HISI_SELINUX_EBITMAP_RO);
#else
    ebitmap_init(flex_array_get(db->type_attr_map_array, value - 1));
#endif
    ebitmap_set_bit(flex_array_get(db->type_attr_map_array, value - 1), value - 1, 1);

    old_fa = db->type_val_to_struct_array;
    db->type_val_to_struct_array = new_type_val_to_struct;
    if (old_fa) {
        flex_array_free(old_fa);
    }
    flex_array_put_ptr(db->type_val_to_struct_array, value - 1, type, GFP_KERNEL | __GFP_ZERO);

    old_fa = db->sym_val_to_name[SYM_TYPES];
    db->sym_val_to_name[SYM_TYPES] = new_val_to_name_types;
    if (old_fa) {
        flex_array_free(old_fa);
    }
    flex_array_put_ptr(db->sym_val_to_name[SYM_TYPES], value - 1, key, GFP_KERNEL | __GFP_ZERO);

    int i;
    for (i = 0; i < db->p_roles.nprim; ++i) {
        ebitmap_set_bit(&db->role_val_to_struct[i]->types, value - 1, 1);
    }
    return true;
#endif

#else
    return false;
#endif
}

static bool set_type_state(struct policydb *db, const char *type_name, bool permissive)
{
    struct type_datum *type;
    if (type_name == NULL) {
        struct hashtab_node *node;
        ksu_hashtab_for_each(db->p_types.table, node)
        {
            type = (struct type_datum *)(node->datum);
            if (ebitmap_set_bit(&db->permissive_map, type->value, permissive))
                pr_info("Could not set bit in permissive map\n");
        };
    } else {
        type = (struct type_datum *)symtab_search(&db->p_types, type_name);
        if (type == NULL) {
            pr_info("type %s does not exist\n", type_name);
            return false;
        }
        if (ebitmap_set_bit(&db->permissive_map, type->value, permissive)) {
            pr_info("Could not set bit in permissive map\n");
            return false;
        }
    }
    return true;
}

static void add_typeattribute_raw(struct policydb *db, struct type_datum *type, struct type_datum *attr)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0) ||                                                                   \
    (defined(KSU_COMPAT_HAS_MODERN_POLICYDB) && !defined(KSU_COMPAT_TYPE_ATTR_MAP_ARRAY_NOT_FOUND))
    struct ebitmap *sattr = &db->type_attr_map_array[type->value - 1];
#elif defined(KSU_COMPAT_TYPE_ATTR_MAP_ARRAY_NOT_FOUND)
    /*
    *  HISI_SELINUX_EBITMAP_RO is Huawei's unique features.
    *  HKIP_SELINUX_EBITMAP_RO is Honor's rename
    */
#ifdef HISI_SELINUX_EBITMAP_RO
    struct ebitmap *sattr = &db->type_attr_map[type->value - 1], HISI_SELINUX_EBITMAP_RO;
#else
    struct ebitmap *sattr = &db->type_attr_map[type->value - 1], HKIP_SELINUX_EBITMAP_RO;
#endif // #ifndef HISI_SELINUX_EBITMAP_RO

#elif defined(KSU_COMPAT_IS_HISI_LEGACY_HM2)
    /* EMUI 10+ / HM2 dedicated branch (HKIP is closed, use the original flex_array_get) */
    struct ebitmap *sattr = flex_array_get(db->type_attr_map_array, type->value - 1);
#else
    struct ebitmap *sattr = flex_array_get(db->type_attr_map_array, type->value - 1);
#endif
    ebitmap_set_bit(sattr, attr->value - 1, 1);

    struct hashtab_node *node;
    struct constraint_node *n;
    struct constraint_expr *e;
    ksu_hashtab_for_each(db->p_classes.table, node)
    {
        struct class_datum *cls = (struct class_datum *)(node->datum);
        for (n = cls->constraints; n; n = n->next) {
            for (e = n->expr; e; e = e->next) {
                if (e->expr_type == CEXPR_NAMES && ebitmap_get_bit(&e->type_names->types, attr->value - 1)) {
                    ebitmap_set_bit(&e->names, type->value - 1, 1);
                }
            }
        }
    };
}

static bool add_typeattribute(struct policydb *db, const char *type, const char *attr)
{
    struct type_datum *type_d = symtab_search(&db->p_types, type);
    if (type_d == NULL) {
        pr_info("type %s does not exist\n", type);
        return false;
    } else if (type_d->attribute) {
        pr_info("type %s is an attribute\n", attr);
        return false;
    }

    struct type_datum *attr_d = symtab_search(&db->p_types, attr);
    if (attr_d == NULL) {
        pr_info("attribute %s does not exist\n", type);
        return false;
    } else if (!attr_d->attribute) {
        pr_info("type %s is not an attribute \n", attr);
        return false;
    }

    add_typeattribute_raw(db, type_d, attr_d);
    return true;
}

//////////////////////////////////////////////////////////////////////////

// Operation on types
bool ksu_type(struct policydb *db, const char *name, const char *attr)
{
    return add_type(db, name, false) && add_typeattribute(db, name, attr);
}

bool ksu_attribute(struct policydb *db, const char *name)
{
    return add_type(db, name, true);
}

bool ksu_permissive(struct policydb *db, const char *type)
{
    return set_type_state(db, type, true);
}

bool ksu_enforce(struct policydb *db, const char *type)
{
    return set_type_state(db, type, false);
}

bool ksu_typeattribute(struct policydb *db, const char *type, const char *attr)
{
    return add_typeattribute(db, type, attr);
}

bool ksu_exists(struct policydb *db, const char *type)
{
    return symtab_search(&db->p_types, type) != NULL;
}

// Access vector rules
bool ksu_allow(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *perm)
{
    return add_rule(db, src, tgt, cls, perm, AVTAB_ALLOWED, false);
}

bool ksu_deny(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *perm)
{
    return add_rule(db, src, tgt, cls, perm, AVTAB_ALLOWED, true);
}

bool ksu_auditallow(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *perm)
{
    return add_rule(db, src, tgt, cls, perm, AVTAB_AUDITALLOW, false);
}
bool ksu_dontaudit(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *perm)
{
    return add_rule(db, src, tgt, cls, perm, AVTAB_AUDITDENY, true);
}

// Extended permissions access vector rules
bool ksu_allowxperm(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *range)
{
    return add_xperm_rule(db, src, tgt, cls, range, AVTAB_XPERMS_ALLOWED, false);
}

bool ksu_auditallowxperm(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *range)
{
    return add_xperm_rule(db, src, tgt, cls, range, AVTAB_XPERMS_AUDITALLOW, false);
}

bool ksu_dontauditxperm(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *range)
{
    return add_xperm_rule(db, src, tgt, cls, range, AVTAB_XPERMS_DONTAUDIT, false);
}

// Type rules
bool ksu_type_transition(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *def,
                         const char *obj)
{
    if (obj) {
        return add_filename_trans(db, src, tgt, cls, def, obj);
    } else {
        return add_type_rule(db, src, tgt, cls, def, AVTAB_TRANSITION);
    }
}

bool ksu_type_change(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *def)
{
    return add_type_rule(db, src, tgt, cls, def, AVTAB_CHANGE);
}

bool ksu_type_member(struct policydb *db, const char *src, const char *tgt, const char *cls, const char *def)
{
    return add_type_rule(db, src, tgt, cls, def, AVTAB_MEMBER);
}

// File system labeling
bool ksu_genfscon(struct policydb *db, const char *fs_name, const char *path, const char *ctx)
{
    return add_genfscon(db, fs_name, path, ctx);
}

void ksu_destroy_policydb(struct policydb *db)
{
    policydb_destroy(db);
}

// handle backport
extern rwlock_t *ksu_policy_rwlock_ptr;

static inline void ksu_lock_sepolicy_legacy(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0) && !defined(KSU_COMPAT_HAS_POLICY_MUTEX)
// 4.14 - 5.10
#if defined(KSU_COMPAT_USE_SELINUX_STATE)
    read_lock(&selinux_state.ss->policy_rwlock);
// 4.14-
#else
    read_lock(ksu_policy_rwlock_ptr);
#endif
#endif
}

static inline void ksu_unlock_sepolicy_legacy(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0) && !defined(KSU_COMPAT_HAS_POLICY_MUTEX)
// 4.14 - 5.10
#if defined(KSU_COMPAT_USE_SELINUX_STATE)
    read_unlock(&selinux_state.ss->policy_rwlock);
// 4.14-
#else
    read_unlock(ksu_policy_rwlock_ptr);
#endif
#endif
}

// result is len or errno
int ksu_dup_policydb(struct policydb *old_db, struct policydb *new_db)
{
    struct policy_file fp = { 0 };
    void *data;
    int ret = 0;
    int len = 0;

    ksu_lock_sepolicy_legacy();

    // Some device policy db seems not marking type itself in type_attr_map_array
    // policydb_read() adds each type to its own attribute map, so old_db->policydb.len may be smaller
    // preserve one ebitmap entry for this condition to avoid trigger -EINVAL
    len = old_db->len + (size_t)old_db->p_types.nprim * (sizeof(u32) + sizeof(u64));

    ksu_unlock_sepolicy_legacy();

    data = vmalloc(len);
    if (!data) {
        pr_err("alloc policy buffer len %d\n", len);
        ret = -ENOMEM;
        goto out_free_data;
    }

    fp.data = data;
    fp.len = len;

    ksu_lock_sepolicy_legacy();
    ret = policydb_write(old_db, &fp);
    if (ret) {
        pr_err("sepolicy: policydb_write: %d\n", ret);
        ksu_unlock_sepolicy_legacy();
        goto out_free_data;
    }
    len -= fp.len;
    ksu_unlock_sepolicy_legacy();

    // https://android-review.googlesource.com/c/kernel/common/+/3009995
    // Android won't add these flags to policydb_write....
    // fixup config
    // 4*2+8+4
    static const size_t kConfigOff = 20;
    if (len >= kConfigOff + sizeof(u32)) {
        u32 *config_ptr = data + kConfigOff;
#ifdef KSU_COMPAT_HAS_POLICYDB_CONFIG_ANDROID_NETLINK_ROUTE
        if (old_db->android_netlink_route) {
            pr_info("adding POLICYDB_CONFIG_ANDROID_NETLINK_ROUTE\n");
            *config_ptr |= POLICYDB_CONFIG_ANDROID_NETLINK_ROUTE;
        }
#endif
#ifdef KSU_COMPAT_HAS_POLICYDB_CONFIG_ANDROID_NETLINK_GETNEIGH
        if (old_db->android_netlink_getneigh) {
            pr_info("adding POLICYDB_CONFIG_ANDROID_NETLINK_GETNEIGH\n");
            *config_ptr |= POLICYDB_CONFIG_ANDROID_NETLINK_GETNEIGH;
        }
#endif
    }

    // rewind fp
    fp.data = data;
    fp.len = len;

    ret = policydb_read(new_db, &fp);
    if (ret) {
        pr_err("sepolicy: policydb_read: %d\n", ret);
        goto out_free_data;
    }

    new_db->len = len;

    vfree(data);
    ret = len;

    return ret;

out_free_data:
    vfree(data);
    return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) || defined(KSU_COMPAT_HAS_POLICY_MUTEX)
// 5.10+ using selinux_policy

// ======== sepolicy ========

void ksu_destroy_sepolicy(struct selinux_policy *pol)
{
    ksu_destroy_policydb(&pol->policydb);
    kfree(pol);
}

struct selinux_policy *ksu_dup_sepolicy(struct selinux_policy *old_pol)
{
    int ret;
    size_t len;
    struct selinux_policy *new_pol;

    new_pol = kmemdup(old_pol, sizeof(*old_pol), GFP_KERNEL);

    if (!new_pol) {
        ret = -ENOMEM;
        pr_err("sepolicy: dup old pol\n");
        goto out;
    }
    memset(&new_pol->policydb, 0, sizeof(new_pol->policydb));

    ret = ksu_dup_policydb(&old_pol->policydb, &new_pol->policydb);

    if (ret < 0) {
        goto out_free_policydb;
    }

    return new_pol;

out_free_policydb:
    kfree(new_pol);
out:
    return ERR_PTR(ret);
}
#endif
KCEOF
cat > selinux/rules.c <<'KCEOF'
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <linux/rwlock.h>
#include <linux/mount.h>

#include "uapi/selinux.h"
#include "klog.h" // IWYU pragma: keep
#include "selinux.h"
#include "sepolicy.h"
#include "ss/services.h"
#include "linux/lsm_audit.h" // IWYU pragma: keep
#include "xfrm.h"
#include "infra/symbol_resolver.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) || defined(KSU_COMPAT_HAS_SELINUX_POLICY_STRUCT)
#define SELINUX_POLICY_INSTEAD_SELINUX_SS

struct selinux_policy *backup_sepolicy;
#else
struct policydb *backup_policydb;
struct sidtab *backup_sidtab;
#endif

#define ALL NULL

#if ((!defined(KSU_COMPAT_USE_SELINUX_STATE)) || LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0))
extern int avc_ss_reset(u32 seqno);
#else
extern int avc_ss_reset(struct selinux_avc *avc, u32 seqno);
#endif
// reset avc cache table, otherwise the new rules will not take effect if already denied
static void reset_avc_cache()
{
#if ((!defined(KSU_COMPAT_USE_SELINUX_STATE)) || LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0))
    avc_ss_reset(0);
    selnl_notify_policyload(0);
    selinux_status_update_policyload(0);
#else
    struct selinux_avc *avc = selinux_state.avc;
    avc_ss_reset(avc, 0);
    selnl_notify_policyload(0);
    selinux_status_update_policyload(&selinux_state, 0);
#endif
    selinux_xfrm_notify_policyload();
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0) && !defined(KSU_COMPAT_HAS_POLICY_MUTEX)

static struct policydb *get_policydb(void)
{
    struct policydb *db;
// selinux_state does not exists before 4.19
#ifdef KSU_COMPAT_USE_SELINUX_STATE
#ifdef SELINUX_POLICY_INSTEAD_SELINUX_SS
#error It should not happen!
#else
    struct selinux_ss *ss = selinux_state.ss;
    db = &ss->policydb;
#endif
#else
    db = &policydb;
#endif
    return db;
}

#if defined(KSU_COMPAT_USE_SELINUX_STATE) && !defined(SELINUX_POLICY_INSTEAD_SELINUX_SS)
extern struct vfsmount *selinuxfs_mount;

struct selinux_fs_info {
    struct dentry *bool_dir;
    unsigned int bool_num;
    char **bool_pending_names;
    unsigned int *bool_pending_values;
    struct dentry *class_dir;
    unsigned long last_class_ino;
    bool policy_opened;
    struct dentry *policycap_dir;
    struct mutex mutex;
    unsigned long last_ino;
    struct selinux_state *state;
    struct super_block *sb;
};
#endif

#ifndef KSU_COMPAT_USE_SELINUX_STATE
static struct mutex *ksu_sel_mutex_ptr = NULL;
rwlock_t *ksu_policy_rwlock_ptr = NULL;
#endif // #ifndef KSU_COMPAT_USE_SELINUX_STATE

static inline void ksu_lock_sel_mutex_legacy(void)
{
// 4.14 - 5.10
#if defined(KSU_COMPAT_USE_SELINUX_STATE) && !defined(SELINUX_POLICY_INSTEAD_SELINUX_SS)
    struct selinux_fs_info *fsi = selinuxfs_mount->mnt_sb->s_fs_info;
    mutex_lock(&fsi->mutex);
// 4.14-
#else
    mutex_lock(ksu_sel_mutex_ptr);
#endif
}

static inline void ksu_unlock_sel_mutex_legacy(void)
{
// 4.14 - 5.10
#if defined(KSU_COMPAT_USE_SELINUX_STATE) && !defined(SELINUX_POLICY_INSTEAD_SELINUX_SS)
    struct selinux_fs_info *fsi = selinuxfs_mount->mnt_sb->s_fs_info;
    mutex_unlock(&fsi->mutex);
// 4.14-
#else
    mutex_unlock(ksu_sel_mutex_ptr);
#endif
}

static inline void ksu_lock_sepolicy_legacy(void)
{
// 4.14 - 5.10
#if defined(KSU_COMPAT_USE_SELINUX_STATE) && !defined(SELINUX_POLICY_INSTEAD_SELINUX_SS)
    write_lock_irq(&selinux_state.ss->policy_rwlock);
// 4.14-
#else
    write_lock_irq(ksu_policy_rwlock_ptr);
#endif
}

static inline void ksu_unlock_sepolicy_legacy(void)
{
// 4.14 - 5.10
#if defined(KSU_COMPAT_USE_SELINUX_STATE) && !defined(SELINUX_POLICY_INSTEAD_SELINUX_SS)
    write_unlock_irq(&selinux_state.ss->policy_rwlock);
// 4.14-
#else
    write_unlock_irq(ksu_policy_rwlock_ptr);
#endif
}

#endif // KSU_COMPAT_HAS_POLICY_MUTEX

void apply_kernelsu_rules()
{
    struct policydb *db;

    if (!getenforce()) {
        pr_info("SELinux permissive or disabled, apply rules!\n");
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) || defined(KSU_COMPAT_HAS_POLICY_MUTEX)
    struct selinux_policy *pol, *old_pol;
    mutex_lock(&selinux_state.policy_mutex);
    old_pol = rcu_dereference_protected(selinux_state.policy, lockdep_is_held(&selinux_state.policy_mutex));
    backup_sepolicy = ksu_dup_sepolicy(old_pol);
    if (IS_ERR(backup_sepolicy)) {
        pr_err("failed to create backup sepolicy: %ld\n", PTR_ERR(backup_sepolicy));
        backup_sepolicy = NULL;
    } else {
        backup_sepolicy->sidtab = kzalloc(sizeof(*backup_sepolicy->sidtab), GFP_KERNEL);
        if (!backup_sepolicy->sidtab) {
            pr_err("failed to alloc backup sidtab\n");
            ksu_destroy_sepolicy(backup_sepolicy);
            backup_sepolicy = NULL;
        } else {
            int ret = policydb_load_isids(&backup_sepolicy->policydb, backup_sepolicy->sidtab);
            if (ret) {
                pr_err("failed to load isids for backup sepolicy: %d!\n", ret);
                kfree(backup_sepolicy->sidtab);
                ksu_destroy_sepolicy(backup_sepolicy);
                backup_sepolicy = NULL;
            } else {
                pr_info("backup sepolicy success! latest_granting=%d\n", backup_sepolicy->latest_granting);
            }
        }
    }
    pol = ksu_dup_sepolicy(old_pol);
    if (IS_ERR(pol)) {
        pr_err("failed to dup selinux_policy: %ld\n", PTR_ERR(pol));
        goto out_unlock;
    }
    db = &pol->policydb;
#else
    int len = 0;

    struct policydb *policydb_ptr = get_policydb();

    struct policydb *oldpolicydb, *newpolicydb, *tmpdb;

    oldpolicydb = kcalloc(2, sizeof(*oldpolicydb), GFP_KERNEL);
    newpolicydb = oldpolicydb + 1;
    db = newpolicydb;

    backup_policydb = kzalloc(sizeof(*backup_policydb), GFP_KERNEL);

    ksu_lock_sel_mutex_legacy();

    len = ksu_dup_policydb(policydb_ptr, backup_policydb);
    pr_info("len of ksu_dup_policydb (backup_db) output: %d", len);
    if (len < 0) {
        pr_err("failed to dup policydb");
        kfree(backup_policydb);
        backup_policydb = NULL;
        backup_sidtab = NULL;
    } else {
        backup_sidtab = kzalloc(sizeof(*backup_sidtab), GFP_KERNEL);
        if (!backup_sidtab) {
            pr_err("failed to alloc backup sidtab\n");
            ksu_destroy_policydb(backup_policydb);
            kfree(backup_policydb);
            backup_policydb = NULL;
            backup_sidtab = NULL;
        } else {
            int ret = policydb_load_isids(backup_policydb, backup_sidtab);
            if (ret) {
                pr_err("failed to load isids for backup sepolicy: %d!\n", ret);
                kfree(backup_sidtab);
                ksu_destroy_policydb(backup_policydb);
                kfree(backup_policydb);
                backup_policydb = NULL;
                backup_sidtab = NULL;
            } else {
                pr_info("backup sepolicy success!\n");
            }
        }
    }

    len = ksu_dup_policydb(policydb_ptr, db);
    pr_info("len of ksu_dup_policydb output: %d", len);

    if (len < 0) {
        pr_err("failed to dup policydb\n");
        goto out_free;
    }
#endif

    ksu_type(db, KERNEL_SU_DOMAIN, "domain");
    ksu_permissive(db, KERNEL_SU_DOMAIN);
    ksu_typeattribute(db, KERNEL_SU_DOMAIN, "mlstrustedsubject");
    ksu_typeattribute(db, KERNEL_SU_DOMAIN, "netdomain");
    ksu_typeattribute(db, KERNEL_SU_DOMAIN, "bluetoothdomain");

    // Create unconstrained file type
    ksu_type(db, KERNEL_SU_FILE, "file_type");
    ksu_typeattribute(db, KERNEL_SU_FILE, "mlstrustedobject");
    ksu_allow(db, "domain", KERNEL_SU_FILE, ALL, ALL);

    // allow all!
    ksu_allow(db, KERNEL_SU_DOMAIN, ALL, ALL, ALL);

    // allow us do any ioctl
    if (db->policyvers >= POLICYDB_VERSION_XPERMS_IOCTL) {
        ksu_allowxperm(db, KERNEL_SU_DOMAIN, ALL, "blk_file", ALL);
        ksu_allowxperm(db, KERNEL_SU_DOMAIN, ALL, "fifo_file", ALL);
        ksu_allowxperm(db, KERNEL_SU_DOMAIN, ALL, "chr_file", ALL);
        ksu_allowxperm(db, KERNEL_SU_DOMAIN, ALL, "file", ALL);
    }

    // our ksud triggered by init
    ksu_allow(db, "init", KERNEL_SU_DOMAIN, ALL, ALL);

    // restored from https://github.com/tiann/KernelSU/pull/3031
    ksu_allow(db, "init", "adb_data_file", "file", ALL);
    ksu_allow(db, "init", "adb_data_file", "dir", ALL); // #1289

    // copied from Magisk rules
    // suRights
    ksu_allow(db, "servicemanager", KERNEL_SU_DOMAIN, "dir", "search");
    ksu_allow(db, "servicemanager", KERNEL_SU_DOMAIN, "dir", "read");
    ksu_allow(db, "servicemanager", KERNEL_SU_DOMAIN, "file", "open");
    ksu_allow(db, "servicemanager", KERNEL_SU_DOMAIN, "file", "read");
    ksu_allow(db, "servicemanager", KERNEL_SU_DOMAIN, "process", "getattr");
    ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "process", "sigchld");

    // allowLog
    ksu_allow(db, "logd", KERNEL_SU_DOMAIN, "dir", "search");
    ksu_allow(db, "logd", KERNEL_SU_DOMAIN, "file", "read");
    ksu_allow(db, "logd", KERNEL_SU_DOMAIN, "file", "open");
    ksu_allow(db, "logd", KERNEL_SU_DOMAIN, "file", "getattr");

    // dumpsys, send fd
    ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "fd", "use");
    ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "fifo_file", "write");
    ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "fifo_file", "read");
    ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "fifo_file", "open");
    ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "fifo_file", "getattr");
    ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "unix_stream_socket", "read");
    ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "unix_stream_socket", "write");
    ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "unix_stream_socket", "connectto");
    ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "unix_stream_socket", "getopt");
    ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "unix_stream_socket", "getattr");

    // use memfd created by su domain
    ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "memfd_file", "execute");
    ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "memfd_file", "getattr");
    ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "memfd_file", "map");
    ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "memfd_file", "read");
    ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "memfd_file", "write");

    // bootctl
    ksu_allow(db, "hwservicemanager", KERNEL_SU_DOMAIN, "dir", "search");
    ksu_allow(db, "hwservicemanager", KERNEL_SU_DOMAIN, "file", "read");
    ksu_allow(db, "hwservicemanager", KERNEL_SU_DOMAIN, "file", "open");
    ksu_allow(db, "hwservicemanager", KERNEL_SU_DOMAIN, "process", "getattr");

    // Allow all binder transactions
    ksu_allow(db, "domain", KERNEL_SU_DOMAIN, "binder", ALL);

    // Allow system server kill su process
    ksu_allow(db, "system_server", KERNEL_SU_DOMAIN, "process", "getpgid");
    ksu_allow(db, "system_server", KERNEL_SU_DOMAIN, "process", "sigkill");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) || defined(KSU_COMPAT_HAS_POLICY_MUTEX)
    rcu_assign_pointer(selinux_state.policy, pol);
    synchronize_rcu();
    ksu_destroy_sepolicy(old_pol);

    reset_avc_cache();
out_unlock:
    mutex_unlock(&selinux_state.policy_mutex);
#else
    /* Save the old policydb to free later. */
    memcpy(oldpolicydb, policydb_ptr, sizeof(*policydb_ptr));

    /* Install the new policydb. */
    ksu_lock_sepolicy_legacy();
    memcpy(policydb_ptr, newpolicydb, sizeof(*policydb_ptr));
    ksu_unlock_sepolicy_legacy();

    reset_avc_cache();

    /* Free the old policydb. */
    ksu_destroy_policydb(oldpolicydb);

out_free:
    /* Free buffer */
    kfree(oldpolicydb);
    ksu_unlock_sel_mutex_legacy();
#endif
}

#define KSU_SEPOLICY_MAX_BATCH_SIZE (8U * 1024U * 1024U)
#define KSU_SEPOLICY_MAX_ARGS 5

struct sepol_data {
    u32 cmd;
    u32 subcmd;
};

struct sepol_batch_cursor {
    const u8 *cur;
    const u8 *end;
};

static size_t sepol_remaining(const struct sepol_batch_cursor *cursor)
{
    return (size_t)(cursor->end - cursor->cur);
}

static int sepol_read_cmd_header(struct sepol_batch_cursor *cursor, struct sepol_data *header)
{
    if (sepol_remaining(cursor) < sizeof(*header)) {
        return -EINVAL;
    }

    memcpy(header, cursor->cur, sizeof(*header));
    cursor->cur += sizeof(*header);

    return 0;
}

static int sepol_read_string(struct sepol_batch_cursor *cursor, const char **out)
{
    u32 len;
    const char *str;

    if (sepol_remaining(cursor) < sizeof(len)) {
        return -EINVAL;
    }

    memcpy(&len, cursor->cur, sizeof(len));
    cursor->cur += sizeof(len);

    if (len >= sepol_remaining(cursor)) {
        return -EINVAL;
    }

    str = (const char *)cursor->cur;
    if (memchr(str, '\0', len) != NULL || str[len] != '\0') {
        return -EINVAL;
    }

    cursor->cur += len + 1;
    if (len == 0) {
        *out = ALL;
        return 0;
    }

    *out = str;
    return 0;
}

static int sepol_require_not_all(const char *value, const char *name)
{
    if (value != ALL) {
        return 0;
    }

    pr_err("sepol: %s cannot be ALL.\n", name);
    return -EINVAL;
}

static int sepol_expected_argc(u32 cmd)
{
    switch (cmd) {
    case KSU_SEPOLICY_CMD_NORMAL_PERM:
        return 4;
    case KSU_SEPOLICY_CMD_XPERM:
        return 5;
    case KSU_SEPOLICY_CMD_TYPE_STATE:
        return 1;
    case KSU_SEPOLICY_CMD_TYPE:
    case KSU_SEPOLICY_CMD_TYPE_ATTR:
        return 2;
    case KSU_SEPOLICY_CMD_ATTR:
        return 1;
    case KSU_SEPOLICY_CMD_TYPE_TRANSITION:
        return 5;
    case KSU_SEPOLICY_CMD_TYPE_CHANGE:
        return 4;
    case KSU_SEPOLICY_CMD_GENFSCON:
        return 3;
    default:
        return -EINVAL;
    }
}

static int apply_one_sepolicy_cmd(struct policydb *db, const struct sepol_data *header, const char **args)
{
    bool success = false;
    int ret;

    switch (header->cmd) {
    case KSU_SEPOLICY_CMD_NORMAL_PERM:
        if (header->subcmd == KSU_SEPOLICY_SUBCMD_NORMAL_PERM_ALLOW) {
            success = ksu_allow(db, args[0], args[1], args[2], args[3]);
        } else if (header->subcmd == KSU_SEPOLICY_SUBCMD_NORMAL_PERM_DENY) {
            success = ksu_deny(db, args[0], args[1], args[2], args[3]);
        } else if (header->subcmd == KSU_SEPOLICY_SUBCMD_NORMAL_PERM_AUDITALLOW) {
            success = ksu_auditallow(db, args[0], args[1], args[2], args[3]);
        } else if (header->subcmd == KSU_SEPOLICY_SUBCMD_NORMAL_PERM_DONTAUDIT) {
            success = ksu_dontaudit(db, args[0], args[1], args[2], args[3]);
        } else {
            pr_err("sepol: unknown subcmd: %d\n", header->subcmd);
        }
        return success ? 0 : -EINVAL;

    case KSU_SEPOLICY_CMD_XPERM:
        ret = sepol_require_not_all(args[3], "operation");
        if (ret < 0) {
            return ret;
        }
        ret = sepol_require_not_all(args[4], "perm_set");
        if (ret < 0) {
            return ret;
        }

        if (header->subcmd == KSU_SEPOLICY_SUBCMD_XPERM_ALLOW) {
            success = ksu_allowxperm(db, args[0], args[1], args[2], args[4]);
        } else if (header->subcmd == KSU_SEPOLICY_SUBCMD_XPERM_AUDITALLOW) {
            success = ksu_auditallowxperm(db, args[0], args[1], args[2], args[4]);
        } else if (header->subcmd == KSU_SEPOLICY_SUBCMD_XPERM_DONTAUDIT) {
            success = ksu_dontauditxperm(db, args[0], args[1], args[2], args[4]);
        } else {
            pr_err("sepol: unknown subcmd: %d\n", header->subcmd);
        }
        return success ? 0 : -EINVAL;

    case KSU_SEPOLICY_CMD_TYPE_STATE:
        ret = sepol_require_not_all(args[0], "type");
        if (ret < 0) {
            return ret;
        }

        if (header->subcmd == KSU_SEPOLICY_SUBCMD_TYPE_STATE_PERMISSIVE) {
            success = ksu_permissive(db, args[0]);
        } else if (header->subcmd == KSU_SEPOLICY_SUBCMD_TYPE_STATE_ENFORCE) {
            success = ksu_enforce(db, args[0]);
        } else {
            pr_err("sepol: unknown subcmd: %d\n", header->subcmd);
        }
        return success ? 0 : -EINVAL;

    case KSU_SEPOLICY_CMD_TYPE:
    case KSU_SEPOLICY_CMD_TYPE_ATTR:
        ret = sepol_require_not_all(args[0], "type");
        if (ret < 0) {
            return ret;
        }
        ret = sepol_require_not_all(args[1], "attribute");
        if (ret < 0) {
            return ret;
        }

        if (header->cmd == KSU_SEPOLICY_CMD_TYPE) {
            success = ksu_type(db, args[0], args[1]);
        } else {
            success = ksu_typeattribute(db, args[0], args[1]);
        }
        if (!success) {
            pr_err("sepol: %d failed.\n", header->cmd);
            return -EINVAL;
        }
        return 0;

    case KSU_SEPOLICY_CMD_ATTR:
        ret = sepol_require_not_all(args[0], "attribute");
        if (ret < 0) {
            return ret;
        }

        if (!ksu_attribute(db, args[0])) {
            pr_err("sepol: %d failed.\n", header->cmd);
            return -EINVAL;
        }
        return 0;

    case KSU_SEPOLICY_CMD_TYPE_TRANSITION: {
        const char *object = ALL;

        ret = sepol_require_not_all(args[0], "src");
        if (ret < 0) {
            return ret;
        }
        ret = sepol_require_not_all(args[1], "tgt");
        if (ret < 0) {
            return ret;
        }
        ret = sepol_require_not_all(args[2], "cls");
        if (ret < 0) {
            return ret;
        }
        ret = sepol_require_not_all(args[3], "default_type");
        if (ret < 0) {
            return ret;
        }

        object = args[4];

        success = ksu_type_transition(db, args[0], args[1], args[2], args[3], object);
        return success ? 0 : -EINVAL;
    }

    case KSU_SEPOLICY_CMD_TYPE_CHANGE:
        ret = sepol_require_not_all(args[0], "src");
        if (ret < 0) {
            return ret;
        }
        ret = sepol_require_not_all(args[1], "tgt");
        if (ret < 0) {
            return ret;
        }
        ret = sepol_require_not_all(args[2], "cls");
        if (ret < 0) {
            return ret;
        }
        ret = sepol_require_not_all(args[3], "default_type");
        if (ret < 0) {
            return ret;
        }

        if (header->subcmd == KSU_SEPOLICY_SUBCMD_TYPE_CHANGE_CHANGE) {
            success = ksu_type_change(db, args[0], args[1], args[2], args[3]);
        } else if (header->subcmd == KSU_SEPOLICY_SUBCMD_TYPE_CHANGE_MEMBER) {
            success = ksu_type_member(db, args[0], args[1], args[2], args[3]);
        } else {
            pr_err("sepol: unknown subcmd: %d\n", header->subcmd);
        }
        return success ? 0 : -EINVAL;

    case KSU_SEPOLICY_CMD_GENFSCON:
        ret = sepol_require_not_all(args[0], "name");
        if (ret < 0) {
            return ret;
        }
        ret = sepol_require_not_all(args[1], "path");
        if (ret < 0) {
            return ret;
        }
        ret = sepol_require_not_all(args[2], "context");
        if (ret < 0) {
            return ret;
        }

        if (!ksu_genfscon(db, args[0], args[1], args[2])) {
            pr_err("sepol: %d failed.\n", header->cmd);
            return -EINVAL;
        }
        return 0;

    default:
        pr_err("sepol: unknown cmd: %d\n", header->cmd);
        return -EINVAL;
    }
}

int handle_sepolicy(void __user *user_data, u64 data_len)
{
    struct policydb *db;
    struct sepol_batch_cursor cursor;
    u8 *payload;
    int ret = 0;
    int success_cmd_count = 0;
    u32 cmd_index = 0;

    if (!user_data || !data_len)
        return -EINVAL;

    if (data_len > KSU_SEPOLICY_MAX_BATCH_SIZE)
        return -E2BIG;

    payload = vmalloc((size_t)data_len);
    if (!payload)
        return -ENOMEM;

    if (copy_from_user(payload, user_data, (size_t)data_len)) {
        ret = -EFAULT;
        goto out_free;
    }

    if (!getenforce()) {
        pr_info("SELinux permissive or disabled when handle policy!\n");
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) || defined(KSU_COMPAT_HAS_POLICY_MUTEX)
    struct selinux_policy *pol, *old_pol;
    // Starting from 5.10, selinux_state have __rcu "policy"
    // It is _rcu, and have an policy mutex
    // 	struct selinux_policy __rcu *policy;
    // 	struct mutex policy_mutex;
    //
    // I think we can directly use this rcu to safety update selinux_policy
    // this is also the upstream ksu way
    mutex_lock(&selinux_state.policy_mutex);
    old_pol = rcu_dereference_protected(selinux_state.policy, lockdep_is_held(&selinux_state.policy_mutex));
    pol = ksu_dup_sepolicy(old_pol);
    if (IS_ERR(pol)) {
        ret = PTR_ERR(pol);
        pr_err("ksu_dup_sepolicy err: %d\n", ret);
        goto out_unlock;
    }
    db = &pol->policydb;
#else
    int len = 0;

    struct policydb *policydb_ptr = get_policydb();

    struct policydb *oldpolicydb, *newpolicydb, *tmpdb;

    oldpolicydb = kcalloc(2, sizeof(*oldpolicydb), GFP_KERNEL);
    newpolicydb = oldpolicydb + 1;
    db = newpolicydb;

    ksu_lock_sel_mutex_legacy();

    len = ksu_dup_policydb(policydb_ptr, db);

    if (len < 0) {
        kfree(oldpolicydb);
        ret = len;
        goto out_free;
    }
#endif

    cursor.cur = payload;
    cursor.end = payload + (size_t)data_len;

    ret = 0;
    success_cmd_count = 0;
    cmd_index = 0;
    while (cursor.cur < cursor.end) {
        struct sepol_data header;
        const char *args[KSU_SEPOLICY_MAX_ARGS] = { 0 };
        int expected_argc;
        u32 arg_index;

        ret = sepol_read_cmd_header(&cursor, &header);
        if (ret < 0) {
            pr_err("sepol: failed to read cmd header #%u.\n", cmd_index);
            goto out_drop_new_policy;
        }

        expected_argc = sepol_expected_argc(header.cmd);
        if (expected_argc < 0 || expected_argc > KSU_SEPOLICY_MAX_ARGS) {
            ret = -EINVAL;
            pr_err("sepol: invalid cmd header #%u.\n", cmd_index);
            goto out_drop_new_policy;
        }

        for (arg_index = 0; arg_index < (u32)expected_argc; arg_index++) {
            ret = sepol_read_string(&cursor, &args[arg_index]);
            if (ret < 0) {
                pr_err("sepol: failed to read cmd #%u arg #%u.\n", cmd_index, arg_index);
                goto out_drop_new_policy;
            }
        }

        ret = apply_one_sepolicy_cmd(db, &header, args);
        if (ret < 0) {
            pr_err("sepol: cmd #%u failed, cmd=%u subcmd=%u.\n", cmd_index, header.cmd, header.subcmd);
        } else {
            success_cmd_count++;
        }
        cmd_index++;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) || defined(KSU_COMPAT_HAS_POLICY_MUTEX)
    // 5.10+
    rcu_assign_pointer(selinux_state.policy, pol);
    synchronize_rcu();
    ksu_destroy_sepolicy(old_pol);

    reset_avc_cache();
    ret = success_cmd_count;
    goto out_unlock;

out_drop_new_policy:
    ksu_destroy_sepolicy(pol);
out_unlock:
    mutex_unlock(&selinux_state.policy_mutex);
#else
    ret = success_cmd_count;
    /* Save the old policydb to free later. */
    memcpy(oldpolicydb, policydb_ptr, sizeof(*policydb_ptr));

    /* Install the new policydb. */
    ksu_lock_sepolicy_legacy();
    memcpy(policydb_ptr, newpolicydb, sizeof(*policydb_ptr));
    ksu_unlock_sepolicy_legacy();

    reset_avc_cache();

    /* Free the old policydb. */
    ksu_destroy_policydb(oldpolicydb);

    /* Free buffer */
    kfree(oldpolicydb);
#endif
out_free:
    vfree(payload);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0) && !defined(KSU_COMPAT_HAS_POLICY_MUTEX)
    ksu_unlock_sel_mutex_legacy();
#endif

    return ret;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0) && !defined(KSU_COMPAT_HAS_POLICY_MUTEX)
out_drop_new_policy:
    ksu_destroy_policydb(newpolicydb);
    kfree(oldpolicydb);
    goto out_free;
#endif
}

void __init ksu_selinux_init()
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0) && !defined(KSU_COMPAT_USE_SELINUX_STATE)

#ifdef CONFIG_KALLSYMS_ALL
    ksu_sel_mutex_ptr = (struct mutex *)ksu_resolve_symbol_for_functable_hook("sel_mutex");
    ksu_policy_rwlock_ptr = (rwlock_t *)ksu_resolve_symbol_for_functable_hook("policy_rwlock");
#else
    extern struct mutex sel_mutex;
    extern rwlock_t policy_rwlock;

    ksu_sel_mutex_ptr = &sel_mutex;
    ksu_policy_rwlock_ptr = &policy_rwlock;
#endif

#endif
}
KCEOF
cat > feature/selinux_hide.h <<'KSEOFH'
#ifndef __KSU_H_SELINUX_HIDE
#define __KSU_H_SELINUX_HIDE
#include <linux/types.h>
#include <linux/version.h>
#include <linux/sched.h>

void ksu_selinux_hide_init();
void ksu_selinux_hide_exit();
void ksu_selinux_hide_drop_backup_if_unused();
void ksu_selinux_hide_handle_second_stage();
void ksu_selinux_hide_handle_post_fs_data();

// https://github.com/torvalds/linux/commit/b21507e272627c434e8dd74e8d51fd8245281b59
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0) || defined(KSU_COMPAT_SETPROCATTR_USE_NEW_PROTOTYPE)
typedef int (*setprocattr_fn)(const char *name, void *value, size_t size);

int ksu_handle_selinux_setprocattr(const char *name, void *value, size_t size);
#else
typedef int (*setprocattr_fn)(struct task_struct *p, char *name, void *value, size_t size);

int ksu_handle_selinux_setprocattr(struct task_struct *p, char *name, void *value, size_t size);
#endif

#endif
KSEOFH
cat > feature/selinux_hide.c <<'KCEOF'
#include <linux/cred.h>
#include <linux/cpu.h>
#include <linux/memory.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <asm-generic/errno-base.h>
#include <net/genetlink.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/version.h>
#include <linux/jump_label.h>

// security/selinux/include/security.h
#include <security.h>
#include <ss/context.h>
#include <ss/services.h>
#include <ss/mls.h>
#include <ss/conditional.h>

#include "avc.h"
#include "klog.h" // IWYU pragma: keep
#include "linux/kallsyms.h"
#include "objsec.h"
#include "hook/patch_memory.h"
#include "ksu.h"
#include "policy/feature.h"
#include "infra/symbol_resolver.h"
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
#include "hook/lsm_hook_magic.h"
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0) || defined(KSU_COMPAT_HAS_LIST_OF_LSM_HOOKS)
#include <linux/lsm_hooks.h>
#endif

#include "selinux/selinux.h"
#include "selinux/sepolicy.h"
#include "selinux_hide.h"
#include "compat/kernel_compat.h"

#ifdef KSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE
#define __maybe_static
#else
#define __maybe_static static
#endif

static DEFINE_MUTEX(selinux_hide_mutex);
__maybe_static bool ksu_selinux_hide_enabled __read_mostly = false;
// remove static in susfs
__maybe_static bool ksu_selinux_hide_running __read_mostly = false;

#ifdef KSU_COMPAT_USE_STATIC_KEY
// We should talk to you, susfs
// Why use manual hook instead of auto hook
__maybe_static DEFINE_STATIC_KEY_FALSE(fake_status_initialize_key);
#else
static bool fake_status_initialize_key __read_mostly = false;
#endif

__maybe_static struct page *fake_status = NULL;
static struct mutex *ksu_selinux_status_lock = NULL;
__maybe_static void initialize_fake_status();

#ifndef KSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE
enum sel_inos {
    SEL_ROOT_INO = 2,
    SEL_LOAD, /* load policy */
    SEL_ENFORCE, /* get or set enforcing status */
    SEL_CONTEXT, /* validate context */
    SEL_ACCESS, /* compute access decision */
    SEL_CREATE, /* compute create labeling decision */
    SEL_RELABEL, /* compute relabeling decision */
    SEL_USER, /* compute reachable user contexts */
    SEL_POLICYVERS, /* return policy version for this kernel */
    SEL_COMMIT_BOOLS, /* commit new boolean values */
    SEL_MLS, /* return if MLS policy is enabled */
    SEL_DISABLE, /* disable SELinux until next reboot */
    SEL_MEMBER, /* compute polyinstantiation membership decision */
    SEL_CHECKREQPROT, /* check requested protection, not kernel-applied one */
    SEL_COMPAT_NET, /* whether to use old compat network packet controls */
    SEL_REJECT_UNKNOWN, /* export unknown reject handling to userspace */
    SEL_DENY_UNKNOWN, /* export unknown deny handling to userspace */
    SEL_STATUS, /* export current status using mmap() */
    SEL_POLICY, /* allow userspace to read the in kernel policy */
    SEL_VALIDATE_TRANS, /* compute validatetrans decision */
    SEL_INO_NEXT, /* The next inode number to use */
};

typedef ssize_t (*write_op_fn)(struct file *, char *, size_t);

static write_op_fn *selinux_write_op;

#endif // #ifndef KSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
// remove static in susfs
__maybe_static int security_context_to_sid_with_policy(struct selinux_policy *policy, const char *scontext,
                                                       u32 scontext_len, u32 *sid, u32 def_sid, gfp_t gfp_flags);
__maybe_static int security_sid_to_context_with_policy(struct selinux_policy *policy, u32 sid, char **scontext,
                                                       u32 *scontext_len);
__maybe_static void security_compute_av_user_with_policy(struct selinux_policy *policy, u32 ssid, u32 tsid, u16 tclass,
                                                         struct av_decision *avd);
static void (*security_dump_masked_av_fn)(struct policydb *policydb, struct context *scontext, struct context *tcontext,
                                          u16 tclass, u32 permissions, const char *reason) = NULL;
static void (*context_struct_compute_av_fn)(struct policydb *policydb, struct context *scontext,
                                            struct context *tcontext, u16 tclass, struct av_decision *avd,
                                            struct extended_perms *xperms) = NULL;
#elif defined(KSU_COMPAT_USE_SELINUX_STATE)
// remove static in susfs
__maybe_static struct selinux_state fake_state;
#else
static int dump_masked_av_helper(void *k, void *d, void *args);
static int context_struct_to_string(struct context *context, char **scontext, u32 *scontext_len);
static void context_struct_compute_av(struct context *scontext, struct context *tcontext, u16 tclass,
                                      struct av_decision *avd, struct extended_perms *xperms);
static void security_dump_masked_av(struct context *scontext, struct context *tcontext, u16 tclass, u32 permissions,
                                    const char *reason);
static int constraint_expr_eval(struct context *scontext, struct context *tcontext, struct context *xcontext,
                                struct constraint_expr *cexpr);
static void type_attribute_bounds_av(struct context *scontext, struct context *tcontext, u16 tclass,
                                     struct av_decision *avd);
static void avd_init(struct av_decision *avd);
static inline u32 current_sid(void);
static int string_to_context_struct(struct policydb *pol, struct sidtab *sidtabp, char *scontext, u32 scontext_len,
                                    struct context *ctx, u32 def_sid);
static int ksu_security_context_to_sid(const char *scontext, u32 scontext_len, u32 *sid, gfp_t gfp_flags);
static int ksu_security_context_str_to_sid(const char *scontext, u32 *sid, gfp_t gfp);
static int ksu_security_sid_to_context(u32 sid, char **scontext, u32 *scontext_len);
static void ksu_security_compute_av_user(u32 ssid, u32 tsid, u16 tclass, struct av_decision *avd);
#endif

#ifndef KSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE

static write_op_fn *context_write, *access_write;
static write_op_fn orig_context_write, orig_access_write;

static ssize_t my_write_context(struct file *file, char *buf, size_t size)
{
    // apply to all app uids
    if (likely(ksu_get_uid_t(current_uid()) < 10000)) {
        return orig_context_write(file, buf, size);
    }
    char *canon = NULL;
    u32 sid, len;
    ssize_t length;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
    length = avc_has_perm(current_sid(), SECINITSID_SECURITY, SECCLASS_SECURITY, SECURITY__CHECK_CONTEXT, NULL);
    if (length)
        goto out;
    length = security_context_to_sid_with_policy(backup_sepolicy, buf, size, &sid, SECSID_NULL, GFP_KERNEL);
    if (length)
        goto out;

    length = security_sid_to_context_with_policy(backup_sepolicy, sid, &canon, &len);
    if (length)
        goto out;

    length = -ERANGE;
    if (len > SIMPLE_TRANSACTION_LIMIT) {
        pr_err("SELinux: %s:  context size (%u) exceeds "
               "payload max\n",
               __func__, len);
        goto out;
    }
#elif defined(KSU_COMPAT_USE_SELINUX_STATE)
    length = avc_has_perm(&selinux_state, current_sid(), SECINITSID_SECURITY, SECCLASS_SECURITY,
                          SECURITY__CHECK_CONTEXT, NULL);
    if (length)
        goto out;

    length = security_context_to_sid(&fake_state, buf, size, &sid, GFP_KERNEL);
    if (length)
        goto out;

    length = security_sid_to_context(&fake_state, sid, &canon, &len);
    if (length)
        goto out;
#else
    length = avc_has_perm(current_sid(), SECINITSID_SECURITY, SECCLASS_SECURITY, SECURITY__CHECK_CONTEXT, NULL);
    if (length)
        goto out;

    length = ksu_security_context_to_sid(buf, size, &sid, GFP_KERNEL);
    if (length)
        goto out;

    length = ksu_security_sid_to_context(sid, &canon, &len);
    if (length)
        goto out;

    length = -ERANGE;
    if (len > SIMPLE_TRANSACTION_LIMIT) {
        printk(KERN_ERR "SELinux: %s:  context size (%u) exceeds "
                        "payload max\n",
               __func__, len);
        goto out;
    }
#endif

    memcpy(buf, canon, len);
    length = len;
out:
    kfree(canon);
    return length;
}

static ssize_t my_write_access(struct file *file, char *buf, size_t size)
{
    // apply to all app uids
    if (likely(ksu_get_uid_t(current_uid()) < 10000)) {
        return orig_access_write(file, buf, size);
    }
    char *scon = NULL, *tcon = NULL;
    u32 ssid, tsid;
    u16 tclass;
    struct av_decision avd;
    ssize_t length;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
    length = avc_has_perm(current_sid(), SECINITSID_SECURITY, SECCLASS_SECURITY, SECURITY__COMPUTE_AV, NULL);
#elif defined(KSU_COMPAT_USE_SELINUX_STATE)
    length =
        avc_has_perm(&selinux_state, current_sid(), SECINITSID_SECURITY, SECCLASS_SECURITY, SECURITY__COMPUTE_AV, NULL);
#else
    length = avc_has_perm(current_sid(), SECINITSID_SECURITY, SECCLASS_SECURITY, SECURITY__COMPUTE_AV, NULL);
#endif
    if (length)
        goto out;

    length = -ENOMEM;
    scon = kzalloc(size + 1, GFP_KERNEL);
    if (!scon)
        goto out;

    length = -ENOMEM;
    tcon = kzalloc(size + 1, GFP_KERNEL);
    if (!tcon)
        goto out;

    length = -EINVAL;
    if (sscanf(buf, "%s %s %hu", scon, tcon, &tclass) != 3)
        goto out;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
    length = security_context_to_sid_with_policy(backup_sepolicy, scon, strlen(scon), &ssid, SECSID_NULL, GFP_KERNEL);
    if (length)
        goto out;

    length = security_context_to_sid_with_policy(backup_sepolicy, tcon, strlen(tcon), &tsid, SECSID_NULL, GFP_KERNEL);
    if (length)
        goto out;

    security_compute_av_user_with_policy(backup_sepolicy, ssid, tsid, tclass, &avd);
#elif defined(KSU_COMPAT_USE_SELINUX_STATE)
    length = security_context_str_to_sid(&fake_state, scon, &ssid, GFP_KERNEL);
    if (length)
        goto out;

    length = security_context_str_to_sid(&fake_state, tcon, &tsid, GFP_KERNEL);
    if (length)
        goto out;

    security_compute_av_user(&fake_state, ssid, tsid, tclass, &avd);
#else
    length = ksu_security_context_str_to_sid(scon, &ssid, GFP_KERNEL);
    if (length)
        goto out;

    length = ksu_security_context_str_to_sid(tcon, &tsid, GFP_KERNEL);
    if (length)
        goto out;

    ksu_security_compute_av_user(ssid, tsid, tclass, &avd);
#endif

    // stock reads 1; a loader load_policy may have bumped the backup before we load
    avd.seqno = 1;
    length = scnprintf(buf, SIMPLE_TRANSACTION_LIMIT, "%x %x %x %x %u %x", avd.allowed, 0xffffffff, avd.auditallow,
                       avd.auditdeny, avd.seqno, avd.flags);
out:
    kfree(tcon);
    kfree(scon);
    return length;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) && !defined(KSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE)
struct ksu_lsm_hook selinux_setprocattr_hook =
    KSU_LSM_HOOK_INIT(setprocattr, "selinux_setprocattr", ksu_handle_selinux_setprocattr, 0);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0) &&                                                                   \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0) || defined(KSU_COMPAT_HAS_LIST_OF_LSM_HOOKS))
static setprocattr_fn ksu_orig_setprocattr;
uintptr_t selinux_setprocattr_hook_ptr = 0;
#else
extern setprocattr_fn ksu_orig_setprocattr;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0) || defined(KSU_COMPAT_SETPROCATTR_USE_NEW_PROTOTYPE)
int __nocfi ksu_handle_selinux_setprocattr(const char *name, void *value, size_t size)
#else
int __nocfi ksu_handle_selinux_setprocattr(struct task_struct *p, char *name, void *value, size_t size)
#endif
{
    int error;
    u32 mysid, sid;
    char *str = value;
    if (likely(ksu_get_uid_t(current_uid()) < 10000)) {
        goto call_orig;
    }

    if (strcmp(name, "current")) {
        goto call_orig;
    }
    mysid = current_sid();

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
    error = avc_has_perm(mysid, mysid, SECCLASS_PROCESS, PROCESS__SETCURRENT, NULL);
#elif defined(KSU_COMPAT_USE_SELINUX_STATE)
    error = avc_has_perm(&selinux_state, mysid, mysid, SECCLASS_PROCESS, PROCESS__SETCURRENT, NULL);
#else
    error = avc_has_perm(mysid, mysid, SECCLASS_PROCESS, PROCESS__SETCURRENT, NULL);
#endif
    if (error) {
        return error;
    }

    if (size && str[0] && str[0] != '\n') {
        if (str[size - 1] == '\n') {
            str[size - 1] = 0;
            size--;
        }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
        error = security_context_to_sid_with_policy(backup_sepolicy, str, size, &sid, SECSID_NULL, GFP_KERNEL);
#elif defined(KSU_COMPAT_USE_SELINUX_STATE)
        error = security_context_to_sid(&fake_state, str, size, &sid, GFP_KERNEL);
#else
        error = ksu_security_context_to_sid(str, size, &sid, GFP_KERNEL);
#endif
        if (error) {
            return error;
        }
    }

call_orig:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    return ((setprocattr_fn)selinux_setprocattr_hook.original)(name, value, size);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0) || defined(KSU_COMPAT_SETPROCATTR_USE_NEW_PROTOTYPE)
    return ksu_orig_setprocattr(name, value, size);
#else
    return ksu_orig_setprocattr(p, name, value, size);
#endif
}

typedef int (*sel_open_handle_status_fn)(struct inode *inode, struct file *filp);
static sel_open_handle_status_fn orig_sel_open_handle_status, *sel_open_handle_status_slot;
static int my_sel_open_handle_status(struct inode *inode, struct file *filp)
{
    if (likely(ksu_get_uid_t(current_uid()) >= 10000 && ksu_selinux_hide_enabled)) {
        void *data;
        mutex_lock(ksu_selinux_status_lock);
        data = fake_status;
        mutex_unlock(ksu_selinux_status_lock);
        if (data) {
            filp->private_data = data;
            return 0;
        }
    }

    int ret = orig_sel_open_handle_status(inode, filp);
#ifdef KSU_COMPAT_USE_STATIC_KEY
    if (static_branch_unlikely(&fake_status_initialize_key) && !ret && !fake_status) {
        initialize_fake_status();
    }
#else
    if (!fake_status_initialize_key && !ret && !fake_status) {
        initialize_fake_status();
    }
#endif
    return ret;
}

static void hook_selinux_status_open()
{
    if (orig_sel_open_handle_status)
        return;
    if (!sel_open_handle_status_slot) {
#ifdef CONFIG_KALLSYMS_ALL
        struct file_operations *ops = (struct file_operations *)find_kernel_symbol_exact("sel_handle_status_ops");
#else
        extern struct file_operations sel_handle_status_ops;
        struct file_operations *ops = &sel_handle_status_ops;
#endif
        if (!ops) {
            pr_err("selinux_hide: sel_handle_status_ops not found, fake status will not work\n");
            return;
        }
        sel_open_handle_status_slot = &ops->open;
    }
    sel_open_handle_status_fn new_fn = my_sel_open_handle_status;
    orig_sel_open_handle_status = *sel_open_handle_status_slot;
    int ret = ksu_patch_text(sel_open_handle_status_slot, &new_fn, sizeof(new_fn), KSU_PATCH_TEXT_FLUSH_DCACHE);
    if (ret) {
        pr_err("selinux_hide: init: patch_text sel_open_handle_status err: %d\n", ret);
        sel_open_handle_status_slot = NULL;
        orig_sel_open_handle_status = NULL;
    }
}

extern void ksu_unregister_setprocattr_lsm_hook();

static void ksu_selinux_hide_unhook()
{
    int ret;
    if (orig_context_write) {
        ret =
            ksu_patch_text(context_write, &orig_context_write, sizeof(orig_context_write), KSU_PATCH_TEXT_FLUSH_DCACHE);
        orig_context_write = NULL;
        if (ret) {
            pr_err("selinux_hide: exit: patch_text context_write err: %d\n", ret);
        }
    }
    if (orig_access_write) {
        ret = ksu_patch_text(access_write, &orig_access_write, sizeof(orig_access_write), KSU_PATCH_TEXT_FLUSH_DCACHE);
        orig_access_write = NULL;
        if (ret) {
            pr_err("selinux_hide: exit: patch_text access_write err: %d\n", ret);
        }
    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    ksu_lsm_unhook(&selinux_setprocattr_hook);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0) || defined(KSU_COMPAT_HAS_LIST_OF_LSM_HOOKS)
    if (ksu_orig_setprocattr) {
        ret = ksu_patch_text((void *)selinux_setprocattr_hook_ptr, &ksu_orig_setprocattr, sizeof(ksu_orig_setprocattr),
                             KSU_PATCH_TEXT_FLUSH_DCACHE);
        ksu_orig_setprocattr = NULL;
        if (ret) {
            pr_err("selinux_hide: exit: patch_text setprocattr err: %d\n", ret);
        }
    }
#else
    stop_machine(ksu_unregister_setprocattr_lsm_hook, NULL, NULL);
#endif
}

extern void ksu_register_setprocattr_lsm_hook();
#else
#define ksu_selinux_hide_unhook()                                                                                      \
    do {                                                                                                               \
    } while (0)
#endif // #ifndef KSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE

static int ksu_selinux_hide_enable()
{
    int ret;
    pr_info("selinux_hide: init selinux hide\n");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) || defined(KSU_COMPAT_HAS_SELINUX_POLICY_STRUCT)
    if (!backup_sepolicy) {
        pr_err("no backup sepolicy available, please save feature and reboot to retry!\n");
        return -EAGAIN;
    }
#else
    if (!backup_policydb) {
        pr_err("no backup policydb available, please save feature and reboot to retry!\n");
        return -EAGAIN;
    }

    if (!backup_sidtab) {
        pr_err("no backup sidtab available, please save feature and reboot to retry!\n");
        return -EAGAIN;
    }
#endif

#ifndef KSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE
    hook_selinux_status_open();
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)

#ifdef CONFIG_KALLSYMS_ALL
    security_dump_masked_av_fn = find_kernel_symbol_exact("security_dump_masked_av");
    if (!security_dump_masked_av_fn) {
        pr_warn("security_dump_masked_av not found!\n");
    }
    context_struct_compute_av_fn = find_kernel_symbol_exact("context_struct_compute_av");
    if (!context_struct_compute_av_fn) {
        pr_warn("context_struct_compute_av not found!\n");
    }
#else
    extern void security_dump_masked_av(struct policydb * policydb, struct context * scontext,
                                        struct context * tcontext, u16 tclass, u32 permissions, const char *reason);
    extern void context_struct_compute_av(struct policydb * policydb, struct context * scontext,
                                          struct context * tcontext, u16 tclass, struct av_decision * avd,
                                          struct extended_perms * xperms);

    security_dump_masked_av_fn = &security_dump_masked_av;
    if (!security_dump_masked_av_fn) {
        pr_warn("security_dump_masked_av not found!\n");
    }

    context_struct_compute_av_fn = &context_struct_compute_av;
    if (!context_struct_compute_av_fn) {
        pr_warn("context_struct_compute_av not found!\n");
    }
#endif

#elif defined(KSU_COMPAT_USE_SELINUX_STATE)
    fake_state.initialized = true;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) || defined(KSU_COMPAT_HAS_SELINUX_POLICY_STRUCT)
    fake_state.policy = backup_sepolicy;
#else
    fake_state.ss = kzalloc(sizeof(*fake_state.ss), GFP_KERNEL);
    if (!fake_state.ss) {
        pr_err("selinux_hide: failed alloc selinux_ss!\n");
        return -ENOMEM;
    }

    rwlock_init(&fake_state.ss->policy_rwlock);

    // In normal android
    // Only set selinux policy once
    // So let's just hardcode to 1 to avoid avdSeqNo detect
    //
    // We manually reset latest_granting to 1, or will cause we may put an abnormal latest_granting to avdSeqNoeqNo
    // Because there will be called in any time, and i am too lazy move it to before apply_kernelsu_rules :)
    fake_state.ss->latest_granting = 1;

    // Replace policydb/sidtab with ourselves
    memcpy(&fake_state.ss->policydb, backup_policydb, sizeof(struct policydb));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0) || defined(KSU_COMPAT_SIDTAB_AS_REFERENCE)
    fake_state.ss->sidtab = backup_sidtab;
#else
    memcpy(&fake_state.ss->sidtab, backup_sidtab, sizeof(struct sidtab));
    kfree(backup_sidtab);
    backup_sidtab = NULL;
#endif
    kfree(backup_policydb);

    backup_policydb = NULL;
#endif // #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) || defined(KSU_COMPAT_HAS_SELINUX_POLICY_STRUCT)

#endif // #if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)

#ifndef KSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE
#ifdef CONFIG_KALLSYMS_ALL
    selinux_write_op = (write_op_fn *)find_kernel_symbol_exact("write_op");
#else
    extern ssize_t (*const write_op[])(struct file *, char *, size_t);

    selinux_write_op = (write_op_fn *)&write_op;
#endif
    if (!selinux_write_op) {
        pr_err("selinux_hide: no write_op found!\n");
        return -ENOSYS;
    }

    context_write = &selinux_write_op[SEL_CONTEXT];
    pr_info("selinux_hide: context_write: 0x%lx [%pSb]\n", (unsigned long)*context_write, *context_write);
    write_op_fn my = my_write_context;
    orig_context_write = *context_write;
    ret = ksu_patch_text(context_write, &my, sizeof(my), KSU_PATCH_TEXT_FLUSH_DCACHE);
    if (ret) {
        pr_err("selinux_hide: init: patch_text context_write err: %d\n", ret);
        goto unhook;
    }

    access_write = &selinux_write_op[SEL_ACCESS];
    pr_info("selinux_hide: access_write: 0x%lx [%pSb]\n", (unsigned long)*access_write, *access_write);
    my = my_write_access;
    orig_access_write = *access_write;
    ret = ksu_patch_text(access_write, &my, sizeof(my), KSU_PATCH_TEXT_FLUSH_DCACHE);
    if (ret) {
        pr_err("selinux_hide: init: patch_text access_write err: %d\n", ret);
        goto unhook;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    ret = ksu_lsm_hook(&selinux_setprocattr_hook);
    if (ret) {
        pr_err("selinux_hide: init: selinux_setprocattr_hook err: %d\n", ret);
        goto unhook;
    }
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0) || defined(KSU_COMPAT_HAS_LIST_OF_LSM_HOOKS)
    struct security_hook_list *hp;

    // https://github.com/torvalds/linux/commit/df0ce17331e2501dbffc060041dfc6c5f85227b5
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0) || defined(KSU_COMPAT_HLIST_FOR_SECURITY_HOOK_LIST)
#define ksu_for_each_lsm_entry hlist_for_each_entry
#else
#define ksu_for_each_lsm_entry list_for_each_entry
#endif

    ksu_for_each_lsm_entry(hp, &security_hook_heads.setprocattr, list)
    {
        // https://github.com/torvalds/linux/commit/d69dece5f5b6bc7a5e39d2b6136ddc69469331fe
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0) || defined(KSU_COMPAT_REQUIRE_PROVIDE_LSM_NAME)
        // when we are in 4.11+, we can ensure we are control "selinux" LSM by that
        if (strcmp("selinux", hp->lsm))
            continue;
#endif // #if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
        selinux_setprocattr_hook_ptr = (unsigned long)&hp->hook.setprocattr;
        ksu_orig_setprocattr = hp->hook.setprocattr;
        setprocattr_fn my_setprocattr = ksu_handle_selinux_setprocattr;
        ret =
            ksu_patch_text(&hp->hook.setprocattr, &my_setprocattr, sizeof(my_setprocattr), KSU_PATCH_TEXT_FLUSH_DCACHE);
        if (ret) {
            pr_err("selinux_hide: init: patch_text selinux setprocattr err: %d\n", ret);
            goto unhook;
        }
        goto out;
    }

#undef ksu_for_each_lsm_entry
out:
#else
    // for 4.2-, We handle it in lsm_hooks.c

    stop_machine(ksu_register_setprocattr_lsm_hook, NULL, NULL);
#endif // #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)

#endif // #ifndef KSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE

    return 0;

#ifndef KSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE
unhook:
#endif
    ksu_selinux_hide_unhook();
    return -ENOSYS;
}

static void ksu_selinux_hide_disable()
{
    pr_info("selinux_hide: exit selinux hide\n");

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0) && defined(KSU_COMPAT_USE_SELINUX_STATE) &&                          \
    !defined(KSU_COMPAT_HAS_SELINUX_POLICY_STRUCT)
    backup_policydb = kzalloc(sizeof(*backup_policydb), GFP_KERNEL);
    memcpy(backup_policydb, &fake_state.ss->policydb, sizeof(struct policydb));

    // 5.0+ backup_sidtab share memory with fake_state, so we doesn't replace to NULL in lifetime
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0) && !defined(KSU_COMPAT_SIDTAB_AS_REFERENCE)
    backup_sidtab = kzalloc(sizeof(*backup_sidtab), GFP_KERNEL);
    memcpy(backup_sidtab, &fake_state.ss->sidtab, sizeof(struct sidtab));
#endif

#endif

    ksu_selinux_hide_unhook();
}

static int selinux_hide_feature_get(u64 *value)
{
    *value = ksu_selinux_hide_enabled ? 1 : 0;
    return 0;
}

static int selinux_hide_feature_set(u64 value)
{
    bool enable = value != 0;
    int ret = 0;
    pr_info("selinux_hide: set to %d\n", enable);
    mutex_lock(&selinux_hide_mutex);
    ksu_selinux_hide_enabled = enable;
    if (enable) {
        if (!ksu_selinux_hide_running) {
            ret = ksu_selinux_hide_enable();
            if (!ret) {
                ksu_selinux_hide_running = true;
            }
        }
    } else {
        if (ksu_selinux_hide_running) {
            ksu_selinux_hide_disable();
            ksu_selinux_hide_running = false;
        }
    }
    mutex_unlock(&selinux_hide_mutex);
    return ret;
}

static const struct ksu_feature_handler selinux_hide_handler = {
    .feature_id = KSU_FEATURE_SELINUX_HIDE,
    .name = "selinux_hide",
    .get_handler = selinux_hide_feature_get,
    .set_handler = selinux_hide_feature_set,
};

void ksu_selinux_hide_handle_second_stage()
{
    initialize_fake_status();
    // https://github.com/torvalds/linux/blame/e8c2f9fdadee7cbc75134dc463c1e0d856d6e5c7/security/selinux/selinuxfs.c#L2014
    if (fake_status) {
#ifdef KSU_COMPAT_USE_STATIC_KEY
        static_key_disable(&fake_status_initialize_key.key);
#else
        fake_status_initialize_key = true;
#endif
    } else {
        pr_warn("selinux_hide: fake status need late initialization\n");
    }
}

void ksu_selinux_hide_handle_post_fs_data()
{
#ifdef KSU_COMPAT_USE_STATIC_KEY
    static_key_disable(&fake_status_initialize_key.key);
#else
    fake_status_initialize_key = true;
#endif
    if (!fake_status) {
        pr_err("selinux_hide: fake status is not initialized after post-fs-data!\n");
    }
}

void __init ksu_selinux_hide_init()
{
    if (ksu_register_feature_handler(&selinux_hide_handler)) {
        pr_err("Failed to register selinux_hide feature handler\n");
    }
    if (ksu_late_loaded) {
        initialize_fake_status();
    } else {
#ifdef KSU_COMPAT_USE_STATIC_KEY
        static_key_enable(&fake_status_initialize_key.key);
#else
        fake_status_initialize_key = false;
#endif
    }
#ifndef KSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE
    hook_selinux_status_open();
#endif
}

void __exit ksu_selinux_hide_exit()
{
    mutex_lock(&selinux_hide_mutex);
    if (ksu_selinux_hide_running) {
        ksu_selinux_hide_disable();
        ksu_selinux_hide_running = false;
    }
    mutex_unlock(&selinux_hide_mutex);
    ksu_unregister_feature_handler(KSU_FEATURE_SELINUX_HIDE);
    mutex_lock(ksu_selinux_status_lock);
    if (fake_status)
        __free_page(fake_status);
    fake_status = NULL;
    mutex_unlock(ksu_selinux_status_lock);
}

void ksu_selinux_hide_drop_backup_if_unused()
{
    mutex_lock(&selinux_hide_mutex);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) || defined(KSU_COMPAT_HAS_SELINUX_POLICY_STRUCT)
    if (!ksu_selinux_hide_running && backup_sepolicy) {
        pr_info("selinux_hide is not enabled - drop backup_sepolicy\n");
        sidtab_destroy(backup_sepolicy->sidtab);
        kfree(backup_sepolicy->sidtab);
        ksu_destroy_sepolicy(backup_sepolicy);
        backup_sepolicy = NULL;
    }
#elif defined(KSU_COMPAT_USE_SELINUX_STATE)
    if (!ksu_selinux_hide_running && backup_policydb && backup_sidtab) {
        pr_info("selinux_hide is not enabled - drop backup_policydb\n");
        sidtab_destroy(backup_sidtab);
        kfree(backup_sidtab);
        ksu_destroy_policydb(backup_policydb);
        kfree(backup_policydb);
        backup_policydb = NULL;
        backup_sidtab = NULL;
    }
#else
    if (!ksu_selinux_hide_running && backup_policydb && backup_sidtab) {
        sidtab_destroy(backup_sidtab);
        kfree(backup_sidtab);
        ksu_destroy_policydb(backup_policydb);
        kfree(backup_policydb);
        backup_policydb = NULL;
        backup_sidtab = NULL;
    }
#endif
    mutex_unlock(&selinux_hide_mutex);
}

// for susfs xN
__maybe_static void initialize_fake_status()
{
    // https://github.com/torvalds/linux/commit/4b36cb773a8153417a080f8025d522322f915aea
#if LINUX_VERSION_CODE > KERNEL_VERSION(5, 7, 0) || defined(KSU_COMPAT_SELINUX_STATUS_VAR_IN_SELINUX_STATE)
    ksu_selinux_status_lock = &selinux_state.status_lock;
#elif defined(KSU_COMPAT_USE_SELINUX_STATE)
    ksu_selinux_status_lock = &selinux_state.ss->status_lock;
#elif defined(CONFIG_KALLSYMS_ALL)
    // call ksu_resolve_symbol_for_functable_hook to search selinux_status_lock
    // because some compiler add suffix for that
    // e.g:
    // 0000000000000000 b selinux_status_lock.llvm.9985633631847037644
    ksu_selinux_status_lock = (struct mutex *)ksu_resolve_symbol_for_functable_hook("selinux_status_lock");
#else
    extern struct mutex selinux_status_lock;
    ksu_selinux_status_lock = &selinux_status_lock;
#endif

    mutex_lock(ksu_selinux_status_lock);
    if (fake_status)
        goto out;

#if LINUX_VERSION_CODE > KERNEL_VERSION(5, 7, 0) || defined(KSU_COMPAT_SELINUX_STATUS_VAR_IN_SELINUX_STATE)
    struct page *selinux_status_page = selinux_state.status_page;
#elif defined(KSU_COMPAT_USE_SELINUX_STATE)
    struct page *selinux_status_page = selinux_state.ss->status_page;
#elif defined(CONFIG_KALLSYMS_ALL)
    // call ksu_resolve_symbol_for_functable_hook to search selinux_status_page
    // because some compiler add suffix for that
    // e.g:
    // 0000000000000000 b selinux_status_page.llvm.9985633631847037644
    struct page *selinux_status_page = *((struct page **)ksu_resolve_symbol_for_functable_hook("selinux_status_page"));
#else
    extern struct page *selinux_status_page;
#endif

    if (!selinux_status_page) {
        pr_warn("initialize_fake_status: status_page not exist\n");
        goto out;
    }

    struct selinux_kernel_status *status = page_address(selinux_status_page);
    if (!status->enforcing && !ksu_late_loaded) {
        pr_warn("initialize_fake_status: skip not enforcing\n");
        goto out;
    }

    struct page *new_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
    if (!new_page) {
        pr_err("initialize_fake_status: failed to allocate page\n");
        goto out;
    }

    struct selinux_kernel_status *new_status = page_address(new_page);
    memcpy(new_status, status, sizeof(*status));
    if (ksu_late_loaded) {
        // In late_load mode the loader may have reloaded sepolicy before us,
        // so the captured page is not stock. Serve what a stock boot ends
        // with instead: creation sentinel below 6.10, one load plus one
        // setenforce above.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 10, 0)
        new_status->sequence = 4;
        new_status->policyload = 1;
#else
        new_status->sequence = 0;
        new_status->policyload = 0;
#endif
        if (!new_status->enforcing) {
            new_status->enforcing = 1;
        }
    }

    fake_status = new_page;
    pr_info("initialize_fake_status initialized: sequence=%d, policyload=%d, enforcing=%d\n", new_status->sequence,
            new_status->policyload, new_status->enforcing);

out:
    mutex_unlock(ksu_selinux_status_lock);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
/*
 * Caveat:  Mutates scontext.
 */
static int string_to_context_struct(struct policydb *pol, struct sidtab *sidtabp, char *scontext, struct context *ctx,
                                    u32 def_sid)
{
    struct role_datum *role;
    struct type_datum *typdatum;
    struct user_datum *usrdatum;
    char *scontextp, *p, oldc;
    int rc = 0;

    context_init(ctx);

    /* Parse the security context. */

    rc = -EINVAL;
    scontextp = scontext;

    /* Extract the user. */
    p = scontextp;
    while (*p && *p != ':')
        p++;

    if (*p == 0)
        goto out;

    *p++ = 0;

    usrdatum = symtab_search(&pol->p_users, scontextp);
    if (!usrdatum)
        goto out;

    ctx->user = usrdatum->value;

    /* Extract role. */
    scontextp = p;
    while (*p && *p != ':')
        p++;

    if (*p == 0)
        goto out;

    *p++ = 0;

    role = symtab_search(&pol->p_roles, scontextp);
    if (!role)
        goto out;
    ctx->role = role->value;

    /* Extract type. */
    scontextp = p;
    while (*p && *p != ':')
        p++;
    oldc = *p;
    *p++ = 0;

    typdatum = symtab_search(&pol->p_types, scontextp);
    if (!typdatum || typdatum->attribute)
        goto out;

    ctx->type = typdatum->value;

    rc = mls_context_to_sid(pol, oldc, p, ctx, sidtabp, def_sid);
    if (rc)
        goto out;

    /* Check the validity of the new context. */
    rc = -EINVAL;
    if (!policydb_context_isvalid(pol, ctx))
        goto out;
    rc = 0;
out:
    if (rc)
        context_destroy(ctx);
    return rc;
}

// remove static in susfs
__maybe_static int security_context_to_sid_with_policy(struct selinux_policy *policy, const char *scontext,
                                                       u32 scontext_len, u32 *sid, u32 def_sid, gfp_t gfp_flags)
{
    struct policydb *policydb;
    struct sidtab *sidtab;
    char *scontext2, *str = NULL;
    struct context context;
    int rc = 0;

    /* An empty security context is never valid. */
    if (!scontext_len)
        return -EINVAL;

    /* Copy the string to allow changes and ensure a NUL terminator */
    scontext2 = kmemdup_nul(scontext, scontext_len, gfp_flags);
    if (!scontext2)
        return -ENOMEM;

    // removed: if (!selinux_initialized())
    *sid = SECSID_NULL;

    // removed: if (force)
    // removed: rcu lock
    policydb = &policy->policydb;
    sidtab = policy->sidtab;
    rc = string_to_context_struct(policydb, sidtab, scontext2, &context, def_sid);
    if (rc)
        goto out;
    rc = sidtab_context_to_sid(sidtab, &context, sid);
    // rc should not be frozen
    if (rc)
        goto out;
    // removed: if (rc == -ESTALE)
    context_destroy(&context);
out:
    kfree(scontext2);
    kfree(str);
    return rc;
}

/*
 * Write the security context string representation of
 * the context structure `context' into a dynamically
 * allocated string of the correct size.  Set `*scontext'
 * to point to this string and set `*scontext_len' to
 * the length of the string.
 */
static int context_struct_to_string(struct policydb *p, struct context *context, char **scontext, u32 *scontext_len)
{
    char *scontextp;

    if (scontext)
        *scontext = NULL;
    *scontext_len = 0;

    if (context->len) {
        *scontext_len = context->len;
        if (scontext) {
            *scontext = kstrdup(context->str, GFP_ATOMIC);
            if (!(*scontext))
                return -ENOMEM;
        }
        return 0;
    }

    /* Compute the size of the context. */
    *scontext_len += strlen(sym_name(p, SYM_USERS, context->user - 1)) + 1;
    *scontext_len += strlen(sym_name(p, SYM_ROLES, context->role - 1)) + 1;
    *scontext_len += strlen(sym_name(p, SYM_TYPES, context->type - 1)) + 1;
    *scontext_len += mls_compute_context_len(p, context);

    if (!scontext)
        return 0;

    /* Allocate space for the context; caller must free this space. */
    scontextp = kmalloc(*scontext_len, GFP_ATOMIC);
    if (!scontextp)
        return -ENOMEM;
    *scontext = scontextp;

    /*
     * Copy the user name, role name and type name into the context.
     */
    scontextp += sprintf(scontextp, "%s:%s:%s", sym_name(p, SYM_USERS, context->user - 1),
                         sym_name(p, SYM_ROLES, context->role - 1), sym_name(p, SYM_TYPES, context->type - 1));

    mls_sid_to_context(p, context, &scontextp);

    *scontextp = 0;

    return 0;
}

static int sidtab_entry_to_string(struct policydb *p, struct sidtab *sidtab, struct sidtab_entry *entry,
                                  char **scontext, u32 *scontext_len)
{
    int rc = sidtab_sid2str_get(sidtab, entry, scontext, scontext_len);

    if (rc != -ENOENT)
        return rc;

    rc = context_struct_to_string(p, &entry->context, scontext, scontext_len);
    if (!rc && scontext)
        sidtab_sid2str_put(sidtab, entry, *scontext, *scontext_len);
    return rc;
}

// remove static in susfs
__maybe_static int security_sid_to_context_with_policy(struct selinux_policy *policy, u32 sid, char **scontext,
                                                       u32 *scontext_len)
{
    struct policydb *policydb;
    struct sidtab *sidtab;
    struct sidtab_entry *entry;
    int rc = 0;

    if (scontext)
        *scontext = NULL;
    *scontext_len = 0;

    // removed: if (!selinux_initialized())
    // removed: rcu lock
    policydb = &policy->policydb;
    sidtab = policy->sidtab;

    // removed: force
    entry = sidtab_search_entry(sidtab, sid);
    if (!entry) {
        pr_err("SELinux: %s:  unrecognized SID %d\n", __func__, sid);
        rc = -EINVAL;
        goto out_unlock;
    }
    // removed: only_invalid

    rc = sidtab_entry_to_string(policydb, sidtab, entry, scontext, scontext_len);

out_unlock:
    return rc;
}

static void avd_init(struct selinux_policy *policy, struct av_decision *avd)
{
    avd->allowed = 0;
    avd->auditallow = 0;
    avd->auditdeny = 0xffffffff;
    if (policy)
        avd->seqno = policy->latest_granting;
    else
        avd->seqno = 0;
    avd->flags = 0;
}

static void context_struct_compute_av(struct policydb *policydb, struct context *scontext, struct context *tcontext,
                                      u16 tclass, struct av_decision *avd, struct extended_perms *xperms);

/*
 * security_boundary_permission - drops violated permissions
 * on boundary constraint.
 */
static void __nocfi type_attribute_bounds_av(struct policydb *policydb, struct context *scontext,
                                             struct context *tcontext, u16 tclass, struct av_decision *avd)
{
    struct context lo_scontext;
    struct context lo_tcontext, *tcontextp = tcontext;
    struct av_decision lo_avd;
    struct type_datum *source;
    struct type_datum *target;
    u32 masked = 0;

    source = policydb->type_val_to_struct[scontext->type - 1];
    BUG_ON(!source);

    if (!source->bounds)
        return;

    target = policydb->type_val_to_struct[tcontext->type - 1];
    BUG_ON(!target);

    memset(&lo_avd, 0, sizeof(lo_avd));

    memcpy(&lo_scontext, scontext, sizeof(lo_scontext));
    lo_scontext.type = source->bounds;

    if (target->bounds) {
        memcpy(&lo_tcontext, tcontext, sizeof(lo_tcontext));
        lo_tcontext.type = target->bounds;
        tcontextp = &lo_tcontext;
    }

    context_struct_compute_av(policydb, &lo_scontext, tcontextp, tclass, &lo_avd, NULL);

    masked = ~lo_avd.allowed & avd->allowed;

    if (likely(!masked))
        return; /* no masked permission */

    /* mask violated permissions */
    avd->allowed &= ~masked;

    /* audit masked permissions */
    if (security_dump_masked_av_fn)
        security_dump_masked_av_fn(policydb, scontext, tcontext, tclass, masked, "bounds");
}

/*
 * Return the boolean value of a constraint expression
 * when it is applied to the specified source and target
 * security contexts.
 *
 * xcontext is a special beast...  It is used by the validatetrans rules
 * only.  For these rules, scontext is the context before the transition,
 * tcontext is the context after the transition, and xcontext is the context
 * of the process performing the transition.  All other callers of
 * constraint_expr_eval should pass in NULL for xcontext.
 */
static int constraint_expr_eval(struct policydb *policydb, struct context *scontext, struct context *tcontext,
                                struct context *xcontext, struct constraint_expr *cexpr)
{
    u32 val1, val2;
    struct context *c;
    struct role_datum *r1, *r2;
    struct mls_level *l1, *l2;
    struct constraint_expr *e;
    int s[CEXPR_MAXDEPTH];
    int sp = -1;

    for (e = cexpr; e; e = e->next) {
        switch (e->expr_type) {
        case CEXPR_NOT:
            BUG_ON(sp < 0);
            s[sp] = !s[sp];
            break;
        case CEXPR_AND:
            BUG_ON(sp < 1);
            sp--;
            s[sp] &= s[sp + 1];
            break;
        case CEXPR_OR:
            BUG_ON(sp < 1);
            sp--;
            s[sp] |= s[sp + 1];
            break;
        case CEXPR_ATTR:
            if (sp == (CEXPR_MAXDEPTH - 1))
                return 0;
            switch (e->attr) {
            case CEXPR_USER:
                val1 = scontext->user;
                val2 = tcontext->user;
                break;
            case CEXPR_TYPE:
                val1 = scontext->type;
                val2 = tcontext->type;
                break;
            case CEXPR_ROLE:
                val1 = scontext->role;
                val2 = tcontext->role;
                r1 = policydb->role_val_to_struct[val1 - 1];
                r2 = policydb->role_val_to_struct[val2 - 1];
                switch (e->op) {
                case CEXPR_DOM:
                    s[++sp] = ebitmap_get_bit(&r1->dominates, val2 - 1);
                    continue;
                case CEXPR_DOMBY:
                    s[++sp] = ebitmap_get_bit(&r2->dominates, val1 - 1);
                    continue;
                case CEXPR_INCOMP:
                    s[++sp] =
                        (!ebitmap_get_bit(&r1->dominates, val2 - 1) && !ebitmap_get_bit(&r2->dominates, val1 - 1));
                    continue;
                default:
                    break;
                }
                break;
            case CEXPR_L1L2:
                l1 = &(scontext->range.level[0]);
                l2 = &(tcontext->range.level[0]);
                goto mls_ops;
            case CEXPR_L1H2:
                l1 = &(scontext->range.level[0]);
                l2 = &(tcontext->range.level[1]);
                goto mls_ops;
            case CEXPR_H1L2:
                l1 = &(scontext->range.level[1]);
                l2 = &(tcontext->range.level[0]);
                goto mls_ops;
            case CEXPR_H1H2:
                l1 = &(scontext->range.level[1]);
                l2 = &(tcontext->range.level[1]);
                goto mls_ops;
            case CEXPR_L1H1:
                l1 = &(scontext->range.level[0]);
                l2 = &(scontext->range.level[1]);
                goto mls_ops;
            case CEXPR_L2H2:
                l1 = &(tcontext->range.level[0]);
                l2 = &(tcontext->range.level[1]);
                goto mls_ops;
            mls_ops:
                switch (e->op) {
                case CEXPR_EQ:
                    s[++sp] = mls_level_eq(l1, l2);
                    continue;
                case CEXPR_NEQ:
                    s[++sp] = !mls_level_eq(l1, l2);
                    continue;
                case CEXPR_DOM:
                    s[++sp] = mls_level_dom(l1, l2);
                    continue;
                case CEXPR_DOMBY:
                    s[++sp] = mls_level_dom(l2, l1);
                    continue;
                case CEXPR_INCOMP:
                    s[++sp] = mls_level_incomp(l2, l1);
                    continue;
                default:
                    BUG();
                    return 0;
                }
                break;
            default:
                BUG();
                return 0;
            }

            switch (e->op) {
            case CEXPR_EQ:
                s[++sp] = (val1 == val2);
                break;
            case CEXPR_NEQ:
                s[++sp] = (val1 != val2);
                break;
            default:
                BUG();
                return 0;
            }
            break;
        case CEXPR_NAMES:
            if (sp == (CEXPR_MAXDEPTH - 1))
                return 0;
            c = scontext;
            if (e->attr & CEXPR_TARGET)
                c = tcontext;
            else if (e->attr & CEXPR_XTARGET) {
                c = xcontext;
                if (!c) {
                    BUG();
                    return 0;
                }
            }
            if (e->attr & CEXPR_USER)
                val1 = c->user;
            else if (e->attr & CEXPR_ROLE)
                val1 = c->role;
            else if (e->attr & CEXPR_TYPE)
                val1 = c->type;
            else {
                BUG();
                return 0;
            }

            switch (e->op) {
            case CEXPR_EQ:
                s[++sp] = ebitmap_get_bit(&e->names, val1 - 1);
                break;
            case CEXPR_NEQ:
                s[++sp] = !ebitmap_get_bit(&e->names, val1 - 1);
                break;
            default:
                BUG();
                return 0;
            }
            break;
        default:
            BUG();
            return 0;
        }
    }

    BUG_ON(sp != 0);
    return s[0];
}

/*
 * Compute access vectors and extended permissions based on a context
 * structure pair for the permissions in a particular class.
 */
static void context_struct_compute_av(struct policydb *policydb, struct context *scontext, struct context *tcontext,
                                      u16 tclass, struct av_decision *avd, struct extended_perms *xperms)
{
    struct constraint_node *constraint;
    struct role_allow *ra;
    struct avtab_key avkey;
    struct avtab_node *node;
    struct class_datum *tclass_datum;
    struct ebitmap *sattr, *tattr;
    struct ebitmap_node *snode, *tnode;
    unsigned int i, j;

    avd->allowed = 0;
    avd->auditallow = 0;
    avd->auditdeny = 0xffffffff;
    if (xperms) {
        memset(&xperms->drivers, 0, sizeof(xperms->drivers));
        xperms->len = 0;
    }

    if (unlikely(!tclass || tclass > policydb->p_classes.nprim)) {
        pr_warn_ratelimited("SELinux:  Invalid class %u\n", tclass);
        return;
    }

    tclass_datum = policydb->class_val_to_struct[tclass - 1];

    /*
     * If a specific type enforcement rule was defined for
     * this permission check, then use it.
     */
    avkey.target_class = tclass;
    avkey.specified = AVTAB_AV | AVTAB_XPERMS;
    sattr = &policydb->type_attr_map_array[scontext->type - 1];
    tattr = &policydb->type_attr_map_array[tcontext->type - 1];
    ebitmap_for_each_positive_bit(sattr, snode, i)
    {
        ebitmap_for_each_positive_bit(tattr, tnode, j)
        {
            avkey.source_type = i + 1;
            avkey.target_type = j + 1;
            for (node = avtab_search_node(&policydb->te_avtab, &avkey); node;
                 node = avtab_search_node_next(node, avkey.specified)) {
                if (node->key.specified == AVTAB_ALLOWED)
                    avd->allowed |= node->datum.u.data;
                else if (node->key.specified == AVTAB_AUDITALLOW)
                    avd->auditallow |= node->datum.u.data;
                else if (node->key.specified == AVTAB_AUDITDENY)
                    avd->auditdeny &= node->datum.u.data;
                else if (xperms && (node->key.specified & AVTAB_XPERMS))
                    services_compute_xperms_drivers(xperms, node);
            }

            /* Check conditional av table for additional permissions */
            cond_compute_av(&policydb->te_cond_avtab, &avkey, avd, xperms);
        }
    }

    /*
     * Remove any permissions prohibited by a constraint (this includes
     * the MLS policy).
     */
    constraint = tclass_datum->constraints;
    while (constraint) {
        if ((constraint->permissions & (avd->allowed)) &&
            !constraint_expr_eval(policydb, scontext, tcontext, NULL, constraint->expr)) {
            avd->allowed &= ~(constraint->permissions);
        }
        constraint = constraint->next;
    }

    /*
     * If checking process transition permission and the
     * role is changing, then check the (current_role, new_role)
     * pair.
     */
    if (tclass == policydb->process_class && (avd->allowed & policydb->process_trans_perms) &&
        scontext->role != tcontext->role) {
        for (ra = policydb->role_allow; ra; ra = ra->next) {
            if (scontext->role == ra->role && tcontext->role == ra->new_role)
                break;
        }
        if (!ra)
            avd->allowed &= ~policydb->process_trans_perms;
    }

    /*
     * If the given source and target types have boundary
     * constraint, lazy checks have to mask any violated
     * permission and notice it to userspace via audit.
     */
    type_attribute_bounds_av(policydb, scontext, tcontext, tclass, avd);
}

// remove static in susfs
__maybe_static void __nocfi security_compute_av_user_with_policy(struct selinux_policy *policy, u32 ssid, u32 tsid,
                                                                 u16 tclass, struct av_decision *avd)
{
    struct policydb *policydb;
    struct sidtab *sidtab;
    struct context *scontext = NULL, *tcontext = NULL;

    // remove: rcu lock
    avd_init(policy, avd);
    // remove: if (!selinux_initialized())

    policydb = &policy->policydb;
    sidtab = policy->sidtab;

    scontext = sidtab_search(sidtab, ssid);
    if (!scontext) {
        pr_err("SELinux: %s:  unrecognized SID %d\n", __func__, ssid);
        goto out;
    }

    /* permissive domain? */
    if (ebitmap_get_bit(&policydb->permissive_map, scontext->type))
        avd->flags |= AVD_FLAGS_PERMISSIVE;

    tcontext = sidtab_search(sidtab, tsid);
    if (!tcontext) {
        pr_err("SELinux: %s:  unrecognized SID %d\n", __func__, tsid);
        goto out;
    }

    if (unlikely(!tclass)) {
        if (policydb->allow_unknown)
            goto allow;
        goto out;
    }

    if (context_struct_compute_av_fn) {
        context_struct_compute_av_fn(policydb, scontext, tcontext, tclass, avd, NULL);
    } else {
        context_struct_compute_av(policydb, scontext, tcontext, tclass, avd, NULL);
    }
out:
    return;
allow:
    avd->allowed = 0xffffffff;
    goto out;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0) && !defined(KSU_COMPAT_USE_SELINUX_STATE)
static int dump_masked_av_helper(void *k, void *d, void *args)
{
    struct perm_datum *pdatum = d;
    char **permission_names = args;

    BUG_ON(pdatum->value < 1 || pdatum->value > 32);

    permission_names[pdatum->value - 1] = (char *)k;

    return 0;
}

static void security_dump_masked_av(struct context *scontext, struct context *tcontext, u16 tclass, u32 permissions,
                                    const char *reason)
{
    struct common_datum *common_dat;
    struct class_datum *tclass_dat;
    struct audit_buffer *ab;
    char *tclass_name;
    char *scontext_name = NULL;
    char *tcontext_name = NULL;
    char *permission_names[32];
    int index;
    u32 length;
    bool need_comma = false;

    if (!permissions)
        return;

    tclass_name = sym_name(backup_policydb, SYM_CLASSES, tclass - 1);
    tclass_dat = backup_policydb->class_val_to_struct[tclass - 1];
    common_dat = tclass_dat->comdatum;

    /* init permission_names */
    if (common_dat && hashtab_map(common_dat->permissions.table, dump_masked_av_helper, permission_names) < 0)
        goto out;

    if (hashtab_map(tclass_dat->permissions.table, dump_masked_av_helper, permission_names) < 0)
        goto out;

    /* get scontext/tcontext in text form */
    if (context_struct_to_string(scontext, &scontext_name, &length) < 0)
        goto out;

    if (context_struct_to_string(tcontext, &tcontext_name, &length) < 0)
        goto out;

    /* audit a message */
    ab = audit_log_start(current->audit_context, GFP_ATOMIC, AUDIT_SELINUX_ERR);
    if (!ab)
        goto out;

    audit_log_format(ab,
                     "op=security_compute_av reason=%s "
                     "scontext=%s tcontext=%s tclass=%s perms=",
                     reason, scontext_name, tcontext_name, tclass_name);

    for (index = 0; index < 32; index++) {
        u32 mask = (1 << index);

        if ((mask & permissions) == 0)
            continue;

        audit_log_format(ab, "%s%s", need_comma ? "," : "", permission_names[index] ? permission_names[index] : "????");
        need_comma = true;
    }
    audit_log_end(ab);
out:
    /* release scontext/tcontext */
    kfree(tcontext_name);
    kfree(scontext_name);

    return;
}

static int constraint_expr_eval(struct context *scontext, struct context *tcontext, struct context *xcontext,
                                struct constraint_expr *cexpr)
{
    u32 val1, val2;
    struct context *c;
    struct role_datum *r1, *r2;
    struct mls_level *l1, *l2;
    struct constraint_expr *e;
    int s[CEXPR_MAXDEPTH];
    int sp = -1;

    for (e = cexpr; e; e = e->next) {
        switch (e->expr_type) {
        case CEXPR_NOT:
            BUG_ON(sp < 0);
            s[sp] = !s[sp];
            break;
        case CEXPR_AND:
            BUG_ON(sp < 1);
            sp--;
            s[sp] &= s[sp + 1];
            break;
        case CEXPR_OR:
            BUG_ON(sp < 1);
            sp--;
            s[sp] |= s[sp + 1];
            break;
        case CEXPR_ATTR:
            if (sp == (CEXPR_MAXDEPTH - 1))
                return 0;
            switch (e->attr) {
            case CEXPR_USER:
                val1 = scontext->user;
                val2 = tcontext->user;
                break;
            case CEXPR_TYPE:
                val1 = scontext->type;
                val2 = tcontext->type;
                break;
            case CEXPR_ROLE:
                val1 = scontext->role;
                val2 = tcontext->role;
                r1 = backup_policydb->role_val_to_struct[val1 - 1];
                r2 = backup_policydb->role_val_to_struct[val2 - 1];
                switch (e->op) {
                case CEXPR_DOM:
                    s[++sp] = ebitmap_get_bit(&r1->dominates, val2 - 1);
                    continue;
                case CEXPR_DOMBY:
                    s[++sp] = ebitmap_get_bit(&r2->dominates, val1 - 1);
                    continue;
                case CEXPR_INCOMP:
                    s[++sp] =
                        (!ebitmap_get_bit(&r1->dominates, val2 - 1) && !ebitmap_get_bit(&r2->dominates, val1 - 1));
                    continue;
                default:
                    break;
                }
                break;
            case CEXPR_L1L2:
                l1 = &(scontext->range.level[0]);
                l2 = &(tcontext->range.level[0]);
                goto mls_ops;
            case CEXPR_L1H2:
                l1 = &(scontext->range.level[0]);
                l2 = &(tcontext->range.level[1]);
                goto mls_ops;
            case CEXPR_H1L2:
                l1 = &(scontext->range.level[1]);
                l2 = &(tcontext->range.level[0]);
                goto mls_ops;
            case CEXPR_H1H2:
                l1 = &(scontext->range.level[1]);
                l2 = &(tcontext->range.level[1]);
                goto mls_ops;
            case CEXPR_L1H1:
                l1 = &(scontext->range.level[0]);
                l2 = &(scontext->range.level[1]);
                goto mls_ops;
            case CEXPR_L2H2:
                l1 = &(tcontext->range.level[0]);
                l2 = &(tcontext->range.level[1]);
                goto mls_ops;
            mls_ops:
                switch (e->op) {
                case CEXPR_EQ:
                    s[++sp] = mls_level_eq(l1, l2);
                    continue;
                case CEXPR_NEQ:
                    s[++sp] = !mls_level_eq(l1, l2);
                    continue;
                case CEXPR_DOM:
                    s[++sp] = mls_level_dom(l1, l2);
                    continue;
                case CEXPR_DOMBY:
                    s[++sp] = mls_level_dom(l2, l1);
                    continue;
                case CEXPR_INCOMP:
                    s[++sp] = mls_level_incomp(l2, l1);
                    continue;
                default:
                    BUG();
                    return 0;
                }
                break;
            default:
                BUG();
                return 0;
            }

            switch (e->op) {
            case CEXPR_EQ:
                s[++sp] = (val1 == val2);
                break;
            case CEXPR_NEQ:
                s[++sp] = (val1 != val2);
                break;
            default:
                BUG();
                return 0;
            }
            break;
        case CEXPR_NAMES:
            if (sp == (CEXPR_MAXDEPTH - 1))
                return 0;
            c = scontext;
            if (e->attr & CEXPR_TARGET)
                c = tcontext;
            else if (e->attr & CEXPR_XTARGET) {
                c = xcontext;
                if (!c) {
                    BUG();
                    return 0;
                }
            }
            if (e->attr & CEXPR_USER)
                val1 = c->user;
            else if (e->attr & CEXPR_ROLE)
                val1 = c->role;
            else if (e->attr & CEXPR_TYPE)
                val1 = c->type;
            else {
                BUG();
                return 0;
            }

            switch (e->op) {
            case CEXPR_EQ:
                s[++sp] = ebitmap_get_bit(&e->names, val1 - 1);
                break;
            case CEXPR_NEQ:
                s[++sp] = !ebitmap_get_bit(&e->names, val1 - 1);
                break;
            default:
                BUG();
                return 0;
            }
            break;
        default:
            BUG();
            return 0;
        }
    }

    BUG_ON(sp != 0);
    return s[0];
}

static void type_attribute_bounds_av(struct context *scontext, struct context *tcontext, u16 tclass,
                                     struct av_decision *avd)
{
    struct context lo_scontext;
    struct context lo_tcontext, *tcontextp = tcontext;
    struct av_decision lo_avd;
    struct type_datum *source;
    struct type_datum *target;
    u32 masked = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0) || defined(KSU_COMPAT_HAS_MODERN_POLICYDB)
    // mostly never happen, except Huawei
    source = backup_policydb->type_val_to_struct[scontext->type - 1];
    BUG_ON(!source);

    if (!source->bounds)
        return;

    target = backup_policydb->type_val_to_struct[tcontext->type - 1];
    BUG_ON(!target);
#else
    source = flex_array_get_ptr(backup_policydb->type_val_to_struct_array, scontext->type - 1);
    BUG_ON(!source);

    if (!source->bounds)
        return;

    target = flex_array_get_ptr(backup_policydb->type_val_to_struct_array, tcontext->type - 1);
    BUG_ON(!target);

#endif

    memset(&lo_avd, 0, sizeof(lo_avd));

    memcpy(&lo_scontext, scontext, sizeof(lo_scontext));
    lo_scontext.type = source->bounds;

    if (target->bounds) {
        memcpy(&lo_tcontext, tcontext, sizeof(lo_tcontext));
        lo_tcontext.type = target->bounds;
        tcontextp = &lo_tcontext;
    }

    context_struct_compute_av(&lo_scontext, tcontextp, tclass, &lo_avd, NULL);

    masked = ~lo_avd.allowed & avd->allowed;

    if (likely(!masked))
        return; /* no masked permission */

    /* mask violated permissions */
    avd->allowed &= ~masked;

    /* audit masked permissions */
    security_dump_masked_av(scontext, tcontext, tclass, masked, "bounds");
}

static void avd_init(struct av_decision *avd)
{
    avd->allowed = 0;
    avd->auditallow = 0;
    avd->auditdeny = 0xffffffff;

    // hardcode 1 to avoid detect for "avdSeqNo"
    // Normal android only set selinux policy once,
    // So there can be simple hardcode to 1
    // For other kernel version
    // kernel with selinux_policy backup real seqno before KernelSU apply rules
    // kernel with selinux_state hardcode to 1 when userspace call selinux hide enable
    avd->seqno = 1;
    avd->flags = 0;
}

#ifndef KSU_COMPAT_HAS_CURRENT_SID
/*
 * get the subjective security ID of the current task
 */
static inline u32 current_sid(void)
{
    const struct task_security_struct *tsec = current_security();

    return tsec->sid;
}
#endif

/*
 * Compute access vectors and extended permissions based on a context
 * structure pair for the permissions in a particular class.
 */
static void context_struct_compute_av(struct context *scontext, struct context *tcontext, u16 tclass,
                                      struct av_decision *avd, struct extended_perms *xperms)
{
    struct constraint_node *constraint;
    struct role_allow *ra;
    struct avtab_key avkey;
    struct avtab_node *node;
    struct class_datum *tclass_datum;
    struct ebitmap *sattr, *tattr;
    struct ebitmap_node *snode, *tnode;
    unsigned int i, j;

    avd->allowed = 0;
    avd->auditallow = 0;
    avd->auditdeny = 0xffffffff;
    if (xperms) {
        memset(&xperms->drivers, 0, sizeof(xperms->drivers));
        xperms->len = 0;
    }

    if (unlikely(!tclass || tclass > backup_policydb->p_classes.nprim)) {
        if (printk_ratelimit())
            printk(KERN_WARNING "SELinux:  Invalid class %hu\n", tclass);
        return;
    }

    tclass_datum = backup_policydb->class_val_to_struct[tclass - 1];

    /*
	 * If a specific type enforcement rule was defined for
	 * this permission check, then use it.
	 */
    avkey.target_class = tclass;
    avkey.specified = AVTAB_AV | AVTAB_XPERMS;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0) ||                                                                   \
    (defined(KSU_COMPAT_HAS_MODERN_POLICYDB) && !defined(KSU_COMPAT_TYPE_ATTR_MAP_ARRAY_NOT_FOUND))
    // mostly never happen
    sattr = &backup_policydb->type_attr_map_array[scontext->type - 1];
    tattr = &backup_policydb->type_attr_map_array[tcontext->type - 1];
#elif defined(KSU_COMPAT_TYPE_ATTR_MAP_ARRAY_NOT_FOUND)
    // huawei! why rename??!
    sattr = &backup_policydb->type_attr_map[scontext->type - 1];
    tattr = &backup_policydb->type_attr_map[tcontext->type - 1];
#else
    sattr = flex_array_get(backup_policydb->type_attr_map_array, scontext->type - 1);
    BUG_ON(!sattr);
    tattr = flex_array_get(backup_policydb->type_attr_map_array, tcontext->type - 1);
    BUG_ON(!tattr);
#endif
    ebitmap_for_each_positive_bit(sattr, snode, i)
    {
        ebitmap_for_each_positive_bit(tattr, tnode, j)
        {
            avkey.source_type = i + 1;
            avkey.target_type = j + 1;
            for (node = avtab_search_node(&backup_policydb->te_avtab, &avkey); node;
                 node = avtab_search_node_next(node, avkey.specified)) {
                if (node->key.specified == AVTAB_ALLOWED)
                    avd->allowed |= node->datum.u.data;
                else if (node->key.specified == AVTAB_AUDITALLOW)
                    avd->auditallow |= node->datum.u.data;
                else if (node->key.specified == AVTAB_AUDITDENY)
                    avd->auditdeny &= node->datum.u.data;
                else if (xperms && (node->key.specified & AVTAB_XPERMS))
                    services_compute_xperms_drivers(xperms, node);
            }

            /* Check conditional av table for additional permissions */
            cond_compute_av(&backup_policydb->te_cond_avtab, &avkey, avd, xperms);
        }
    }

    /*
	 * Remove any permissions prohibited by a constraint (this includes
	 * the MLS policy).
	 */
    constraint = tclass_datum->constraints;
    while (constraint) {
        if ((constraint->permissions & (avd->allowed)) &&
            !constraint_expr_eval(scontext, tcontext, NULL, constraint->expr)) {
            avd->allowed &= ~(constraint->permissions);
        }
        constraint = constraint->next;
    }

    /*
	 * If checking process transition permission and the
	 * role is changing, then check the (current_role, new_role)
	 * pair.
	 */
    if (tclass == backup_policydb->process_class && (avd->allowed & backup_policydb->process_trans_perms) &&
        scontext->role != tcontext->role) {
        for (ra = backup_policydb->role_allow; ra; ra = ra->next) {
            if (scontext->role == ra->role && tcontext->role == ra->new_role)
                break;
        }
        if (!ra)
            avd->allowed &= ~backup_policydb->process_trans_perms;
    }

    /*
	 * If the given source and target types have boundary
	 * constraint, lazy checks have to mask any violated
	 * permission and notice it to userspace via audit.
	 */
    type_attribute_bounds_av(scontext, tcontext, tclass, avd);
}

/*
 * Write the security context string representation of
 * the context structure `context' into a dynamically
 * allocated string of the correct size.  Set `*scontext'
 * to point to this string and set `*scontext_len' to
 * the length of the string.
 */
static int context_struct_to_string(struct context *context, char **scontext, u32 *scontext_len)
{
    char *scontextp;

    if (scontext)
        *scontext = NULL;
    *scontext_len = 0;

    if (context->len) {
        *scontext_len = context->len;
        if (scontext) {
            *scontext = kstrdup(context->str, GFP_ATOMIC);
            if (!(*scontext))
                return -ENOMEM;
        }
        return 0;
    }

    /* Compute the size of the context. */
    *scontext_len += strlen(sym_name(backup_policydb, SYM_USERS, context->user - 1)) + 1;
    *scontext_len += strlen(sym_name(backup_policydb, SYM_ROLES, context->role - 1)) + 1;
    *scontext_len += strlen(sym_name(backup_policydb, SYM_TYPES, context->type - 1)) + 1;
    *scontext_len += mls_compute_context_len(context);

    if (!scontext)
        return 0;

    /* Allocate space for the context; caller must free this space. */
    scontextp = kmalloc(*scontext_len, GFP_ATOMIC);
    if (!scontextp)
        return -ENOMEM;
    *scontext = scontextp;

    /*
	 * Copy the user name, role name and type name into the context.
	 */
    scontextp += sprintf(scontextp, "%s:%s:%s", sym_name(backup_policydb, SYM_USERS, context->user - 1),
                         sym_name(backup_policydb, SYM_ROLES, context->role - 1),
                         sym_name(backup_policydb, SYM_TYPES, context->type - 1));

    mls_sid_to_context(context, &scontextp);

    *scontextp = 0;

    return 0;
}

/*
 * Caveat:  Mutates scontext.
 */
static int string_to_context_struct(struct policydb *pol, struct sidtab *sidtabp, char *scontext, u32 scontext_len,
                                    struct context *ctx, u32 def_sid)
{
    struct role_datum *role;
    struct type_datum *typdatum;
    struct user_datum *usrdatum;
    char *scontextp, *p, oldc;
    int rc = 0;

    context_init(ctx);

    /* Parse the security context. */

    rc = -EINVAL;
    scontextp = (char *)scontext;

    /* Extract the user. */
    p = scontextp;
    while (*p && *p != ':')
        p++;

    if (*p == 0)
        goto out;

    *p++ = 0;

    usrdatum = hashtab_search(pol->p_users.table, scontextp);
    if (!usrdatum)
        goto out;

    ctx->user = usrdatum->value;

    /* Extract role. */
    scontextp = p;
    while (*p && *p != ':')
        p++;

    if (*p == 0)
        goto out;

    *p++ = 0;

    role = hashtab_search(pol->p_roles.table, scontextp);
    if (!role)
        goto out;
    ctx->role = role->value;

    /* Extract type. */
    scontextp = p;
    while (*p && *p != ':')
        p++;
    oldc = *p;
    *p++ = 0;

    typdatum = hashtab_search(pol->p_types.table, scontextp);
    if (!typdatum || typdatum->attribute)
        goto out;

    ctx->type = typdatum->value;

    rc = mls_context_to_sid(pol, oldc, &p, ctx, sidtabp, def_sid);
    if (rc)
        goto out;

    rc = -EINVAL;
    if ((p - scontext) < scontext_len)
        goto out;

    /* Check the validity of the new context. */
    if (!policydb_context_isvalid(pol, ctx))
        goto out;
    rc = 0;
out:
    if (rc)
        context_destroy(ctx);
    return rc;
}

static int ksu_security_context_to_sid(const char *scontext, u32 scontext_len, u32 *sid, gfp_t gfp_flags)
{
    char *scontext2, *str = NULL;
    struct context context;
    int rc = 0;

    /* An empty security context is never valid. */
    if (!scontext_len)
        return -EINVAL;

    *sid = SECSID_NULL;

    /* Copy the string so that we can modify the copy as we parse it. */
    scontext2 = kmalloc(scontext_len + 1, gfp_flags);
    if (!scontext2)
        return -ENOMEM;
    memcpy(scontext2, scontext, scontext_len);
    scontext2[scontext_len] = 0;

    rc = string_to_context_struct(backup_policydb, backup_sidtab, scontext2, scontext_len, &context, SECSID_NULL);
    if (rc)
        goto out;
    rc = sidtab_context_to_sid(backup_sidtab, &context, sid);
    context_destroy(&context);
out:
    kfree(scontext2);
    kfree(str);
    return rc;
}

static int ksu_security_context_str_to_sid(const char *scontext, u32 *sid, gfp_t gfp)
{
    return ksu_security_context_to_sid(scontext, strlen(scontext), sid, gfp);
}

static int ksu_security_sid_to_context(u32 sid, char **scontext, u32 *scontext_len)
{
    struct context *context;
    int rc = 0;

    if (scontext)
        *scontext = NULL;
    *scontext_len = 0;

    context = sidtab_search(backup_sidtab, sid);
    if (!context) {
        printk(KERN_ERR "SELinux: %s:  unrecognized SID %d\n", __func__, sid);
        rc = -EINVAL;
        goto out;
    }
    rc = context_struct_to_string(context, scontext, scontext_len);
out:
    return rc;
}

static void ksu_security_compute_av_user(u32 ssid, u32 tsid, u16 tclass, struct av_decision *avd)
{
    struct context *scontext = NULL, *tcontext = NULL;

    avd_init(avd);

    scontext = sidtab_search(backup_sidtab, ssid);
    if (!scontext) {
        printk(KERN_ERR "SELinux: %s:  unrecognized SID %d\n", __func__, ssid);
        goto out;
    }

    /* permissive domain? */
    if (ebitmap_get_bit(&backup_policydb->permissive_map, scontext->type))
        avd->flags |= AVD_FLAGS_PERMISSIVE;

    tcontext = sidtab_search(backup_sidtab, tsid);
    if (!tcontext) {
        printk(KERN_ERR "SELinux: %s:  unrecognized SID %d\n", __func__, tsid);
        goto out;
    }

    if (unlikely(!tclass)) {
        if (backup_policydb->allow_unknown)
            goto allow;
        goto out;
    }

    context_struct_compute_av(scontext, tcontext, tclass, avd, NULL);
out:
    return;
allow:
    avd->allowed = 0xffffffff;
    goto out;
}
#endif
KCEOF
# seccomp_cache.c stub（4.14 struct seccomp_filter 无 cache 字段，4.18+ 才有）
cat > infra/seccomp_cache.c <<'EOF'
/* 4.14 compat stub: struct seccomp_filter no cache field (4.18+) */
#include "infra/seccomp_cache.h"
#include <linux/version.h>

void ksu_seccomp_clear_cache(struct seccomp_filter *filter, int nr)
{
}

void ksu_seccomp_allow_cache(struct seccomp_filter *filter, int nr)
{
}
EOF

# selinux/selinux.h：补 BakaSU 的 KSU_COMPAT_USE_SELINUX_STATE 定义
# （kernel_compat.mk 检测到 selinux_state 即启用 ss->* 路径）
python3 - <<'PYSEL'
import sys
path = 'selinux/selinux.h'
try:
    with open(path, encoding='utf-8') as f:
        s = f.read()
except FileNotFoundError:
    print("[414compat] ERROR: selinux/selinux.h not found")
    sys.exit(1)

if '#define KSU_COMPAT_USE_SELINUX_STATE' in s:
    print("[414compat] selinux/selinux.h: KSU_COMPAT_USE_SELINUX_STATE already present")
    sys.exit(0)

anchor = '#define KSU_FILE_CONTEXT "u:object_r:" KERNEL_SU_FILE ":s0"'
add_lines = [
    anchor,
    '',
    '// BakaSU compat: use selinux_state.ss->* path when selinux_state exists',
    '// (including MTK 4.14 backport)',
    '#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)) || defined(KSU_COMPAT_HAS_SELINUX_STATE)',
    '#define KSU_COMPAT_USE_SELINUX_STATE',
    '#endif',
]
add = '\n'.join(add_lines)
if s.count(anchor) != 1:
    print("[414compat] ERROR: selinux/selinux.h anchor count=%d" % s.count(anchor))
    sys.exit(1)
s = s.replace(anchor, add)
with open(path, 'w', encoding='utf-8') as f:
    f.write(s)
print("[414compat] selinux/selinux.h: KSU_COMPAT_USE_SELINUX_STATE added")
PYSEL

# include/ksu.h：把旧 stub 流程遗留的无条件
#   extern struct selinux_policy *backup_sepolicy;
# 换成 BakaSU 的条件声明——<5.10 且无 selinux_policy 结构时，
# backup 是 rules.c 定义的 struct policydb *backup_policydb /
# struct sidtab *backup_sidtab（selinux_hide.c 经 ksu.h 引用它们）
python3 - <<'PYKSU'
import sys
path = 'include/ksu.h'
try:
    with open(path, encoding='utf-8') as f:
        s = f.read()
except FileNotFoundError:
    print("[414compat] ERROR: include/ksu.h not found")
    sys.exit(1)

old = 'extern struct selinux_policy *backup_sepolicy;'
if old not in s:
    print("[414compat] ksu.h: backup_sepolicy extern not found (already patched?)")
    sys.exit(0)

new_lines = [
    '#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) || defined(KSU_COMPAT_HAS_SELINUX_POLICY_STRUCT)',
    'extern struct selinux_policy *backup_sepolicy;',
    '#else',
    'extern struct policydb *backup_policydb;',
    'extern struct sidtab *backup_sidtab;',
    '#endif',
]
new = '\n'.join(new_lines)
if s.count(old) != 1:
    print("[414compat] ERROR: ksu.h anchor count=%d" % s.count(old))
    sys.exit(1)
s = s.replace(old, new)

# LINUX_VERSION_CODE 需要 linux/version.h（pristine ksu.h 未包含）
if '#include <linux/version.h>' not in s:
    vh_anchor = '#include <linux/types.h>\n'
    if s.count(vh_anchor) != 1:
        print("[414compat] ERROR: ksu.h version.h anchor count=%d" % s.count(vh_anchor))
        sys.exit(1)
    s = s.replace(vh_anchor, vh_anchor + '#include <linux/version.h>\n')

with open(path, 'w', encoding='utf-8') as f:
    f.write(s)
print("[414compat] include/ksu.h: backup extern declarations -> version-conditional")
PYKSU
# Kbuild: restore sepolicy.o, add compat/kernel_compat.o, include compat mk
python3 - <<'PYKB'
import sys
path = 'Kbuild'
try:
    with open(path, encoding='utf-8') as f:
        s = f.read()
except FileNotFoundError:
    print("[414compat] ERROR: Kbuild not found")
    sys.exit(1)

old = 'kernelsu-objs := core/init.o'
# 注意：pristine Kbuild 本来就带 selinux/sepolicy.o（旧 stub 流程是运行时
# sed 删除它，现已不再删），这里只负责补 compat/kernel_compat.o。
if 'compat/kernel_compat.o' not in s:
    if s.count(old) != 1:
        print("[414compat] ERROR: Kbuild anchor count=%d" % s.count(old))
        sys.exit(1)
    s = s.replace(old, old + '\nkernelsu-objs += compat/kernel_compat.o')

# sepolicy.o 兜底：万一下游 Kbuild 没有这行（如被其他流程删过），补上
if 'selinux/sepolicy.o' not in s:
    if s.count(old) != 1:
        print("[414compat] ERROR: Kbuild anchor count=%d for sepolicy.o" % s.count(old))
        sys.exit(1)
    s = s.replace(old, old + '\nkernelsu-objs += selinux/sepolicy.o')

if 'tools/kernel_compat.mk' not in s:
    s = s.rstrip('\n') + "\n\n# BakaSU compat: scan kernel tree to generate KSU_COMPAT_* ccflags\ninclude $(src)/tools/kernel_compat.mk\n"
with open(path, 'w', encoding='utf-8') as f:
    f.write(s)
print("[414compat] Kbuild: sepolicy.o + compat/kernel_compat.o + kernel_compat.mk")
PYKB

echo "[414compat] SELinux rules/hide (BakaSU 4.14 port) written"
echo "[414compat] stubs written, all done"

# =============================================================================
# 31) SUSFS 集成层（仅当第二个参数为 "susfs" 时执行）
#
# susfs_patch_to_4.14.patch 只提供 VFS 层（fs/susfs.c），其功能全部包在
# #ifdef CONFIG_KSU_SUSFS_* 内，且 extern 以下 KernelSU 侧符号：
#     susfs_is_current_ksu_domain / setup_selinux / ksu_cred
#     susfs_ksu_sid / susfs_priv_app_sid（avc.c log spoofing 用）
# 后两组中 setup_selinux / ksu_cred 7kimisu 已有，这里补齐其余：
#   a. susfs_ksu.c：定义 susfs_is_current_ksu_domain、两个 SID
#      （second_stage 时 policy 已加载，用 security_secctx_to_secid
#       初始化，与 selinux.c cache_sid() 同阶段同 API）
#      + 默认隐藏路径
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
 * 它 extern 以下 KernelSU 侧符号：
 *     susfs_is_current_ksu_domain / setup_selinux / ksu_cred
 *     susfs_ksu_sid / susfs_priv_app_sid（avc.c log spoofing 用）
 * 后两组中 setup_selinux / ksu_cred 7kimisu 已有，本文件补上其余，并提供：
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
#include <linux/security.h>
#include <linux/string.h>

/* fs/susfs.c 中 DEFINE_STATIC_KEY_FALSE 定义的开关（susfs 补丁提供） */
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
extern struct static_key_false susfs_is_hide_sus_mnts_for_non_su_procs_enabled;
#endif

#ifdef CONFIG_KSU_SUSFS
/* --------------------------------------------------------------------------
 * avc.c log spoofing 引用的两个 SID（官方 KernelSU 同样在 KSU 侧定义）
 *
 * susfs_patch_to_4.14.patch 的 avc.c hunk 只放 extern 声明：
 *     extern u32 susfs_ksu_sid;
 *     extern u32 susfs_priv_app_sid;
 * 定义责任在 KernelSU 侧。语义见 avc_dump_query()：audit 日志里
 * tsid == susfs_ksu_sid（KSU 自身域）时，把 tcontext 伪造成
 * "u:r:priv_app:s0:c512,c768"、tsid 伪造成 susfs_priv_app_sid，
 * 使 avc log 看上去来自 priv_app 而非 ksu。
 *
 * 在 ksu_susfs_handle_second_stage() 初始化：该点 SELinux policy 已加载
 * （与 selinux.c cache_sid() 同阶段、同 API security_secctx_to_secid）。
 * -------------------------------------------------------------------------- */
u32 susfs_ksu_sid = 0;
u32 susfs_priv_app_sid = 0;
EXPORT_SYMBOL(susfs_ksu_sid);
EXPORT_SYMBOL(susfs_priv_app_sid);
#endif /* CONFIG_KSU_SUSFS */

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
    int err;

    /* 初始化 avc log spoofing 用的两个 SID。
     * 时机：/system/bin/init second_stage，policy 已加载（selinux.c
     * 的 cache_sid() 在同一处用同一 API，可证此时可查）。
     * KSU 域用 KERNEL_SU_CONTEXT（u:r:ksu:s0），priv_app 用 AOSP 标准域
     * "u:r:priv_app:s0"（avc.c 伪造的 tcontext 文本同属该域）。
     * 查找失败保持 0：tsid 永不为 0（SECINITSID_NUM 以下保留），
     * spoofing 不会误触发。 */
    err = security_secctx_to_secid(KERNEL_SU_CONTEXT,
                                   strlen(KERNEL_SU_CONTEXT),
                                   &susfs_ksu_sid);
    if (err) {
        susfs_ksu_sid = 0;
        pr_warn("susfs: failed to lookup ksu domain sid: %d\n", err);
    } else {
        pr_info("susfs: ksu sid=%u\n", susfs_ksu_sid);
    }

    err = security_secctx_to_secid("u:r:priv_app:s0",
                                   strlen("u:r:priv_app:s0"),
                                   &susfs_priv_app_sid);
    if (err) {
        susfs_priv_app_sid = 0;
        pr_warn("susfs: failed to lookup priv_app sid: %d\n", err);
    } else {
        pr_info("susfs: priv_app sid=%u\n", susfs_priv_app_sid);
    }

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

