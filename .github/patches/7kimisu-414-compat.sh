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
# 本脚本做两类处理：
#   1. 精确替换：给新版 API 调用加版本守卫或改写成 4.14 等价写法
#   2. 整体 stub：将深度依赖 5.x+ 内部结构（selinux_state.policy RCU 机制、
#      struct seccomp_filter cache 字段、selinux_hide 的 status page 机制）
#      的特性在 4.14 上置空，保证内核可编译、su 基本功能可用
#
# 已知 4.14 限制（相对新版内核）：
#   - apply_kernelsu_rules / handle_sepolicy 不可用（sepolicy 规则注入需要
#     5.x+ 的 selinux_state.policy 机制，该 4.14.186 内核未 backport），
#     su 的 SELinux 域切换本身可用
#   - SELinux 隐身（selinux_hide）不可用
#   - seccomp filter cache 不可用
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

print("[414compat] source patches done")
PYEOF

# -----------------------------------------------------------------------------
# 7) 整体 stub：以下特性深度依赖 5.x+ 内核内部结构，4.14 无可移植实现。
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
# 8) SUSFS 集成层（仅当第二个参数为 "susfs" 时执行）
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
