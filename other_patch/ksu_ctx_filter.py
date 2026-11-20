#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KSU_CTX_FILTER
在 security/selinux 的三个入口上过滤敏感 type 名（lsposed_file / ksu_file），
只对 uid >= 10000 的非特权进程生效：
  1. sel_write_context()   /sys/fs/selinux/context 写入 -> -EINVAL（当作 type 不存在）
  2. sel_write_access()    /sys/fs/selinux/access 查询 -> 返回全 0（denied）
  3. selinux_setprocattr() /proc/self/attr/current 写入 -> -EINVAL
幂等：已插入则跳过；锚点缺失则直接失败退出。
"""

import os
import sys

MARK = "KSU_CTX_FILTER"

HELPER = (
    "\n/* %s: 隐藏敏感 SELinux type 名，仅对非特权进程生效 */\n"
    "static inline bool ksu_ctx_blocked(const char *s, size_t n)\n"
    "{\n"
    "\tif (!s || !n)\n"
    "\t\treturn false;\n"
    "\tif (strnstr(s, \"lsposed_file\", n))\n"
    "\t\treturn true;\n"
    "\tif (strnstr(s, \"ksu_file\", n))\n"
    "\t\treturn true;\n"
    "\treturn false;\n"
    "}\n\n"
) % MARK

CTX_GUARD = (
    "\tif (current_uid().val >= 10000 && ksu_ctx_blocked(buf, size)) { /* %s */\n"
    "\t\tlength = -EINVAL;\n"
    "\t\tgoto out;\n"
    "\t}\n\n"
) % MARK

ACCESS_GUARD = (
    "\tif (current_uid().val >= 10000 && ksu_ctx_blocked(buf, size)) { /* %s */\n"
    "\t\t/* 返回全拒决策，让探测看到 denied，而不是 type 不存在 */\n"
    "\t\tlength = scnprintf(buf, SIMPLE_TRANSACTION_LIMIT, \"0 0 0 0 0 0\");\n"
    "\t\tgoto out;\n"
    "\t}\n\n"
) % MARK

PROC_GUARD = (
    "\tif (current_uid().val >= 10000 && size > 0 &&\n"
    "\t    ksu_ctx_blocked((const char *)value, size)) { /* %s */\n"
    "\t\treturn -EINVAL;\n"
    "\t}\n\n"
) % MARK


def read(p):
    with open(p, "r", encoding="utf-8", errors="surrogateescape") as f:
        return f.read()


def write(p, s):
    with open(p, "w", encoding="utf-8", errors="surrogateescape") as f:
        f.write(s)


def fail(msg):
    print("FATAL: " + msg)
    sys.exit(1)


def insert_before(s, anchor, text, path, what):
    if text.strip() and text in s:
        print("[skip] %s 已存在: %s" % (path, what))
        return s
    pos = s.find(anchor)
    if pos < 0:
        fail("%s 中找不到锚点: %s" % (path, what))
    return s[:pos] + text + s[pos:]


def insert_after(s, anchor, text, path, what):
    if text.strip() and text in s:
        print("[skip] %s 已存在: %s" % (path, what))
        return s
    pos = s.find(anchor)
    if pos < 0:
        fail("%s 中找不到锚点: %s" % (path, what))
    pos += len(anchor)
    return s[:pos] + text + s[pos:]


def main():
    base = os.path.join("common", "security", "selinux")
    fsf = os.path.join(base, "selinuxfs.c")
    hk = os.path.join(base, "hooks.c")
    for p in (fsf, hk):
        if not os.path.isfile(p):
            fail("找不到源码: " + p)

    # ---------- selinuxfs.c ----------
    s = read(fsf)
    if "#include <linux/cred.h>" not in s:
        s = insert_before(s, "#include <linux/string.h>\n",
                          "#include <linux/cred.h>\n", fsf, "cred.h include")
    s = insert_before(
        s,
        "static ssize_t sel_write_context(struct file *file, char *buf, size_t size)\n{",
        HELPER, fsf, "helper")
    s = insert_before(
        s,
        "\tlength = avc_has_perm(&selinux_state,\n\t\t\t      current_sid(), SECINITSID_SECURITY,\n\t\t\t      SECCLASS_SECURITY, SECURITY__CHECK_CONTEXT, NULL);",
        CTX_GUARD, fsf, "context guard")
    s = insert_before(
        s,
        "\tlength = avc_has_perm(&selinux_state,\n\t\t\t      current_sid(), SECINITSID_SECURITY,\n\t\t\t      SECCLASS_SECURITY, SECURITY__COMPUTE_AV, NULL);",
        ACCESS_GUARD, fsf, "access guard")
    write(fsf, s)

    # ---------- hooks.c ----------
    s = read(hk)
    s = insert_before(
        s,
        "static int selinux_setprocattr(const char *name, void *value, size_t size)\n{",
        HELPER, hk, "helper")
    s = insert_after(s, "\tchar *str = value;\n", PROC_GUARD, hk, "procattr guard")
    write(hk, s)

    # ---------- 校验 ----------
    for p in (fsf, hk):
        txt = read(p)
        if txt.count(MARK) < 2:
            fail("%s 中标记数量不足，注入不完整" % p)
    print("OK: KSU_CTX_FILTER 已注入 selinuxfs.c / hooks.c")


if __name__ == "__main__":
    main()
